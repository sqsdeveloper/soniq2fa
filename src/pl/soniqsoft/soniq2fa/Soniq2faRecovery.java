// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.auth.AuthMechanism;
import com.zimbra.cs.account.ldap.LdapLockoutPolicy;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.util.JMSession;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.mail.Message;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Self-service password recovery for accounts with 2FA, at /service/extension/soniq2fa-recover (no session).
 * Carbonio's own recovery signs in with a mailed code alone, outside the domain mechanism, so it is turned off when
 * 2FA is turned on; this one asks for a code mailed to the verified recovery address (zimbraPrefPasswordRecoveryAddress,
 * the same attribute Carbonio uses) and, in addition, the code from the authenticator app or a backup code.
 *
 * POST op=start   account - mails a code when the account has 2FA and a verified recovery address. The answer is the
 *                 same whatever the account, and the mail goes out in the background, so the page reveals nothing.
 * POST op=finish  account, mailCode, code, password - checks the mailed code (5 attempts, 15 minutes), then the second
 *                 factor (rate-limited as at sign-in, a backup code is used up), then sets the password under the
 *                 Carbonio password policy, lifts a lockout and mails a notice to the recovery address.
 * POST op=enroll-start, op=enroll-confirm  account, password (and code) - setting up 2FA without a session, for an
 *                 account that must use it after its grace period (Enforcement); GET ?op=enroll serves the page
 * POST op=send    account, password, channel (sms|email) - from the code dialog of the login page: after the mailbox
 *                 password, sends a 6-digit login code (5 minutes, single use) by SMS to the confirmed number or to the
 *                 recovery address, when the account turned that channel on (Channels). The password check follows the
 *                 Carbonio lockout policy and has its own limit (5 per 10 minutes, account and client); login codes have
 *                 their own sending limit. The answer is the same in every case, so the endpoint tells nobody whether
 *                 the password is right. A new code replaces a pending one. The code is then typed after the
 *                 password like a code from the app.
 *
 * Codes live in memory (RecoveryCodes): a mailbox restart voids them.
 */
public final class Soniq2faRecovery extends ExtensionHttpHandler {
    static final String A_ADDRESS = "zimbraPrefPasswordRecoveryAddress";
    static final String A_ADDRESS_STATUS = "zimbraPrefPasswordRecoveryAddressStatus";
    private static final long CODE_MS = 15 * 60_000, ADDRESS_MS = 30 * 60_000, LOGIN_MS = 5 * 60_000, PHONE_MS = 10 * 60_000;
    private static final ExecutorService MAILER = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "soniq2fa-mail");
        t.setDaemon(true);
        return t;
    });

    @Override
    public String getPath() {
        return "/soniq2fa-recover";
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Soniq2faPage.noCache(resp);
        String op = req.getParameter("op");
        if ("recover.js".equals(op) || "enroll.js".equals(op) || "qrcode.js".equals(op)) {
            Soniq2faPage.resource(resp, op, "text/javascript; charset=utf-8");
            return;
        }
        if ("i18n".equals(op)) {
            String lang = Soniq2faPage.language(null, req);
            Soniq2faPage.json(resp, 200, "{\"lang\":" + Soniq2faPage.q(lang) + ",\"messages\":" + Soniq2faPage.bundle(lang)
                    + ",\"fallback\":" + Soniq2faPage.bundle("en") + "}");
            return;
        }
        resp.setHeader("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
        Soniq2faPage.resource(resp, "enroll".equals(op) ? "enroll.html" : "recover.html", "text/html; charset=utf-8");
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Soniq2faPage.noCache(resp);
        // parameters only from the body: a query string would take precedence in getParameter and let a crafted link
        // swap the action our own page sends (e.g. ?op=disable), whatever the user clicked
        if (req.getQueryString() != null && !req.getQueryString().isEmpty()) {
            Soniq2faPage.json(resp, 400, "{\"error\":\"rejected\"}");
            return;
        }
        if (req.getHeader("X-Soniq2fa") == null || !Soniq2faPage.sameHost(req.getHeader("Origin"), req.getHeader("Host"))) {
            Soniq2faPage.json(resp, 403, "{\"error\":\"rejected\"}");
            return;
        }
        String op = req.getParameter("op");
        try {
            if ("start".equals(op)) {
                start(req.getParameter("account"), client(req));
                Soniq2faPage.json(resp, 200, "{\"ok\":true}");
            } else if ("send".equals(op)) {
                sendLoginCode(req.getParameter("account"), req.getParameter("password"), req.getParameter("channel"), req);
                Soniq2faPage.json(resp, 200, "{\"ok\":true}");
            } else if ("enroll-start".equals(op)) {
                Account a = enrolment(req.getParameter("account"), req.getParameter("password"), req);
                Soniq2faPage.json(resp, 200, Soniq2faPage.startEnrolment(a));
            } else if ("enroll-confirm".equals(op)) {
                Account a = enrolment(req.getParameter("account"), req.getParameter("password"), req);
                String[] codes = Soniq2faPage.finishEnrolment(Provisioning.getInstance(), a, req.getParameter("code"), client(req));
                StringBuilder b = new StringBuilder();
                for (String c : codes) b.append(b.length() == 0 ? "" : ",").append(Soniq2faPage.q(c));
                Soniq2faPage.json(resp, 200, "{\"codes\":[" + b + "]}");
            } else if ("finish".equals(op)) {
                String error = finish(req.getParameter("account"), req.getParameter("mailCode"), req.getParameter("code"),
                        req.getParameter("password"), req);
                if (error == null) Soniq2faPage.json(resp, 200, "{\"ok\":true}");
                else Soniq2faPage.json(resp, 400, "{\"error\":" + Soniq2faPage.q(error) + "}");
            } else {
                Soniq2faPage.json(resp, 400, "{\"error\":\"rejected\"}");
            }
        } catch (Soniq2faPage.UserError e) {
            Soniq2faPage.json(resp, 400, "{\"error\":" + Soniq2faPage.q(e.getMessage()) + "}");
        } catch (PolicyError e) {
            Soniq2faPage.json(resp, 400, "{\"error\":\"password_policy\",\"detail\":" + Soniq2faPage.q(e.getMessage()) + "}");
        } catch (Exception e) {
            ZimbraLog.account.warn("soniq2fa: recovery error", e);
            Soniq2faPage.json(resp, 500, "{\"error\":\"server\"}");
        }
    }

    private static final class PolicyError extends Exception {
        private static final long serialVersionUID = 1L;

        PolicyError(String m) {
            super(m);
        }
    }

    /** The client address: behind the Carbonio proxy the first X-Forwarded-For entry, else the connection's. For logs and the notice. */
    static String client(HttpServletRequest req) {
        // the entry the proxy appends; earlier ones come from the client and could put any text into notices and logs
        return safe(proxyPeer(req));
    }

    /** The account when recovery applies to it: its domain uses soniq2fa, 2FA is on and the address is verified. */
    private static Account eligible(String name) {
        try {
            if (name == null || name.isBlank()) return null;
            Account a = Provisioning.getInstance().getAccountByName(name.trim());
            if (a == null || Soniq2faPage.unavailable(a) != null) return null;
            String secret = a.getAttr(Soniq2faAuth.A_SECRET);
            if (secret == null || secret.isEmpty()) return null;
            if (!confirmedAddress(a)) return null;
            return a;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * The recovery address counts only when it was confirmed with a mailed code on our page: zimbraPrefPasswordRecovery*
     * are preferences the user's own session can set through ModifyPrefs (address and "verified" at once), so a stolen
     * session could point recovery at the attacker. The page records the confirmed address in the immutable channel
     * attribute ("recovery:<address>"), which SOAP cannot write.
     */
    static boolean confirmedAddress(Account a) {
        String addr = a.getAttr(A_ADDRESS, "");
        return !addr.isEmpty() && "verified".equals(a.getAttr(A_ADDRESS_STATUS))
                && java.util.Arrays.asList(a.getMultiAttr(Channels.A_CHANNELS)).contains(Channels.RECOVERY_PREFIX + addr.toLowerCase(java.util.Locale.ROOT));
    }

    private static void start(String name, String ip) {
        Account a = eligible(name);
        if (a == null) {
            ZimbraLog.account.info("soniq2fa: recovery code not sent for '%s' (no such account, no 2FA or no confirmed address; ip=%s)", safe(name), ip);
            return;
        }
        // a pending code stays valid: a stranger asking again must not void the code the owner already has
        if (RecoveryCodes.pending("reset:" + a.getId())) {
            ZimbraLog.account.info("soniq2fa: recovery code for %s not sent, one is still valid (ip=%s)", a.getName(), ip);
            return;
        }
        if (!RecoveryCodes.mayMail("reset:" + a.getId())) {
            ZimbraLog.account.info("soniq2fa: recovery code for %s not sent, mail limit reached (ip=%s)", a.getName(), ip);
            return;
        }
        String code = RecoveryCodes.issue("reset:" + a.getId(), CODE_MS, null);
        String to = a.getAttr(A_ADDRESS);
        mailLater(a, to, "mail.code.subject", "mail.code.body", Map.of("code", code, "account", a.getName(), "minutes", "15"));
        ZimbraLog.account.info("soniq2fa: recovery code for %s sent to the recovery address (ip=%s)", a.getName(), ip);
    }

    /**
     * Enrolment without a session, for an account that must use 2FA and can no longer sign in with the password alone
     * (Enforcement): the mailbox password under the Carbonio lockout policy and a limit per account and client, then
     * the same steps as on the self-service page. "not_required" is said only to whoever knows the password.
     */
    private static Account enrolment(String name, String password, HttpServletRequest req) throws Exception {
        Provisioning prov = Provisioning.getInstance();
        Account a = name == null || name.isBlank() ? null : prov.getAccountByName(name.trim());
        if (a == null) throw new Soniq2faPage.UserError("invalid_login");
        LdapLockoutPolicy lockout = new LdapLockoutPolicy(prov, a);
        if (lockout.isLockedOut() || !TwoFa.SEND_THROTTLE.tryAcquire("enrol|" + a.getId() + "|" + proxyPeer(req), System.currentTimeMillis()))
            throw new Soniq2faPage.UserError("too_many_attempts");
        try {
            AuthMechanism.doZimbraAuth((LdapProv) prov, prov.getDomain(a), a, password == null ? "" : password, new HashMap<>());
        } catch (ServiceException wrongPassword) {
            lockout.failedLogin();
            ZimbraLog.account.info("soniq2fa: enrolment for %s refused, wrong password (ip=%s)", a.getName(), client(req));
            throw new Soniq2faPage.UserError("invalid_login");
        }
        String secret = a.getAttr(Soniq2faAuth.A_SECRET);
        if ((secret != null && !secret.isEmpty()) || Soniq2faPage.unavailable(a) != null || !Soniq2faPage.required(a)
                || !"active".equals(a.getAttr("zimbraAccountStatus", "active")))
            throw new Soniq2faPage.UserError("not_required");
        return a;
    }

    static String loginKey(Account a) {
        return "login:" + a.getId();
    }

    /**
     * Login code by SMS or mail, only after the mailbox password (Soniq2faAuth accepts the code once, within 5 minutes).
     * The password check follows the Carbonio lockout policy (a locked account gets nothing, a wrong password counts as
     * a failed login) and has its own limit per account and client, so strangers cannot block the owner's sends.
     */
    private static void sendLoginCode(String name, String password, String channel, HttpServletRequest req) throws Exception {
        String ip = client(req);
        Provisioning prov = Provisioning.getInstance();
        Account a = name == null || name.isBlank() ? null : prov.getAccountByName(name.trim());
        String secret = a == null ? null : a.getAttr(Soniq2faAuth.A_SECRET);
        if (secret == null || secret.isEmpty() || Soniq2faPage.unavailable(a) != null || !"active".equals(a.getAttr("zimbraAccountStatus", "active"))) {
            ZimbraLog.account.info("soniq2fa: login code not sent for '%s' (no such active account with 2FA; ip=%s)", safe(name), ip);
            return;
        }
        LdapLockoutPolicy lockout = new LdapLockoutPolicy(prov, a);
        if (lockout.isLockedOut()) {
            ZimbraLog.account.info("soniq2fa: login code for %s not sent, account locked out (ip=%s)", a.getName(), ip);
            return;
        }
        if (!TwoFa.SEND_THROTTLE.tryAcquire(a.getId() + "|" + proxyPeer(req), System.currentTimeMillis())) {
            ZimbraLog.account.info("soniq2fa: login code for %s not sent, too many password attempts (ip=%s)", a.getName(), ip);
            return;
        }
        try {
            AuthMechanism.doZimbraAuth((LdapProv) prov, prov.getDomain(a), a, password == null ? "" : password, new HashMap<>());
        } catch (ServiceException wrongPassword) {
            lockout.failedLogin();
            ZimbraLog.account.info("soniq2fa: login code for %s not sent, wrong password (ip=%s)", a.getName(), ip);
            return;
        }
        String[] channels = a.getMultiAttr(Channels.A_CHANNELS);
        String phone = Channels.phone(channels);
        boolean sms = "sms".equals(channel) && phone != null && Soniq2faPage.smsEnabled(a);
        boolean mail = "email".equals(channel) && Channels.email(channels) && eligible(a.getName()) != null
                && !onThisServer(a.getAttr(A_ADDRESS));
        if (!sms && !mail) {
            ZimbraLog.account.info("soniq2fa: login code for %s not sent, channel '%s' not set up (ip=%s)", a.getName(), safe(channel), ip);
            return;
        }
        if (!RecoveryCodes.mayMail(loginKey(a))) {
            ZimbraLog.account.info("soniq2fa: login code for %s not sent, sending limit reached (ip=%s)", a.getName(), ip);
            return;
        }
        String code = RecoveryCodes.issue(loginKey(a), LOGIN_MS, null, 6);
        Map<String, String> vars = Map.of("code", code, "account", a.getName(), "minutes", "5");
        if (sms) textLater(a, phone, "sms.login", vars);
        else mailLater(a, a.getAttr(A_ADDRESS), "mail.login.subject", "mail.login.body", vars);
        ZimbraLog.account.info("soniq2fa: login code for %s sent by %s (ip=%s)", a.getName(), sms ? "SMS" : "mail", ip);
    }

    /**
     * The client as the Carbonio proxy saw it: the last X-Forwarded-For entry (the one nginx appends; earlier entries
     * come from the client), else the connection's address. For limits, where a forged value must not help.
     */
    private static String proxyPeer(HttpServletRequest req) {
        String f = req.getHeader("X-Forwarded-For");
        if (f == null || f.isBlank()) return req.getRemoteAddr();
        String[] parts = f.split(",");
        return parts[parts.length - 1].trim();
    }

    /**
     * The address is in a domain of this server (a mailbox, an alias, a list, possibly one forwarding back): codes sent
     * there could be read with a device password, so the e-mail channel refuses such addresses.
     */
    static boolean onThisServer(String address) {
        int at = address == null ? -1 : address.lastIndexOf('@');
        if (at < 0) return false;
        try {
            return Provisioning.getInstance().getDomainByName(address.substring(at + 1).toLowerCase()) != null;
        } catch (ServiceException e) {
            return true;
        }
    }

    /** A request parameter for the log: no line breaks, at most 100 characters. */
    private static String safe(String s) {
        if (s == null) return "";
        String t = s.replaceAll("[\\p{Cntrl}]", "_");
        return t.length() > 100 ? t.substring(0, 100) + "..." : t;
    }

    /** Sends a code that confirms a phone number for SMS codes; called from the self-service page. */
    static boolean verifyPhone(Account a, String phone) {
        if (!RecoveryCodes.mayMail("phone:" + a.getId())) return false;
        String code = RecoveryCodes.issue("phone:" + a.getId(), PHONE_MS, phone, 6);
        textLater(a, phone, "sms.verify", Map.of("code", code, "account", a.getName(), "minutes", "10"));
        ZimbraLog.account.info("soniq2fa: %s asked to confirm a phone number for SMS codes", a.getName());
        return true;
    }

    /** The phone number confirmed by the code, or null. */
    static String confirmPhone(Account a, String code) {
        RecoveryCodes.Pending p = RecoveryCodes.check("phone:" + a.getId(), code, true);
        return p == null ? null : p.extra;
    }

    /** null on success, else an error code; unknown accounts get the same answer as a wrong mailed code. */
    private static String finish(String name, String mailCode, String code, String password, HttpServletRequest req) throws Exception {
        Account a = eligible(name);
        String key = a == null ? null : "reset:" + a.getId();
        if (a == null || RecoveryCodes.check(key, mailCode, false) == null) return "invalid_mail_code";
        if (password == null || password.isEmpty()) return "password_policy";
        Provisioning prov = Provisioning.getInstance();
        // before the second factor, so a rejected new password does not use up a backup code
        try {
            prov.checkPasswordStrength(a, password);
        } catch (ServiceException e) {
            throw new PolicyError(e.getMessage());
        }
        String error = Soniq2faAuth.verifySecondFactor(a, Secrets.read(a.getId(), a.getAttr(Soniq2faAuth.A_SECRET)), code, true);
        if (error != null) return error;
        try {
            prov.setPassword(a, password, true);
        } catch (ServiceException e) {
            throw new PolicyError(e.getMessage());
        }
        RecoveryCodes.check(key, mailCode, true);
        Soniq2faAuth.dropImapConnections(a, "password reset by recovery");
        if ("lockout".equals(a.getAttr("zimbraAccountStatus"))) {
            Map<String, Object> m = new HashMap<>();
            m.put("zimbraAccountStatus", "active");
            m.put("zimbraPasswordLockoutFailureTime", "");
            m.put("zimbraPasswordLockoutLockedTime", "");
            prov.modifyAttrs(a, m);
        }
        mailLater(a, a.getAttr(A_ADDRESS), "mail.changed.subject", "mail.changed.body",
                Map.of("account", a.getName(), "ip", client(req)));
        ZimbraLog.account.info("soniq2fa: %s reset the password by recovery (mailed code and second factor, ip=%s)",
                a.getName(), client(req));
        return null;
    }

    /** Sends a code that confirms a new recovery address; called from the self-service page. */
    static boolean verifyAddress(Account a, String address) {
        if (!RecoveryCodes.mayMail("address:" + a.getId())) return false;
        String code = RecoveryCodes.issue("address:" + a.getId(), ADDRESS_MS, address);
        mailLater(a, address, "mail.verify.subject", "mail.verify.body", Map.of("code", code, "account", a.getName(), "minutes", "30"));
        ZimbraLog.account.info("soniq2fa: %s asked to verify a new recovery address", a.getName());
        return true;
    }

    /** The address confirmed by the code, or null. */
    static String confirmAddress(Account a, String code) {
        RecoveryCodes.Pending p = RecoveryCodes.check("address:" + a.getId(), code, true);
        return p == null ? null : p.extra;
    }

    // --- mail ---

    private static void mailLater(Account a, String to, String subjectKey, String bodyKey, Map<String, String> vars) {
        String lang = Soniq2faPage.language(a, null);
        MAILER.submit(() -> {
            try {
                MimeMessage m = new MimeMessage(JMSession.getSmtpSession(a));
                // The account itself: it exists, so the MTA accepts it (a made-up local sender such as postmaster@ is
                // rejected where the domain has no such address), and the recipient sees which mailbox it concerns.
                m.setFrom(new InternetAddress(a.getName(), text(lang, "title", Map.of()), "UTF-8"));
                m.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
                m.setSubject(text(lang, subjectKey, vars), "UTF-8");
                m.setText(text(lang, bodyKey, vars), "UTF-8");
                m.setSentDate(new Date());
                Transport.send(m);
                ZimbraLog.account.info("soniq2fa: mail '%s' for %s handed to the MTA", subjectKey, a.getName());
            } catch (Throwable e) {
                // Throwable: an Error inside an executor task would otherwise vanish in its Future
                ZimbraLog.account.warn("soniq2fa: mail '%s' to the recovery address of %s failed", subjectKey, a.getName(), e);
            }
        });
    }

    /** A notice mail (no code) to an address of the account, sent in the background. */
    static void notice(Account a, String to, String subjectKey, String bodyKey, Map<String, String> vars) {
        mailLater(a, to, subjectKey, bodyKey, vars);
    }

    private static void textLater(Account a, String phone, String key, Map<String, String> vars) {
        String lang = Soniq2faPage.language(a, null);
        MAILER.submit(() -> {
            try {
                Channels.sendSms(a.getDomainName(), phone, text(lang, key, vars));
                ZimbraLog.account.info("soniq2fa: SMS '%s' for %s accepted by the gateway", key, a.getName());
            } catch (Throwable e) {
                ZimbraLog.account.warn("soniq2fa: SMS '%s' for %s failed", key, a.getName(), e);
            }
        });
    }

    /** One text of i18n/<lang>.json (English as fallback) with {placeholders} filled. */
    static String text(String lang, String key, Map<String, String> vars) throws IOException {
        String v = RecoveryCodes.value(Soniq2faPage.bundle(lang), key);
        if (v == null) v = RecoveryCodes.value(Soniq2faPage.bundle("en"), key);
        if (v == null) v = key;
        for (Map.Entry<String, String> e : vars.entrySet()) v = v.replace("{" + e.getKey() + "}", e.getValue());
        return v;
    }
}
