// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.auth.AuthMechanism;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.service.AuthProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Self-service page at /service/extension/soniq2fa, authenticated by the webmail session cookie.
 *
 * GET              page; ?op=app.js, ?op=qrcode.js static scripts; ?op=i18n texts in the user's language;
 *                  ?op=state JSON; ?op=domain&name=<mail domain> {"twoFactor":bool,"sms":bool} for the login page
 * Errors are returned as codes ({"error":"invalid_code"}); the page maps them to text from i18n/<lang>.json.
 * POST op=start    new pending secret (10 min), returned for the QR code
 * POST op=confirm  password, code - saves the pending secret: 2FA is on from here. Ends every other session of the
 *                  account (zimbraAuthTokenValidityValue + 1, as a password change does) and sets a new session cookie
 *                  for this one; open IMAP connections are closed too. Also turns off Carbonio's password
 *                  recovery by mail for the account (zimbraFeatureResetPasswordStatus), which signs in without the
 *                  domain mechanism and would skip the second factor; a forgotten password is reset by the admin. When 2FA is required, both also
 *                  work with 2FA on (a new phone): the secret and backup codes are replaced, device passwords stay
 * POST op=disable           - removes the secret, every device password and the backup codes; refused when
 *                            2FA is required for the account
 * POST op=create   label  - new device password, shown once
 * POST op=revoke   label  - removes one app password
 * POST op=codes           - 10 new backup codes (old ones void), shown once; confirm also returns the first set
 * POST op=address  address - mails a code to a new recovery address (self-service password recovery)
 * POST op=address-confirm code - saves the address as verified
 * POST op=phone    phone, password - texts a code to a phone number for SMS login codes (when the server has an SMS
 *                  gateway and the number's country is allowed)
 * POST op=phone-confirm code - saves the number as a login code channel
 * POST op=phone-remove    - removes the number
 * POST op=email-codes on (1|0), password for on - login codes to the verified recovery address on or off; refused
 *                  for an address in a domain of this server
 * Adding a channel, a device password or new backup codes, changing the recovery address and turning 2FA off ask for
 * the mailbox password again (decision 2026-10-25, after a security review): a stolen session alone cannot mint lasting
 * access. Removing a device needs no password, it only narrows access.
 *
 * POST needs the X-Soniq2fa header (a cross-site form cannot set it without a CORS preflight we never answer)
 * and a same-host Origin when the browser sends one. Turning 2FA on needs the mailbox password and the first code
 * from the app. After that the session is trusted: a webmail session of an enrolled account was itself opened with
 * the second factor, so device passwords, new backup codes and turning 2FA off need no further code (decision
 * 2026-10-10; the cost is that a stolen session can mint a device password). Delegated sessions are refused, except an
 * admin's session delegated to its own account (webmail opened from the admin console).
 */
public final class Soniq2faPage extends ExtensionHttpHandler {
    private static final long PENDING_MS = 10 * 60_000;
    static final String A_RESET_PASSWORD = "zimbraFeatureResetPasswordStatus";
    private static final Map<String, String[]> PENDING = new ConcurrentHashMap<>();

    @Override
    public String getPath() {
        return "/soniq2fa";
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        noCache(resp);
        String op = req.getParameter("op");
        if ("app.js".equals(op) || "qrcode.js".equals(op)) {
            resource(resp, op, "text/javascript; charset=utf-8");
            return;
        }
        if ("domain".equals(op)) {
            boolean on = domainUsesTwoFactor(req.getParameter("name"));
            warnUnreadableGateway();
            json(resp, 200, "{\"twoFactor\":" + on + ",\"codeRequired\":true" + ",\"sms\":" + (on && smsEnabled(mailDomain(req.getParameter("name")))) + "}");
            return;
        }
        Account acct = user(req);
        if ("i18n".equals(op)) {
            String lang = language(acct, req);
            json(resp, 200, "{\"lang\":" + q(lang) + ",\"messages\":" + bundle(lang) + ",\"fallback\":" + bundle("en") + "}");
            return;
        }
        if (acct == null) {
            if ("state".equals(op)) json(resp, 401, "{\"error\":\"login\"}");
            else resp.sendRedirect("/");
            return;
        }
        if ("state".equals(op)) {
            try {
                json(resp, 200, state(acct));
            } catch (Exception e) {
                ZimbraLog.account.warn("soniq2fa: state error for %s", acct.getName(), e);
                json(resp, 500, "{\"error\":\"server\"}");
            }
            return;
        }
        resp.setHeader("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'");
        resource(resp, "page.html", "text/html; charset=utf-8");
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        noCache(resp);
        // parameters only from the body: a query string would take precedence in getParameter and let a crafted link
        // swap the action our own page sends (e.g. ?op=disable), whatever the user clicked
        if (req.getQueryString() != null && !req.getQueryString().isEmpty()) {
            json(resp, 400, "{\"error\":\"rejected\"}");
            return;
        }
        if (req.getHeader("X-Soniq2fa") == null || !sameHost(req.getHeader("Origin"), req.getHeader("Host"))) {
            json(resp, 403, "{\"error\":\"rejected\"}");
            return;
        }
        Account acct = user(req);
        if (acct == null) {
            json(resp, 401, "{\"error\":\"login\"}");
            return;
        }
        try {
            String op = req.getParameter("op");
            String secret = acct.getAttr(Soniq2faAuth.A_SECRET);
            boolean on = secret != null && !secret.isEmpty();
            Provisioning prov = Provisioning.getInstance();
            // turning 2FA off and removing devices stay possible whatever the configuration; widening needs a safe one
            if (!"disable".equals(op) && !"revoke".equals(op) && unavailable(acct) != null) throw new UserError("unavailable");
            switch (op == null ? "" : op) {
                case "start" -> {
                    if (on && !required(acct)) throw new UserError("already_on");
                    json(resp, 200, startEnrolment(acct));
                }
                case "confirm" -> {
                    if (on && !required(acct)) throw new UserError("already_on");
                    pendingSecret(acct);
                    checkPassword(prov, acct, req.getParameter("password"));
                    String[] codes = finishEnrolment(prov, acct, req.getParameter("code"), Soniq2faRecovery.client(req));
                    // every other session ended; this one gets a new cookie so webmail around the page keeps working
                    // (encode(req, resp, boolean) is a no-op in Carbonio; this is the call its AuthRequest makes)
                    AuthProvider.getAuthToken(acct).encode(resp, false, com.zimbra.common.util.ZimbraCookie.secureCookie(req), false);
                    json(resp, 200, withCodes(state(acct), codes));
                }
                case "disable" -> {
                    if (!on) throw new UserError("already_off");
                    if (required(acct)) throw new UserError("required");
                    checkPassword(prov, acct, req.getParameter("password"));
                    Map<String, Object> m = new HashMap<>();
                    m.put(Soniq2faAuth.A_SECRET, "");
                    m.put(Soniq2faAuth.A_APP_PASSWORDS, "");
                    m.put(Soniq2faAuth.A_BACKUP_CODES, "");
                    m.put(Channels.A_CHANNELS, "");
                    synchronized (Soniq2faAuth.BACKUP_LOCK) {
                        prov.modifyAttrs(acct, m, false);
                    }
                    RecoveryCodes.drop(Soniq2faRecovery.loginKey(acct));
                    ZimbraLog.account.info("soniq2fa: %s disabled two-factor authentication (ip=%s)", acct.getName(), Soniq2faRecovery.client(req));
                    Soniq2faAuth.dropImapConnections(acct, "2FA turned off");
                    json(resp, 200, state(acct));
                }
                case "create" -> {
                    if (!on) throw new UserError("enable_first");
                    String label = req.getParameter("label");
                    if (label == null || !label.trim().matches("[\\p{L}0-9 ._-]{1,40}"))
                        throw new UserError("bad_label");
                    checkPassword(prov, acct, req.getParameter("password"));
                    label = label.trim();
                    String[] existing = acct.getMultiAttr(Soniq2faAuth.A_APP_PASSWORDS);
                    if (existing.length >= TwoFa.MAX_DEVICES) throw new UserError("too_many_devices");
                    for (String e : existing)
                        if (TwoFa.label(e).equalsIgnoreCase(label)) throw new UserError("label_taken");
                    String pw = TwoFa.newAppPassword();
                    prov.modifyAttrs(acct, Map.of("+" + Soniq2faAuth.A_APP_PASSWORDS, TwoFa.hashAppPassword(label, pw)), false);
                    ZimbraLog.account.info("soniq2fa: %s created device password '%s'", acct.getName(), label);
                    json(resp, 200, "{\"password\":" + q(pw) + ",\"label\":" + q(label) + "}");
                }
                case "revoke" -> {
                    String label = req.getParameter("label");
                    String entry = null;
                    for (String e : acct.getMultiAttr(Soniq2faAuth.A_APP_PASSWORDS))
                        if (TwoFa.label(e).equals(label)) entry = e;
                    if (entry == null) throw new UserError("no_device");
                    prov.modifyAttrs(acct, Map.of("-" + Soniq2faAuth.A_APP_PASSWORDS, entry), false);
                    ZimbraLog.account.info("soniq2fa: %s revoked device password '%s'", acct.getName(), label);
                    Soniq2faAuth.dropImapConnections(acct, "device password revoked");
                    json(resp, 200, state(acct));
                }
                case "address" -> {
                    String address = req.getParameter("address");
                    address = address == null ? "" : address.trim();
                    if (!address.matches("[^@\\s]{1,64}@[^@\\s]{1,253}\\.[^@\\s]{2,}") || address.equalsIgnoreCase(acct.getName()))
                        throw new UserError("bad_address");
                    // on this server it could be an alias of this very mailbox, readable with a device password
                    if (Soniq2faRecovery.onThisServer(address)) throw new UserError("address_local");
                    checkPassword(prov, acct, req.getParameter("password"));
                    if (!Soniq2faRecovery.verifyAddress(acct, address)) throw new UserError("mail_limit");
                    json(resp, 200, "{\"pending\":" + q(RecoveryCodes.mask(address)) + "}");
                }
                case "address-confirm" -> {
                    String address = Soniq2faRecovery.confirmAddress(acct, req.getParameter("code"));
                    if (address == null) throw new UserError("invalid_mail_code");
                    String previous = Soniq2faRecovery.confirmedAddress(acct) ? acct.getAttr(Soniq2faRecovery.A_ADDRESS) : null;
                    prov.modifyAttrs(acct, Map.of(Soniq2faRecovery.A_ADDRESS, address, Soniq2faRecovery.A_ADDRESS_STATUS, "verified"), false);
                    setChannel(prov, acct, Channels.RECOVERY_PREFIX, Channels.RECOVERY_PREFIX + address.toLowerCase(java.util.Locale.ROOT));
                    RecoveryCodes.drop(Soniq2faRecovery.loginKey(acct));
                    if (previous != null && !previous.equalsIgnoreCase(address))
                        Soniq2faRecovery.notice(acct, previous, "mail.addressChanged.subject", "mail.addressChanged.body",
                                Map.of("account", acct.getName(), "address", RecoveryCodes.mask(address), "ip", Soniq2faRecovery.client(req)));
                    ZimbraLog.account.info("soniq2fa: %s verified a new recovery address", acct.getName());
                    json(resp, 200, state(acct));
                }
                case "phone" -> {
                    if (!on) throw new UserError("enable_first");
                    if (!smsEnabled(acct)) throw new UserError("sms_unavailable");
                    String phone = Channels.normalizePhone(req.getParameter("phone"));
                    if (phone == null) throw new UserError("bad_phone");
                    if (!Channels.allowedCountry(acct.getDomainName(), phone)) throw new UserError("phone_country");
                    checkPassword(prov, acct, req.getParameter("password"));
                    if (!Soniq2faRecovery.verifyPhone(acct, phone)) throw new UserError("mail_limit");
                    json(resp, 200, "{\"pending\":" + q(Channels.maskPhone(phone)) + "}");
                }
                case "phone-confirm" -> {
                    if (!on) throw new UserError("enable_first");
                    String phone = Soniq2faRecovery.confirmPhone(acct, req.getParameter("code"));
                    if (phone == null) throw new UserError("invalid_sms_code");
                    setChannel(prov, acct, Channels.SMS_PREFIX, Channels.SMS_PREFIX + phone);
                    ZimbraLog.account.info("soniq2fa: %s confirmed a phone number for SMS codes", acct.getName());
                    json(resp, 200, state(acct));
                }
                case "phone-remove" -> {
                    setChannel(prov, acct, Channels.SMS_PREFIX, null);
                    RecoveryCodes.drop(Soniq2faRecovery.loginKey(acct));
                    ZimbraLog.account.info("soniq2fa: %s removed the phone number for SMS codes", acct.getName());
                    json(resp, 200, state(acct));
                }
                case "email-codes" -> {
                    boolean wanted = "1".equals(req.getParameter("on"));
                    if (wanted && (!on || !Soniq2faRecovery.confirmedAddress(acct)))
                        throw new UserError("address_first");
                    if (wanted && Soniq2faRecovery.onThisServer(acct.getAttr(Soniq2faRecovery.A_ADDRESS)))
                        throw new UserError("address_local");
                    if (wanted) checkPassword(prov, acct, req.getParameter("password"));
                    setChannel(prov, acct, Channels.EMAIL, wanted ? Channels.EMAIL : null);
                    if (!wanted) RecoveryCodes.drop(Soniq2faRecovery.loginKey(acct));
                    ZimbraLog.account.info("soniq2fa: %s turned login codes to the recovery address %s", acct.getName(), wanted ? "on" : "off");
                    json(resp, 200, state(acct));
                }
                case "codes" -> {
                    if (!on) throw new UserError("enable_first");
                    checkPassword(prov, acct, req.getParameter("password"));
                    String[] codes = TwoFa.newBackupCodes();
                    synchronized (Soniq2faAuth.BACKUP_LOCK) {
                        prov.modifyAttrs(acct, Map.of(Soniq2faAuth.A_BACKUP_CODES, TwoFa.hashBackupCodes(codes)), false);
                    }
                    ZimbraLog.account.info("soniq2fa: %s generated new backup codes", acct.getName());
                    json(resp, 200, withCodes(state(acct), codes));
                }
                default -> throw new UserError("rejected");
            }
        } catch (UserError e) {
            json(resp, 400, "{\"error\":" + q(e.getMessage()) + "}");
        } catch (Exception e) {
            ZimbraLog.account.warn("soniq2fa: page error for %s", acct.getName(), e);
            json(resp, 500, "{\"error\":\"server\"}");
        }
    }

    /** Replaces the channel values starting with prefix by value (null: removes them); other values stay untouched. */
    private static void setChannel(Provisioning prov, Account acct, String prefix, String value) throws ServiceException {
        java.util.List<String> drop = new java.util.ArrayList<>();
        for (String v : acct.getMultiAttr(Channels.A_CHANNELS)) if (v.startsWith(prefix) && !v.equals(value)) drop.add(v);
        Map<String, Object> m = new HashMap<>();
        if (!drop.isEmpty()) m.put("-" + Channels.A_CHANNELS, drop.toArray(new String[0]));
        if (value != null) m.put("+" + Channels.A_CHANNELS, value);
        if (!m.isEmpty()) prov.modifyAttrs(acct, m, false);
    }

    private static volatile long gatewayWarned;

    // ponytail: checked on the login page's domain request, at most one log line an hour
    private static void warnUnreadableGateway() {
        long now = System.currentTimeMillis();
        if (now - gatewayWarned < 3_600_000 || !Channels.gatewayUnreadable()) return;
        gatewayWarned = now;
        ZimbraLog.account.error("soniq2fa: %s exists but the mailbox cannot read it (owner/mode must be root:zextras 0640); "
                + "codes by SMS are off", Channels.GATEWAY_FILE);
    }

    /** A new secret waiting for its first code (10 minutes), as JSON {secret, uri} for the QR code. */
    static String startEnrolment(Account acct) {
        String s = TwoFa.newSecret();
        PENDING.put(acct.getId(), new String[]{s, Long.toString(System.currentTimeMillis())});
        return "{\"secret\":" + q(s) + ",\"uri\":" + q(TwoFa.otpauthUri(acct.getDomainName(), acct.getName(), s)) + "}";
    }

    static String pendingSecret(Account acct) throws UserError {
        String[] p = PENDING.get(acct.getId());
        if (p == null || System.currentTimeMillis() - Long.parseLong(p[1]) > PENDING_MS) throw new UserError("qr_expired");
        return p[0];
    }

    /**
     * Turns 2FA on with the pending secret once the first code matches (the caller has checked the password): stores the
     * secret (sealed) and new backup codes, turns Carbonio's recovery by mail off, ends every session of the account
     * (zimbraAuthTokenValidityValue + 1, as a password change does) and its IMAP connections, mails a notice to the
     * confirmed recovery address. Returns the backup codes, shown once.
     */
    static String[] finishEnrolment(Provisioning prov, Account acct, String code, String ip) throws Exception {
        String secret = pendingSecret(acct);
        boolean again = acct.getAttr(Soniq2faAuth.A_SECRET) != null && !acct.getAttr(Soniq2faAuth.A_SECRET).isEmpty();
        checkCode(acct, secret, code);
        String[] codes = TwoFa.newBackupCodes();
        Map<String, Object> m = new HashMap<>();
        m.put(Soniq2faAuth.A_SECRET, Secrets.forStorage(acct.getId(), secret));
        m.put(Soniq2faAuth.A_BACKUP_CODES, TwoFa.hashBackupCodes(codes));
        m.put(A_RESET_PASSWORD, "disabled");
        int validity = acct.getAuthTokenValidityValue();
        acct.setAuthTokenValidityValue(validity == Integer.MAX_VALUE ? 0 : validity + 1, m);
        String since = Enforcement.marker(acct);
        if (since != null) m.put("-" + Channels.A_CHANNELS, since);
        synchronized (Soniq2faAuth.BACKUP_LOCK) {
            prov.modifyAttrs(acct, m, false);
        }
        PENDING.remove(acct.getId());
        ZimbraLog.account.info("soniq2fa: %s %s two-factor authentication (ip=%s)", acct.getName(), again ? "set up again" : "enabled", ip);
        if (Soniq2faRecovery.confirmedAddress(acct))
            Soniq2faRecovery.notice(acct, acct.getAttr(Soniq2faRecovery.A_ADDRESS), "mail.enabled.subject", "mail.enabled.body",
                    Map.of("account", acct.getName(), "ip", ip));
        Soniq2faAuth.dropImapConnections(acct, "2FA turned on");
        return codes;
    }

    static final class UserError extends Exception {
        private static final long serialVersionUID = 1L;

        UserError(String m) {
            super(m);
        }
    }

    /** First TOTP code from the app, confirming the enrolment. */
    static void checkCode(Account acct, String secret, String code) throws Exception {
        String error = Soniq2faAuth.verifySecondFactor(acct, secret, code, false);
        if (error != null) throw new UserError(error);
    }

    /** Mailbox password, counted against the same per-account limit as codes. */
    static void checkPassword(Provisioning prov, Account acct, String password) throws Exception {
        if (!TwoFa.THROTTLE.tryAcquire(acct.getId(), System.currentTimeMillis())) throw new UserError("too_many_attempts");
        // as a login: a locked account is refused and a wrong password counts as a failed login
        com.zimbra.cs.account.ldap.LdapLockoutPolicy lockout = new com.zimbra.cs.account.ldap.LdapLockoutPolicy(prov, acct);
        if (lockout.isLockedOut()) throw new UserError("too_many_attempts");
        try {
            AuthMechanism.doZimbraAuth((LdapProv) prov, prov.getDomain(acct), acct, password == null ? "" : password, new HashMap<>());
        } catch (ServiceException e) {
            lockout.failedLogin();
            throw new UserError("invalid_password");
        }
        TwoFa.THROTTLE.reset(acct.getId());
    }

    /**
     * Origin and Host name the same host. Ports are not compared: behind the admin console proxy the mailbox sees
     * Host <name>:7071 while the browser sends Origin <name>:6071. Cross-site requests are stopped by X-Soniq2fa anyway.
     */
    static boolean sameHost(String origin, String host) {
        if (origin == null) return true;
        try {
            String name = host == null ? null : host.replaceFirst(":\\d+$", "");
            return name != null && name.equalsIgnoreCase(new java.net.URI(origin).getHost());
        } catch (Exception e) {
            return false;
        }
    }

    private static Account user(HttpServletRequest req) {
        try {
            AuthToken at = AuthProvider.getAuthToken(req, false);
            // "log in as" another user is refused; an admin's own mailbox opened from the admin console is also a delegated
            // session, but of the admin to itself, and counts as the user's own
            if (at == null || at.isDelegatedAuth() && !at.getAccountId().equals(at.getAdminAccountId())) return null;
            // expiry, logout, password-change invalidation, account status and token usage
            return AuthProvider.validateAuthToken(Provisioning.getInstance(), at, false, AuthToken.Usage.AUTH);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * null when 2FA can be turned on for the account, else why not. Each reason is a configuration in which the
     * second factor could be bypassed: the domain does not use soniq2fa, a refused login falls back to the plain
     * password or admin logins use another mechanism. "not_offered": the domain uses soniq2fa, but the account may
     * not turn it on (an account that already has it keeps managing it).
     */
    static String unavailable(Account acct) throws Exception {
        Domain d = Provisioning.getInstance().getDomain(acct);
        String mech = d.getAttr("zimbraAuthMech");
        if (mech == null || !mech.startsWith("custom:soniq2fa")) return "not_enabled";
        String secret = acct.getAttr(Soniq2faAuth.A_SECRET);
        if ((secret == null || secret.isEmpty()) && !offered(acct)) return "not_offered";
        if (d.getBooleanAttr("zimbraAuthFallbackToLocal", false)) return "fallback";
        String adminMech = d.getAttr("zimbraAuthMechAdmin");
        if (adminMech != null && !adminMech.isEmpty() && !adminMech.startsWith("custom:soniq2fa")) return "admin_mech";
        return null;
    }

    /**
     * The domain-wide level, an argument of the mechanism: "custom:soniq2fa available" lets every account turn 2FA
     * on, "custom:soniq2fa required" makes it mandatory; plain "custom:soniq2fa" leaves it to the account flags.
     */
    private static String domainLevel(Account acct) throws Exception {
        java.util.List<String> args = mechArgs(Provisioning.getInstance().getDomain(acct));
        return args.contains("required") ? "required" : args.contains("available") ? "available" : "";
    }

    /** Words after "custom:soniq2fa " in the domain's mechanism: the level (available | required) and the flag "sms". */
    static java.util.List<String> mechArgs(Domain d) {
        String mech = d == null ? null : d.getAttr("zimbraAuthMech");
        if (mech == null || !mech.startsWith("custom:soniq2fa ")) return java.util.List.of();
        return java.util.List.of(mech.substring("custom:soniq2fa ".length()).trim().toLowerCase(java.util.Locale.ROOT).split("\\s+"));
    }

    /**
     * Codes by SMS for the domain: the flag "sms" of its mechanism (set on the administration page; off by default, so a
     * domain never sends SMS on a gateway it was not meant to use) and a working gateway for it (Channels).
     */
    static boolean smsEnabled(Domain d) {
        return d != null && mechArgs(d).contains("sms") && Channels.smsAvailable(d.getName());
    }

    static boolean smsEnabled(Account acct) {
        try {
            return smsEnabled(Provisioning.getInstance().getDomain(acct));
        } catch (Exception e) {
            return false;
        }
    }

    /** 2FA mandatory: domain level "required" or zimbraFeatureTwoFactorAuthRequired (account, inherited from COS). */
    static boolean required(Account acct) throws Exception {
        return "required".equals(domainLevel(acct)) || acct.getBooleanAttr("zimbraFeatureTwoFactorAuthRequired", false);
    }

    /** The account may turn 2FA on: required, domain level "available" or zimbraFeatureTwoFactorAuthAvailable. */
    static boolean offered(Account acct) throws Exception {
        return required(acct) || "available".equals(domainLevel(acct))
                || acct.getBooleanAttr("zimbraFeatureTwoFactorAuthAvailable", false);
    }

    /**
     * For the login page: whether a mail domain uses soniq2fa, so the page knows to ask for the code. Says nothing
     * about accounts (no account lookup, same answer for every name in the domain); domain names are public (MX).
     */
    static boolean domainUsesTwoFactor(String name) {
        Domain d = mailDomain(name);
        String mech = d == null ? null : d.getAttr("zimbraAuthMech");
        return mech != null && mech.startsWith("custom:soniq2fa");
    }

    /** The domain of a login name's domain part, an alias domain resolved to its target; null if unknown or invalid. */
    static Domain mailDomain(String name) {
        if (name == null || !name.matches("[A-Za-z0-9.-]{1,253}")) return null;
        try {
            Provisioning prov = Provisioning.getInstance();
            Domain d = prov.getDomainByName(name.toLowerCase());
            if (d != null && "alias".equals(d.getAttr("zimbraDomainType"))) {
                String target = d.getAttr("zimbraDomainAliasTargetId");
                d = target == null ? null : prov.getDomainById(target);
            }
            return d;
        } catch (Exception e) {
            return null;
        }
    }

    private static String state(Account acct) throws Exception {
        String secret = acct.getAttr(Soniq2faAuth.A_SECRET);
        String reason = unavailable(acct);
        StringBuilder devices = new StringBuilder();
        for (String e : acct.getMultiAttr(Soniq2faAuth.A_APP_PASSWORDS))
            devices.append(devices.length() == 0 ? "" : ",").append(q(TwoFa.label(e)));
        return "{\"account\":" + q(acct.getName()) + ",\"available\":" + (reason == null)
                + ",\"reason\":" + (reason == null ? "null" : q(reason))
                + ",\"enabled\":" + (secret != null && !secret.isEmpty()) + ",\"required\":" + required(acct)
                + ",\"recovery\":" + "enabled".equalsIgnoreCase(acct.getAttr(A_RESET_PASSWORD))
                + ",\"recoveryAddress\":" + q(Soniq2faRecovery.confirmedAddress(acct)
                        ? RecoveryCodes.mask(acct.getAttr(Soniq2faRecovery.A_ADDRESS)) : "")
                + ",\"devices\":[" + devices + "]"
                + ",\"smsAvailable\":" + smsEnabled(acct)
                + ",\"phone\":" + q(Channels.maskPhone(Channels.phone(acct.getMultiAttr(Channels.A_CHANNELS))))
                + ",\"emailCodes\":" + Channels.email(acct.getMultiAttr(Channels.A_CHANNELS))
                + ",\"backupLeft\":" + TwoFa.countBackupCodes(acct.getAttr(Soniq2faAuth.A_BACKUP_CODES)) + "}";
    }

    private static String withCodes(String stateJson, String[] codes) {
        StringBuilder b = new StringBuilder();
        for (String c : codes) b.append(b.length() == 0 ? "" : ",").append(q(c));
        return stateJson.substring(0, stateJson.length() - 1) + ",\"codes\":[" + b + "]}";
    }

    /**
     * The user's Carbonio language (zimbraPrefLocale, as chosen in webmail), else the browser's, else English.
     * Only languages with a bundle in i18n/ are returned.
     */
    static String language(Account acct, HttpServletRequest req) {
        java.util.List<String> wanted = new java.util.ArrayList<>();
        if (acct != null && acct.getAttr("zimbraPrefLocale") != null) wanted.add(acct.getAttr("zimbraPrefLocale"));
        String al = req == null ? null : req.getHeader("Accept-Language");
        if (al != null) for (String part : al.split(",")) wanted.add(part.split(";")[0].trim());
        for (String w : wanted) {
            String[] parts = w.replace('-', '_').split("_");
            if (parts.length == 0) continue;
            String lang = parts[0].toLowerCase();
            if (lang.matches("[a-z]{2,3}") && Soniq2faPage.class.getResource("i18n/" + lang + ".json") != null) return lang;
        }
        return "en";
    }

    static String bundle(String lang) throws IOException {
        try (InputStream in = Soniq2faPage.class.getResourceAsStream("i18n/" + lang + ".json")) {
            return in == null ? "{}" : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20 || c == '<' || c == '>' || c == '&') b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    static void noCache(HttpServletResponse resp) {
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("X-Content-Type-Options", "nosniff");
        resp.setHeader("Referrer-Policy", "no-referrer");
    }

    static void json(HttpServletResponse resp, int status, String body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json; charset=utf-8");
        resp.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
    }

    static void resource(HttpServletResponse resp, String name, String type) throws IOException {
        try (InputStream in = Soniq2faPage.class.getResourceAsStream(name)) {
            if (in == null) {
                resp.sendError(404);
                return;
            }
            resp.setContentType(type);
            in.transferTo(resp.getOutputStream());
        }
    }
}
