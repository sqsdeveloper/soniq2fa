// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.service.AuthProvider;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Administration page at /service/extension/soniq2fa-admin, for global admins, authenticated by the admin console
 * session cookie (open it on the admin console port, e.g. https://mail.example.com:6071/service/extension/soniq2fa-admin).
 * Carbonio CE's admin console loads no external modules, so the page stands on its own and changes nothing in it.
 *
 * GET              page; ?op=admin.js; ?op=i18n; ?op=domains; ?op=accounts&domain=<name>; ?op=sms (gateways, read-only:
 *                  the configuration stays in the file on the server, the token is shown only as set / its length)
 * POST op=domain   domain, level (off | plain | available | required) - zimbraAuthMech; any level but "off" also sets
 *                  zimbraAuthFallbackToLocal FALSE first, so there is no moment in which the second factor can be skipped
 * POST op=account  account, attr (available | required), value (yes | no | inherit) - zimbraFeatureTwoFactorAuth*
 * POST op=reset    account - removes the secret, device passwords, backup codes and SMS/mail code channels (lost phone and codes)
 * POST op=recovery account, on (true | false) - zimbraFeatureResetPasswordStatus; turning it on for an account with 2FA
 *                  weakens it (the page asks first), and every login of that account logs an error
 * POST op=domain-sms domain, on (true | false) - the flag "sms" of the domain's mechanism (codes by SMS allowed)
 * POST op=sms-points gateway - points left on its SMSAPI account
 * POST op=sms-test gateway, phone - a test SMS, sent at once (at most one a minute per admin)
 *
 * POST needs the X-Soniq2fa header and a same-host Origin, as the user page. Every change is logged with the admin.
 * Served only on the mailbox admin port (zimbraAdminPort, behind the admin console proxy): cookies are not bound to a
 * port, so an admin session cookie also reaches the user port, which may be open to the world.
 */
public final class Soniq2faAdmin extends ExtensionHttpHandler {
    private static final String MECH = "custom:soniq2fa";
    private static final Map<String, String> FLAGS = Map.of(
            "available", "zimbraFeatureTwoFactorAuthAvailable", "required", "zimbraFeatureTwoFactorAuthRequired");
    private static final Map<String, String> VALUES = Map.of("yes", "TRUE", "no", "FALSE", "inherit", "");

    @Override
    public String getPath() {
        return "/soniq2fa-admin";
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Soniq2faPage.noCache(resp);
        String op = req.getParameter("op");
        if ("admin.js".equals(op)) {
            Soniq2faPage.resource(resp, op, "text/javascript; charset=utf-8");
            return;
        }
        if ("i18n".equals(op)) {
            // as the admin console: the admin's zimbraPrefLocale, else English (the browser's language is not used)
            String lang = Soniq2faPage.language(admin(req), null);
            Soniq2faPage.json(resp, 200, "{\"lang\":" + Soniq2faPage.q(lang) + ",\"messages\":" + Soniq2faPage.bundle(lang)
                    + ",\"fallback\":" + Soniq2faPage.bundle("en") + "}");
            return;
        }
        Account admin = admin(req);
        if (admin == null) {
            if (op == null) resp.sendRedirect("/");
            else Soniq2faPage.json(resp, 401, "{\"error\":\"login\"}");
            return;
        }
        try {
            if ("domains".equals(op)) Soniq2faPage.json(resp, 200, domains());
            else if ("accounts".equals(op)) Soniq2faPage.json(resp, 200, accounts(domain(req.getParameter("domain"))));
            else if ("sms".equals(op)) Soniq2faPage.json(resp, 200, gateways());
            else {
                resp.setHeader("Content-Security-Policy",
                        "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
                Soniq2faPage.resource(resp, "admin.html", "text/html; charset=utf-8");
            }
        } catch (IllegalArgumentException e) {
            Soniq2faPage.json(resp, 400, "{\"error\":" + Soniq2faPage.q(e.getMessage()) + "}");
        } catch (Exception e) {
            ZimbraLog.account.warn("soniq2fa: admin page error", e);
            Soniq2faPage.json(resp, 500, "{\"error\":\"server\"}");
        }
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Soniq2faPage.noCache(resp);
        if (req.getHeader("X-Soniq2fa") == null || !Soniq2faPage.sameHost(req.getHeader("Origin"), req.getHeader("Host"))) {
            Soniq2faPage.json(resp, 403, "{\"error\":\"rejected\"}");
            return;
        }
        Account admin = admin(req);
        if (admin == null) {
            Soniq2faPage.json(resp, 401, "{\"error\":\"login\"}");
            return;
        }
        Provisioning prov = Provisioning.getInstance();
        String op = req.getParameter("op");
        try {
            switch (op == null ? "" : op) {
                case "domain" -> {
                    Domain d = domain(req.getParameter("domain"));
                    String level = req.getParameter("level");
                    String mech = switch (level == null ? "" : level) {
                        case "off" -> "";
                        case "plain" -> MECH;
                        case "available", "required" -> MECH + " " + level;
                        default -> throw new IllegalArgumentException("rejected");
                    };
                    if (!mech.isEmpty() && Soniq2faPage.mechArgs(d).contains("sms")) mech += " sms";
                    if (!mech.isEmpty()) prov.modifyAttrs(d, Map.of("zimbraAuthFallbackToLocal", "FALSE"));
                    prov.modifyAttrs(d, Map.of("zimbraAuthMech", mech));
                    ZimbraLog.account.info("soniq2fa: admin %s set domain %s to '%s'", admin.getName(), d.getName(), mech);
                    Soniq2faPage.json(resp, 200, domains());
                }
                case "domain-sms" -> {
                    Domain d = domain(req.getParameter("domain"));
                    String level = level(d);
                    if (!java.util.Set.of("plain", "available", "required").contains(level)) throw new IllegalArgumentException("rejected");
                    boolean on = "true".equals(req.getParameter("on"));
                    String mech = MECH + ("plain".equals(level) ? "" : " " + level) + (on ? " sms" : "");
                    prov.modifyAttrs(d, Map.of("zimbraAuthMech", mech));
                    ZimbraLog.account.info("soniq2fa: admin %s turned codes by SMS %s for domain %s", admin.getName(), on ? "on" : "off", d.getName());
                    Soniq2faPage.json(resp, 200, domains());
                }
                case "sms-points" -> {
                    java.util.Properties g = gatewayByName(req.getParameter("gateway"));
                    String points;
                    try {
                        points = Channels.smsapiPoints(g);
                    } catch (java.io.IOException e) {
                        ZimbraLog.account.warn("soniq2fa: admin %s: points of SMS gateway '%s': %s", admin.getName(), g.getProperty("gateway.name"), e.getMessage());
                        throw new IllegalArgumentException("sms_gateway");
                    }
                    Soniq2faPage.json(resp, 200, "{\"points\":" + Soniq2faPage.q(points) + "}");
                }
                case "sms-test" -> {
                    java.util.Properties g = gatewayByName(req.getParameter("gateway"));
                    String phone = Channels.normalizePhone(req.getParameter("phone"));
                    if (phone == null) throw new IllegalArgumentException("bad_phone");
                    if (!Channels.allowedCountry(g, phone)) throw new IllegalArgumentException("phone_country");
                    if (!RecoveryCodes.mayMail("smstest:" + admin.getId())) throw new IllegalArgumentException("mail_limit");
                    try {
                        Channels.sendSms(g, phone, "soniq2fa: test SMS (" + g.getProperty("gateway.name") + ")");
                    } catch (java.io.IOException e) {
                        ZimbraLog.account.warn("soniq2fa: admin %s: test SMS through '%s' failed: %s", admin.getName(), g.getProperty("gateway.name"), e.getMessage());
                        Soniq2faPage.json(resp, 400, "{\"error\":\"sms_gateway\",\"detail\":" + Soniq2faPage.q(e.getMessage()) + "}");
                        return;
                    }
                    ZimbraLog.account.info("soniq2fa: admin %s sent a test SMS through '%s' to %s", admin.getName(), g.getProperty("gateway.name"), Channels.maskPhone(phone));
                    Soniq2faPage.json(resp, 200, "{\"sent\":" + Soniq2faPage.q(Channels.maskPhone(phone)) + "}");
                }
                case "account" -> {
                    Account a = account(req.getParameter("account"));
                    String attr = FLAGS.get(String.valueOf(req.getParameter("attr")));
                    String value = VALUES.get(String.valueOf(req.getParameter("value")));
                    if (attr == null || value == null) throw new IllegalArgumentException("rejected");
                    prov.modifyAttrs(a, Map.of(attr, value));
                    ZimbraLog.account.info("soniq2fa: admin %s set %s %s='%s'", admin.getName(), a.getName(), attr, value);
                    Soniq2faPage.json(resp, 200, accounts(prov.getDomain(a)));
                }
                case "reset" -> {
                    Account a = account(req.getParameter("account"));
                    Map<String, Object> m = new HashMap<>();
                    m.put(Soniq2faAuth.A_SECRET, "");
                    m.put(Soniq2faAuth.A_APP_PASSWORDS, "");
                    m.put(Soniq2faAuth.A_BACKUP_CODES, "");
                    m.put(Channels.A_CHANNELS, "");
                    synchronized (Soniq2faAuth.BACKUP_LOCK) {
                        prov.modifyAttrs(a, m, false);
                    }
                    RecoveryCodes.drop(Soniq2faRecovery.loginKey(a));
                    ZimbraLog.account.info("soniq2fa: admin %s reset two-factor authentication of %s", admin.getName(), a.getName());
                    Soniq2faAuth.dropImapConnections(a, "2FA reset by admin");
                    Soniq2faPage.json(resp, 200, accounts(prov.getDomain(a)));
                }
                case "recovery" -> {
                    Account a = account(req.getParameter("account"));
                    String status = "true".equals(req.getParameter("on")) ? "enabled" : "disabled";
                    prov.modifyAttrs(a, Map.of(Soniq2faPage.A_RESET_PASSWORD, status));
                    ZimbraLog.account.info("soniq2fa: admin %s set password recovery of %s to %s%s", admin.getName(), a.getName(),
                            status, enrolled(a) && "enabled".equals(status) ? " (account has 2FA, second factor can be bypassed)" : "");
                    Soniq2faPage.json(resp, 200, accounts(prov.getDomain(a)));
                }
                default -> throw new IllegalArgumentException("rejected");
            }
        } catch (IllegalArgumentException e) {
            Soniq2faPage.json(resp, 400, "{\"error\":" + Soniq2faPage.q(e.getMessage()) + "}");
        } catch (Exception e) {
            ZimbraLog.account.warn("soniq2fa: admin page error (%s)", admin.getName(), e);
            Soniq2faPage.json(resp, 500, "{\"error\":\"server\"}");
        }
    }

    /** A global admin of an admin console session; domain admins and delegated sessions are refused. */
    private static Account admin(HttpServletRequest req) {
        try {
            if (req.getLocalPort() != Provisioning.getInstance().getLocalServer().getAdminPort()) return null;
            AuthToken at = AuthProvider.getAuthToken(req, true);
            if (at == null || !at.isAdmin() || at.isDelegatedAuth()) return null;
            return AuthProvider.validateAuthToken(Provisioning.getInstance(), at, false, AuthToken.Usage.AUTH);
        } catch (Exception e) {
            return null;
        }
    }

    private static Domain domain(String name) throws Exception {
        Domain d = name == null ? null : Provisioning.getInstance().getDomainByName(name);
        if (d == null || "alias".equals(d.getAttr("zimbraDomainType"))) throw new IllegalArgumentException("no_domain");
        return d;
    }

    private static Account account(String name) throws Exception {
        Account a = name == null ? null : Provisioning.getInstance().getAccountByName(name);
        if (a == null) throw new IllegalArgumentException("no_account");
        return a;
    }

    private static boolean enrolled(Account a) {
        String s = a.getAttr(Soniq2faAuth.A_SECRET);
        return s != null && !s.isEmpty();
    }

    /** "off", "plain", "available", "required", or "other" for a mechanism that is not soniq2fa (ldap, ad, ...). */
    private static String level(Domain d) {
        String mech = d.getAttr("zimbraAuthMech");
        if (mech == null || mech.isEmpty() || "zimbra".equals(mech)) return "off";
        if (!mech.equals(MECH) && !mech.startsWith(MECH + " ")) return "other";
        java.util.List<String> args = Soniq2faPage.mechArgs(d);
        return args.contains("required") ? "required" : args.contains("available") ? "available" : "plain";
    }

    /** A gateway by the name shown on the page: "default" or a domain with its own token. */
    private static java.util.Properties gatewayByName(String name) {
        java.util.Properties file = Channels.file();
        if (name == null || !Channels.gatewayNames(file).contains(name)) throw new IllegalArgumentException("rejected");
        return Channels.gateway(file, Channels.DEFAULT.equals(name) ? "" : name);
    }

    private static String gateways() throws Exception {
        java.util.Properties file = Channels.file();
        String state = !java.nio.file.Files.exists(Channels.GATEWAY_FILE) ? "missing" : Channels.gatewayUnreadable() ? "unreadable" : "ok";
        java.util.Map<String, java.util.List<String>> users = new java.util.HashMap<>();
        for (Domain d : Provisioning.getInstance().getAllDomains())
            if (Soniq2faPage.mechArgs(d).contains("sms"))
                users.computeIfAbsent(Channels.gateway(file, d.getName()).getProperty("gateway.name"), k -> new java.util.ArrayList<>()).add(d.getName());
        StringBuilder b = new StringBuilder();
        long now = System.currentTimeMillis();
        for (String name : Channels.gatewayNames(file)) {
            java.util.Properties g = Channels.gateway(file, Channels.DEFAULT.equals(name) ? "" : name);
            StringBuilder ds = new StringBuilder();
            for (String d : users.getOrDefault(name, java.util.List.of())) ds.append(ds.length() == 0 ? "" : ",").append(Soniq2faPage.q(d));
            b.append(b.length() == 0 ? "" : ",").append("{\"name\":").append(Soniq2faPage.q(name))
                    .append(",\"configured\":").append(Channels.configured(g))
                    .append(",\"provider\":").append(Soniq2faPage.q(g.getProperty("sms.provider", "")))
                    .append(",\"from\":").append(Soniq2faPage.q(g.getProperty("sms.from", "")))
                    .append(",\"countries\":").append(Soniq2faPage.q(g.getProperty("sms.countries", "+48")))
                    .append(",\"maxPerHour\":").append(Soniq2faPage.q(g.getProperty("sms.maxPerHour", "200")))
                    .append(",\"url\":").append(Soniq2faPage.q(g.getProperty("sms.url", "https://api.smsapi.pl/sms.do")))
                    .append(",\"tokenLength\":").append(g.getProperty("sms.token", "").trim().length())
                    .append(",\"sentThisHour\":").append(Channels.sentThisHour(name, now))
                    .append(",\"domains\":[").append(ds).append("]}");
        }
        return "{\"file\":" + Soniq2faPage.q(Channels.GATEWAY_FILE.toString()) + ",\"state\":" + Soniq2faPage.q(state)
                + ",\"gateways\":[" + b + "]}";
    }

    private static String domains() throws Exception {
        StringBuilder b = new StringBuilder();
        for (Domain d : Provisioning.getInstance().getAllDomains()) {
            if ("alias".equals(d.getAttr("zimbraDomainType"))) continue;
            String adminMech = d.getAttr("zimbraAuthMechAdmin");
            b.append(b.length() == 0 ? "" : ",").append("{\"name\":").append(Soniq2faPage.q(d.getName()))
                    .append(",\"level\":").append(Soniq2faPage.q(level(d)))
                    .append(",\"fallback\":").append(d.getBooleanAttr("zimbraAuthFallbackToLocal", false))
                    .append(",\"adminMech\":").append(adminMech != null && !adminMech.isEmpty() && !adminMech.startsWith(MECH))
                    .append(",\"sms\":").append(Soniq2faPage.mechArgs(d).contains("sms"))
                    .append(",\"smsGateway\":").append(Soniq2faPage.q(Channels.smsAvailable(d.getName())
                            ? Channels.gateway(d.getName()).getProperty("gateway.name") : ""))
                    .append("}");
        }
        return "{\"domains\":[" + b + "]}";
    }

    private static String accounts(Domain d) throws Exception {
        StringBuilder b = new StringBuilder();
        java.util.List<Account> list = new java.util.ArrayList<>();
        for (Object o : Provisioning.getInstance().getAllAccounts(d))
            if (o instanceof Account a && !a.getBooleanAttr("zimbraIsSystemResource", false)) list.add(a);
        list.sort(java.util.Comparator.comparing(Account::getName));
        for (Account a : list) {
            Map<String, Object> f = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : FLAGS.entrySet()) {
                String own = a.getAttr(e.getValue(), false);
                f.put(e.getKey(), own == null || own.isEmpty() ? "inherit" : "TRUE".equalsIgnoreCase(own) ? "yes" : "no");
            }
            String last = a.getAttr("zimbraLastLogonTimestamp");
            b.append(b.length() == 0 ? "" : ",").append("{\"name\":").append(Soniq2faPage.q(a.getName()))
                    .append(",\"displayName\":").append(Soniq2faPage.q(a.getAttr("displayName", "")))
                    // active, locked, lockout (too many wrong passwords), maintenance, pending, closed
                    .append(",\"status\":").append(Soniq2faPage.q(a.getAttr("zimbraAccountStatus", "active")))
                    // generalized time, updated at most every zimbraLastLogonTimestampFrequency (1 day by default)
                    .append(",\"lastLogin\":").append(Soniq2faPage.q(last == null || last.length() < 8 ? ""
                            : last.substring(0, 4) + "-" + last.substring(4, 6) + "-" + last.substring(6, 8)))
                    .append(",\"available\":").append(Soniq2faPage.q((String) f.get("available")))
                    .append(",\"required\":").append(Soniq2faPage.q((String) f.get("required")))
                    .append(",\"offered\":").append(Soniq2faPage.offered(a))
                    .append(",\"mustHave\":").append(Soniq2faPage.required(a))
                    .append(",\"enabled\":").append(enrolled(a))
                    .append(",\"devices\":").append(a.getMultiAttr(Soniq2faAuth.A_APP_PASSWORDS).length)
                    .append(",\"backupLeft\":").append(TwoFa.countBackupCodes(a.getAttr(Soniq2faAuth.A_BACKUP_CODES)))
                    .append(",\"recovery\":").append("enabled".equalsIgnoreCase(a.getAttr(Soniq2faPage.A_RESET_PASSWORD)))
                    .append(",\"sms\":").append(Channels.phone(a.getMultiAttr(Channels.A_CHANNELS)) != null)
                    .append(",\"emailCodes\":").append(Channels.email(a.getMultiAttr(Channels.A_CHANNELS)))
                    .append("}");
        }
        return "{\"domain\":" + Soniq2faPage.q(d.getName()) + ",\"domainId\":" + Soniq2faPage.q(d.getId()) + ",\"level\":" + Soniq2faPage.q(level(d))
                + ",\"accounts\":[" + b + "]}";
    }
}
