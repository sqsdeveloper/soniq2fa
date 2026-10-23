// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.AccountServiceException;
import com.zimbra.cs.account.AccountServiceException.AuthFailedServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.auth.AuthContext;
import com.zimbra.cs.account.auth.AuthMechanism;
import com.zimbra.cs.account.auth.ZimbraCustomAuth;
import com.zimbra.cs.account.ldap.LdapProv;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Domain auth mechanism "custom:soniq2fa".
 *
 * Accounts without zimbraTwoFactorAuthSecret: plain password, as before.
 * Enrolled accounts:
 *   SOAP (webmail, admin console, password change) and requests without a protocol: password immediately followed
 *   by the 6-digit TOTP code, a code sent by SMS or to the recovery address, or a single-use backup code; the password is checked first, then the code,
 *   which is rate-limited per account. A wrong password is AUTH_FAILED; the right password without a code is
 *   TWO_FACTOR_AUTH_REQUIRED and with a wrong code TWO_FACTOR_AUTH_FAILED, so the login page asks for the code only
 *   when the password is right (decision 2026-10-12; password guessing stays limited by the Carbonio lockout policy,
 *   which counts all three as failed logins, and the second factor is still needed);
 *   IMAP, POP3, CalDAV/CardDAV, and SMTP AUTH (SOAP from saslauthd on zimbraMtaAuthPort, from loopback, a local
 *   address or an MTA server, never as admin): device password only, the mailbox password is refused;
 *   HTTP basic auth (REST, can return a session cookie with ?auth=sc): refused.
 *
 * The domain must have zimbraAuthFallbackToLocal=FALSE, otherwise a refusal here falls back to the plain
 * password in LdapProvisioning.verifyPasswordInternal. Refusals reach the client as a generic
 * "authentication failed"; the reason goes to the log only.
 */
public final class Soniq2faAuth extends ZimbraCustomAuth {
    static final String A_SECRET = "zimbraTwoFactorAuthSecret";
    static final String A_APP_PASSWORDS = "zimbraAppSpecificPassword";
    static final String A_BACKUP_CODES = "zimbraTwoFactorAuthScratchCodes";
    /** Guards every write of A_BACKUP_CODES in this JVM. */
    static final Object BACKUP_LOCK = new Object();

    @Override
    public void authenticate(Account acct, String password, Map<String, Object> ctx, List<String> args) throws Exception {
        LdapProv prov = (LdapProv) Provisioning.getInstance();
        Domain domain = prov.getDomain(acct);
        String secret = acct.getAttr(A_SECRET);
        if (secret == null || secret.isEmpty()) {
            AuthMechanism.doZimbraAuth(prov, domain, acct, password, ctx);
            return;
        }
        if (domain.getBooleanAttr("zimbraAuthFallbackToLocal", false))
            ZimbraLog.account.error("soniq2fa: domain %s has zimbraAuthFallbackToLocal=TRUE, second factor can be bypassed", domain.getName());
        if ("enabled".equalsIgnoreCase(acct.getAttr(Soniq2faPage.A_RESET_PASSWORD)))
            ZimbraLog.account.error("soniq2fa: %s has password recovery by mail enabled, second factor can be bypassed", acct.getName());

        Object proto = ctx.get(AuthContext.AC_PROTOCOL);
        if (proto == null || proto == AuthContext.Protocol.soap) {
            if (proto == null || !isMta(prov, ctx)) {
                secondFactorLogin(prov, domain, acct, secret, password, ctx);
                return;
            }
        } else if (proto == AuthContext.Protocol.http_basic) {
            throw deny(acct, ctx, "device passwords are not accepted for HTTP basic auth");
        }
        String label = TwoFa.matchAppPassword(acct.getMultiAttr(A_APP_PASSWORDS), password);
        if (label == null) throw deny(acct, ctx, "device password required (proto=" + proto + ")");
        ZimbraLog.account.info("soniq2fa: %s device password '%s' accepted (proto=%s)", acct.getName(), label, proto);
    }

    @Override
    public boolean checkPasswordAging() {
        return true;
    }

    /**
     * password = mailbox password + TOTP code | backup code ("xxxxx-xxxxx" or "xxxxxxxxxx"). Each plausible split
     * is tried against the mailbox password; only after the password matches is the code checked.
     */
    private static void secondFactorLogin(LdapProv prov, Domain domain, Account acct, String secret, String password,
                                          Map<String, Object> ctx) throws Exception {
        int n = password == null ? 0 : password.length();
        for (int len : new int[]{TwoFa.DIGITS, TwoFa.BACKUP_LEN + 1, TwoFa.BACKUP_LEN}) {
            int cut = n - len;
            if (cut < 1) continue;
            String code = password.substring(cut);
            if (len == TwoFa.DIGITS && !code.matches("[0-9]{6}")) continue;
            if (len == TwoFa.BACKUP_LEN + 1 && code.indexOf('-') != TwoFa.BACKUP_LEN / 2) continue;
            if (len == TwoFa.BACKUP_LEN && code.indexOf('-') >= 0) continue;
            try {
                AuthMechanism.doZimbraAuth(prov, domain, acct, password.substring(0, cut), ctx);
            } catch (ServiceException wrongPassword) {
                continue;
            }
            String error = verifySecondFactor(acct, secret, code, true);
            if (error != null) {
                ZimbraLog.account.info("soniq2fa: %s refused: second factor: %s", acct.getName(), error);
                throw AccountServiceException.TWO_FACTOR_AUTH_FAILED(acct.getName(), AuthMechanism.namePassedIn(ctx), "soniq2fa: " + error);
            }
            return;
        }
        try {
            AuthMechanism.doZimbraAuth(prov, domain, acct, password == null ? "" : password, ctx);
        } catch (ServiceException wrongPassword) {
            throw deny(acct, ctx, "password invalid");
        }
        ZimbraLog.account.info("soniq2fa: %s refused: password right, code missing", acct.getName());
        throw AccountServiceException.TWO_FACTOR_AUTH_REQUIRED();
    }

    /**
     * Checks a TOTP code (or, with allowBackup, a backup code or a sent login code, both consumed). Returns null on success,
     * else an error code for the page: too_many_attempts, invalid_code, code_used.
     */
    static String verifySecondFactor(Account acct, String secret, String code, boolean allowBackup) throws Exception {
        String id = acct.getId();
        if (!TwoFa.THROTTLE.tryAcquire(id, System.currentTimeMillis())) return "too_many_attempts";
        String c = code == null ? "" : code.replace(" ", "").trim();
        if (c.matches("[0-9]{" + TwoFa.DIGITS + "}")) {
            long counter = TwoFa.matchTotp(secret, c, System.currentTimeMillis());
            if (counter == TwoFa.NO_MATCH) {
                // a code sent by SMS or to the recovery address (Soniq2faRecovery, op=send), single use; while one is
                // pending a guess has one more valid value, still within the THROTTLE limit
                if (!allowBackup || RecoveryCodes.check(Soniq2faRecovery.loginKey(acct), c, true) == null) return "invalid_code";
            } else if (!TwoFa.REPLAY.accept(id, counter)) {
                return "code_used";
            }
        } else if (!allowBackup || !consumeBackupCode(acct, c)) {
            return "invalid_code";
        }
        TwoFa.THROTTLE.reset(id);
        return null;
    }

    /** Removes the backup code if it is valid and unused. */
    static boolean consumeBackupCode(Account acct, String code) throws Exception {
        synchronized (BACKUP_LOCK) {
            String rest = TwoFa.useBackupCode(acct.getAttr(A_BACKUP_CODES), code);
            if (rest == null) return false;
            Provisioning.getInstance().modifyAttrs(acct, Map.of(A_BACKUP_CODES, rest), false);
            ZimbraLog.account.info("soniq2fa: %s used a backup code, %d left", acct.getName(), TwoFa.countBackupCodes(rest));
            return true;
        }
    }

    /**
     * Closes the account's open IMAP connections (BYE). IMAP checks the password only at login, so a connection opened
     * with the mailbox password before 2FA was turned on, or with a device password since revoked, would otherwise
     * stay usable for hours (seen 2026-10-12: one Thunderbird connection, 1669 commands over 8 hours). Clients with a
     * valid device password reconnect on their own. Reaches connections with a selected folder (an IMAP session in
     * SessionCache), which covers mail clients idling on a folder; reflection, because the handler is not public API.
     * Returns the number of connections closed, -1 when the mailbox classes are not as expected.
     */
    static int dropImapConnections(Account acct, String why) {
        int n = 0;
        try {
            Class<?> listener = Class.forName("com.zimbra.cs.imap.ImapListener");
            Method handlerOf = listener.getDeclaredMethod("getHandler");
            handlerOf.setAccessible(true);
            Method drop = Class.forName("com.zimbra.cs.imap.ImapHandler").getDeclaredMethod("dropConnection", boolean.class);
            drop.setAccessible(true);
            Set<Object> handlers = new HashSet<>();
            for (Object s : com.zimbra.cs.session.SessionCache.getAllSessions(acct.getId())) {
                if (!listener.isInstance(s)) continue;
                Object h = handlerOf.invoke(s);
                if (h != null && handlers.add(h)) {
                    drop.invoke(h, true);
                    n++;
                }
            }
        } catch (Throwable t) {
            // error level: connections opened with a credential just withdrawn stay usable until the client disconnects
            ZimbraLog.account.error("soniq2fa: cannot close IMAP connections of %s (%s)", acct.getName(), why, t);
            return -1;
        }
        if (n > 0) ZimbraLog.account.info("soniq2fa: closed %d IMAP connection(s) of %s (%s)", n, acct.getName(), why);
        return n;
    }

    /** Generic failure for the client; the reason is logged by the mailbox, not returned. */
    private static AuthFailedServiceException deny(Account acct, Map<String, Object> ctx, String reason) {
        ZimbraLog.account.info("soniq2fa: %s refused: %s", acct.getName(), reason);
        return AuthFailedServiceException.AUTH_FAILED(acct.getName(), AuthMechanism.namePassedIn(ctx), "soniq2fa: " + reason);
    }

    // ---- SMTP AUTH detection ----

    /**
     * SMTP AUTH reaches the mailbox as SOAP from saslauthd on zimbraMtaAuthPort, a port nginx does not proxy.
     * Accepted only on that port, from loopback, a local address or an MTA server, and never as an admin login.
     * Headers such as X-Forwarded-Proto are not used: nginx passes them from the client on the HTTPS virtual host.
     * Any failure answers "not MTA", which makes SMTP AUTH demand a TOTP code (fails closed).
     */
    static boolean isMta(Provisioning prov, Map<String, Object> ctx) {
        if (Boolean.TRUE.equals(ctx.get(AuthContext.AC_AS_ADMIN))) return false;
        try {
            InetSocketAddress[] la = Jetty.localAndRemote();
            if (la == null) return false;
            int port = prov.getLocalServer().getIntAttr("zimbraMtaAuthPort", 7073);
            if (la[0].getPort() != port) return false;
            InetAddress remote = la[1].getAddress();
            return remote.isLoopbackAddress() || NetworkInterface.getByInetAddress(remote) != null
                    || mtaAddresses(prov).contains(remote);
        } catch (Throwable t) {
            ZimbraLog.account.warn("soniq2fa: cannot read the connection, treating as non-MTA", t);
            return false;
        }
    }

    private static volatile Set<InetAddress> mtaCache = Collections.emptySet();
    private static volatile long mtaCacheTime;

    // ponytail: refreshed every 5 minutes; a new MTA server waits up to that long
    private static Set<InetAddress> mtaAddresses(Provisioning prov) throws ServiceException {
        if (System.currentTimeMillis() - mtaCacheTime < 300_000) return mtaCache;
        Set<InetAddress> s = new HashSet<>();
        for (Server server : prov.getAllServers("mta")) {
            try {
                Collections.addAll(s, InetAddress.getAllByName(server.getAttr("zimbraServiceHostname")));
            } catch (Exception e) {
                ZimbraLog.account.warn("soniq2fa: cannot resolve MTA server %s", server.getName());
            }
        }
        mtaCache = s;
        mtaCacheTime = System.currentTimeMillis();
        return s;
    }

    /**
     * Local and remote address of the HTTP connection serving the current request. Reflection keeps the jar
     * independent of the Jetty version: Jetty 9.4 (mailbox up to 4.27) has org.eclipse.jetty.server.HttpConnection,
     * Jetty 12 (4.28+) has org.eclipse.jetty.server.internal.HttpConnection, both with static getCurrentConnection().
     */
    static final class Jetty {
        private static final Method CURRENT = find();

        static boolean available() {
            return CURRENT != null;
        }

        private static Method find() {
            for (String c : new String[]{"org.eclipse.jetty.server.HttpConnection", "org.eclipse.jetty.server.internal.HttpConnection"}) {
                try {
                    return Class.forName(c).getMethod("getCurrentConnection");
                } catch (ReflectiveOperationException | LinkageError e) {
                    // try the next Jetty generation
                }
            }
            return null;
        }

        static InetSocketAddress[] localAndRemote() throws Exception {
            if (CURRENT == null) return null;
            Object conn = CURRENT.invoke(null);
            if (conn == null) return null;
            // methods taken from the public interfaces: implementation classes (e.g. TLS end points) may not be public
            Object ep = Class.forName("org.eclipse.jetty.io.Connection").getMethod("getEndPoint").invoke(conn);
            Class<?> epi = Class.forName("org.eclipse.jetty.io.EndPoint");
            Object local = address(epi, ep, "getLocalSocketAddress", "getLocalAddress");
            Object remote = address(epi, ep, "getRemoteSocketAddress", "getRemoteAddress");
            if (!(local instanceof InetSocketAddress) || !(remote instanceof InetSocketAddress)) return null;
            return new InetSocketAddress[]{(InetSocketAddress) local, (InetSocketAddress) remote};
        }

        private static Object address(Class<?> iface, Object endPoint, String... methods) throws Exception {
            for (String m : methods) {
                try {
                    return iface.getMethod(m).invoke(endPoint);
                } catch (NoSuchMethodException e) {
                    // the other Jetty generation's name
                }
            }
            return null;
        }
    }
}
