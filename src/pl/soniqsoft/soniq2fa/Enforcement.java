// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Provisioning;
import java.util.Map;

/**
 * "2FA required" enforced by the server. An account that must use 2FA but has not set it up signs in with the password
 * alone only during a grace period, counted from its first such sign-in (recorded as "required-since:<ms>" in the
 * channel attribute, which users cannot write) and set in the gateway file as required.graceDays (default 7, 0 = none).
 * After that the password alone is refused everywhere and the user sets 2FA up on the enrolment page of
 * Soniq2faRecovery. Without this the setup window over webmail, shown by the browser, was the only enforcement.
 */
final class Enforcement {
    static final String PREFIX = "required-since:";
    static final long DAY_MS = 24 * 3_600_000L;

    private Enforcement() {
    }

    static String marker(Account a) {
        for (String v : a.getMultiAttr(Channels.A_CHANNELS)) if (v.startsWith(PREFIX)) return v;
        return null;
    }

    static long graceMs() {
        try {
            int days = Integer.parseInt(Channels.file().getProperty("required.graceDays", "7").trim());
            return Math.max(0, days) * DAY_MS;
        } catch (NumberFormatException e) {
            return 7 * DAY_MS;
        }
    }

    static boolean overdue(long since, long now, long grace) {
        return now - since >= grace;
    }

    /**
     * After the right password of an account without 2FA: true when the grace period is over and the login must be
     * refused. Starts the period on the first such sign-in; clears the record when 2FA is no longer required.
     */
    static boolean overdue(Account a, long now) {
        String m = marker(a);
        try {
            boolean must = Soniq2faPage.required(a) && Soniq2faPage.unavailable(a) == null;
            Provisioning prov = Provisioning.getInstance();
            if (!must) {
                if (m != null) prov.modifyAttrs(a, Map.of("-" + Channels.A_CHANNELS, m), false);
                return false;
            }
            long grace = graceMs();
            if (m == null) {
                if (grace > 0) {
                    prov.modifyAttrs(a, Map.of("+" + Channels.A_CHANNELS, PREFIX + now), false);
                    ZimbraLog.account.info("soniq2fa: %s must set 2FA up, grace period of %d days starts", a.getName(), grace / DAY_MS);
                }
                return grace == 0;
            }
            return overdue(Long.parseLong(m.substring(PREFIX.length())), now, grace);
        } catch (Exception e) {
            // a broken record or LDAP error: do not lock the user out because of it
            ZimbraLog.account.warn("soniq2fa: cannot check the 2FA grace period of %s", a.getName(), e);
            return false;
        }
    }
}
