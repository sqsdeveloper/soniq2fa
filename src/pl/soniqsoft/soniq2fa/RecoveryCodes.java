// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Codes sent by mail or SMS, kept in memory: password recovery and address verification (8 digits), phone verification
 * and login codes (6 digits); stored as SHA-256 with a limited number of tries. Also the sending limit per key and
 * reading one text of an i18n bundle. No Carbonio classes,
 * so the self-test runs without a mailbox.
 */
final class RecoveryCodes {
    static final int MAX_TRIES = 5, MAX_SENT_PER_HOUR = 5;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, Pending> CODES = new ConcurrentHashMap<>();
    private static final Map<String, long[]> SENT = new ConcurrentHashMap<>();

    private RecoveryCodes() {
    }

    static final class Pending {
        final byte[] hash;
        final long expires;
        final String extra;
        int tries;

        Pending(byte[] hash, long expires, String extra) {
            this.hash = hash;
            this.expires = expires;
            this.extra = extra;
        }
    }

    static String issue(String key, long ttl, String extra) {
        return issue(key, ttl, extra, 8);
    }

    /** digits: 8 for mailed recovery codes, 6 for login codes, which are typed after the password like a TOTP code. */
    static String issue(String key, long ttl, String extra, int digits) {
        String code = String.format("%0" + digits + "d", RANDOM.nextInt((int) Math.pow(10, digits)));
        CODES.put(key, new Pending(sha256(code), System.currentTimeMillis() + ttl, extra));
        return code;
    }

    /** The pending entry when the code matches; every check counts as a try, consume removes the entry. */
    static Pending check(String key, String code, boolean consume) {
        Pending p = key == null ? null : CODES.get(key);
        if (p == null) return null;
        if (System.currentTimeMillis() > p.expires) {
            CODES.remove(key, p);
            return null;
        }
        String c = code == null ? "" : code.replaceAll("[\\s-]", "");
        boolean ok;
        synchronized (p) {
            if (p.tries >= MAX_TRIES) {
                CODES.remove(key, p);
                return null;
            }
            ok = MessageDigest.isEqual(p.hash, sha256(c));
            if (!ok || !consume) p.tries++;
            // inside the lock: of two requests with the right code, only the one that removes the entry succeeds
            else if (!CODES.remove(key, p)) return null;
        }
        return ok ? p : null;
    }

    /** A code for the key exists and has not expired. */
    static boolean pending(String key) {
        Pending p = CODES.get(key);
        return p != null && System.currentTimeMillis() <= p.expires && p.tries < MAX_TRIES;
    }

    /** Voids a pending code (its channel was removed, 2FA turned off or reset). */
    static void drop(String key) {
        CODES.remove(key);
    }

    /**
     * At most MAX_SENT_PER_HOUR sends per key and hour, and one a minute. Keys: the account id (recovery and address
     * mails), "login:" + id (login codes), "phone:" + id (phone verification), so one kind cannot use up another.
     */
    static boolean mayMail(String id) {
        long now = System.currentTimeMillis();
        long[] s = SENT.computeIfAbsent(id, k -> new long[]{0, 0, 0});
        synchronized (s) {
            if (now - s[1] > 3_600_000) {
                s[1] = now;
                s[2] = 0;
            }
            if (now - s[0] < 60_000 || s[2] >= MAX_SENT_PER_HOUR) return false;
            s[0] = now;
            s[2]++;
            return true;
        }
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String mask(String address) {
        if (address == null || address.indexOf('@') < 1) return "";
        int at = address.indexOf('@');
        return address.charAt(0) + "***" + address.substring(at);
    }

    /**
     * The string value of a top-level key in an i18n bundle, unescaped (\\n, \\t, \\uXXXX, \\" and the like); null when
     * missing. A plain scan: a regular expression with an alternation inside a repeated group recurses once per character
     * in java.util.regex and overflowed the small stack of the mail thread right after a restart (StackOverflowError,
     * 2026-10-10 22:34 and 2026-10-12 21:20, before the JIT compiled the matcher).
     */
    static String value(String json, String key) {
        String k = "\"" + key + "\"";
        for (int i = json.indexOf(k); i >= 0; i = json.indexOf(k, i + 1)) {
            int j = skipSpace(json, i + k.length());
            if (j >= json.length() || json.charAt(j) != ':') continue;
            j = skipSpace(json, j + 1);
            if (j < json.length() && json.charAt(j) == '"') return unescape(json, j + 1);
        }
        return null;
    }

    private static int skipSpace(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }

    /** The JSON string starting at from (after the opening quote), up to the closing quote; null if unterminated. */
    private static String unescape(String s, int from) {
        StringBuilder b = new StringBuilder();
        for (int i = from; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') return b.toString();
            if (c != '\\' || i + 1 >= s.length()) {
                b.append(c);
                continue;
            }
            char e = s.charAt(++i);
            if (e == 'u' && i + 4 < s.length()) {
                b.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                i += 4;
            } else {
                b.append(e == 'n' ? '\n' : e == 't' ? '\t' : e == 'r' ? '\r' : e);
            }
        }
        return null;
    }

    static void selftest() {
        String c = issue("t:1", 60_000, "x@example.com");
        check(c.matches("[0-9]{8}"), "recovery code format");
        check(check("t:1", "00000000".equals(c) ? "11111111" : "00000000", false) == null, "recovery wrong code");
        check(check("t:1", c, false) != null && CODES.containsKey("t:1"), "recovery peek keeps the code");
        check("x@example.com".equals(check("t:1", c.substring(0, 4) + "-" + c.substring(4), true).extra), "recovery consume");
        check(check("t:1", c, true) == null, "recovery code single use");
        String d = issue("t:2", 60_000, null);
        for (int i = 0; i < MAX_TRIES; i++) check("t:2", "x", false);
        check(check("t:2", d, true) == null, "recovery tries limit");
        check(issue("t:3", -1, null) != null && check("t:3", "x", true) == null && !CODES.containsKey("t:3"), "recovery expiry");
        check(mayMail("m") && !mayMail("m"), "recovery mail once a minute");
        check(issue("t:4", 60_000, null, 6).matches("[0-9]{6}"), "login code format");
        check(pending("t:4"), "code pending");
        drop("t:4");
        check(!CODES.containsKey("t:4") && !pending("t:4"), "login code dropped");
        check("Kod: 12\n\"x\" ż".equals(value("{\"k\": \"Kod: {c}\\n\\\"x\\\" \\u017c\"}", "k").replace("{c}", "12")), "i18n value");
        check(value("{\"a\": \"x\"}", "k") == null && "y".equals(value("{\"kk\": \"x\", \"k\" : \"y\"}", "k")), "i18n value lookup");
        // a long text on a small stack: the earlier regular expression overflowed here
        String[] out = new String[1];
        Thread t = new Thread(null, () -> out[0] = value("{\"k\": \"" + "a\\\"".repeat(20_000) + "\"}", "k"), "selftest", 64 * 1024);
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        check(out[0] != null && out[0].length() == 40_000, "i18n value of a long text on a small stack");
        check("a***@example.com".equals(mask("anna@example.com")), "address mask");
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("selftest failed: " + name);
    }
}
