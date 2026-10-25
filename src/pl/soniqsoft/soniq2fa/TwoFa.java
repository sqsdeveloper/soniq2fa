// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP (RFC 6238), device passwords, backup codes, replay guard and rate limit. Plain Java (Base32 included), so it
 * runs both inside the mailbox and as a CLI.
 *
 * Stored forms:
 *   zimbraAppSpecificPassword (multi-valued):   label|sha256|saltB64|hashB64
 *   zimbraTwoFactorAuthScratchCodes (one value): sha256|saltB64|hashB64,sha256|...,...
 * Device passwords and backup codes are random (~99 and ~49 bits), so a single salted SHA-256 is enough and keeps
 * failed logins cheap. Entries written by earlier versions (pbkdf2-sha256|iter|salt|hash) are still accepted.
 */
public final class TwoFa {
    static final int STEP = 30, DIGITS = 6, WINDOW = 1;
    static final int BACKUP_CODES = 10, BACKUP_LEN = 10, MAX_DEVICES = 20;
    private static final SecureRandom RND = new SecureRandom();
    private static final String ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";

    private TwoFa() {}

    // ---- TOTP ----

    static String totp(byte[] key, long counter) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] h = mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(counter).array());
        int o = h[h.length - 1] & 0xf;
        int bin = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
        return String.format("%0" + DIGITS + "d", bin % 1_000_000);
    }

    static final long NO_MATCH = Long.MIN_VALUE;

    /** Time-step counter the code belongs to (within +/-WINDOW), or NO_MATCH. */
    static long matchTotp(String base32Secret, String code, long nowMillis) throws Exception {
        if (code == null || !code.matches("[0-9]{" + DIGITS + "}")) return NO_MATCH;
        byte[] key = base32Decode(base32Secret.trim());
        long t = nowMillis / 1000 / STEP, found = NO_MATCH;
        for (int i = -WINDOW; i <= WINDOW; i++)
            if (MessageDigest.isEqual(totp(key, t + i).getBytes(StandardCharsets.US_ASCII), code.getBytes(StandardCharsets.US_ASCII)))
                found = t + i;
        return found;
    }

    static boolean verifyTotp(String base32Secret, String code, long nowMillis) throws Exception {
        return matchTotp(base32Secret, code, nowMillis) != NO_MATCH;
    }

    /** Key URI for authenticator apps; the issuer (the name shown in the app) is the mail domain. */
    static String otpauthUri(String issuer, String account, String secret) {
        String i = java.net.URLEncoder.encode(issuer, StandardCharsets.UTF_8).replace("+", "%20");
        String a = java.net.URLEncoder.encode(account, StandardCharsets.UTF_8).replace("+", "%20");
        return "otpauth://totp/" + i + ":" + a + "?secret=" + secret + "&issuer=" + i + "&digits=" + DIGITS + "&period=" + STEP;
    }

    static String newSecret() {
        byte[] b = new byte[20];
        RND.nextBytes(b);
        return base32(b);
    }

    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /** RFC 4648 Base32 without padding, the form authenticator apps take. */
    static String base32(byte[] data) {
        StringBuilder b = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        for (byte d : data) {
            buffer = (buffer << 8) | (d & 0xff);
            bits += 8;
            while (bits >= 5) {
                b.append(B32.charAt((buffer >>> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) b.append(B32.charAt((buffer << (5 - bits)) & 31));
        return b.toString();
    }

    /** RFC 4648 Base32; case, spaces and padding are ignored, any other character is an error. */
    static byte[] base32Decode(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int buffer = 0, bits = 0;
        for (char c : s.toUpperCase(java.util.Locale.ROOT).toCharArray()) {
            if (c == '=' || c == ' ') continue;
            int v = B32.indexOf(c);
            if (v < 0) throw new IllegalArgumentException("not Base32: '" + c + "'");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    // ---- hashing of random secrets ----

    static String hashRandom(String value) throws Exception {
        byte[] salt = new byte[16];
        RND.nextBytes(salt);
        Base64.Encoder e = Base64.getEncoder();
        return "sha256|" + e.encodeToString(salt) + "|" + e.encodeToString(sha256(salt, value));
    }

    /** stored: "sha256|salt|hash" or the earlier "pbkdf2-sha256|iter|salt|hash". */
    static boolean verifyHashed(String stored, String value) throws Exception {
        String[] f = stored.split("\\|");
        Base64.Decoder d = Base64.getDecoder();
        if (f.length == 3 && "sha256".equals(f[0]))
            return MessageDigest.isEqual(sha256(d.decode(f[1]), value), d.decode(f[2]));
        if (f.length == 4 && "pbkdf2-sha256".equals(f[0]))
            return MessageDigest.isEqual(pbkdf2(value, d.decode(f[2]), Integer.parseInt(f[1])), d.decode(f[3]));
        return false;
    }

    private static byte[] sha256(byte[] salt, String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        return md.digest(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] pbkdf2(String pw, byte[] salt, int iter) throws Exception {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(pw.toCharArray(), salt, iter, 256)).getEncoded();
    }

    // ---- device passwords ----

    static String newAppPassword() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            if (i > 0 && i % 5 == 0) sb.append('-');
            sb.append(ALPHABET.charAt(RND.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    /** Typed with or without dashes, in any case. */
    static String normalize(String s) {
        return s == null ? "" : s.replace("-", "").replace(" ", "").trim().toLowerCase();
    }

    static String hashAppPassword(String label, String pw) throws Exception {
        if (label.contains("|")) throw new IllegalArgumentException("label must not contain |");
        return label + "|" + hashRandom(normalize(pw));
    }

    static String label(String entry) {
        int i = entry.indexOf('|');
        return i < 0 ? entry : entry.substring(0, i);
    }

    /** Returns the matching label, or null. */
    static String matchAppPassword(String[] entries, String pw) throws Exception {
        if (entries == null || pw == null || pw.isEmpty()) return null;
        for (String entry : entries) {
            int i = entry.indexOf('|');
            if (i < 0) continue;
            String stored = entry.substring(i + 1);
            // entries from earlier versions were hashed from the password exactly as shown, dashes included
            String candidate = stored.startsWith("pbkdf2-") ? pw : normalize(pw);
            if (verifyHashed(stored, candidate)) return entry.substring(0, i);
        }
        return null;
    }

    // ---- backup codes ----

    /** Plain codes, shown once, formatted "xxxxx-xxxxx". */
    static String[] newBackupCodes() {
        String[] out = new String[BACKUP_CODES];
        for (int n = 0; n < BACKUP_CODES; n++) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < BACKUP_LEN; i++) {
                if (i == BACKUP_LEN / 2) sb.append('-');
                sb.append(ALPHABET.charAt(RND.nextInt(ALPHABET.length())));
            }
            out[n] = sb.toString();
        }
        return out;
    }

    static String hashBackupCodes(String[] codes) throws Exception {
        StringBuilder b = new StringBuilder();
        for (String c : codes) b.append(b.length() == 0 ? "" : ",").append(hashRandom(normalize(c)));
        return b.toString();
    }

    static int countBackupCodes(String stored) {
        return stored == null || stored.isEmpty() ? 0 : stored.split(",").length;
    }

    /** Remaining stored value after using the code ("" when it was the last), or null when the code does not match. */
    static String useBackupCode(String stored, String code) throws Exception {
        String c = normalize(code);
        if (stored == null || stored.isEmpty() || c.length() != BACKUP_LEN) return null;
        String[] entries = stored.split(",");
        for (int i = 0; i < entries.length; i++) {
            if (!verifyHashed(entries[i], c)) continue;
            StringBuilder rest = new StringBuilder();
            for (int j = 0; j < entries.length; j++)
                if (j != i) rest.append(rest.length() == 0 ? "" : ",").append(entries[j]);
            return rest.toString();
        }
        return null;
    }

    // ---- replay guard and rate limit ----

    /**
     * Accepts a TOTP counter only if it is later than the last one accepted for the account, so a code
     * cannot be reused, nor can an older code from the window follow a newer one.
     */
    // ponytail: in-memory, one mailbox server; a restart forgets it, which reopens at most the current ~90 s window
    static final class Replay {
        private final ConcurrentHashMap<String, Long> last = new ConcurrentHashMap<>();

        boolean accept(String accountId, long counter) {
            boolean[] ok = {false};
            last.compute(accountId, (k, prev) -> {
                if (prev != null && counter <= prev) return prev;
                ok[0] = true;
                return counter;
            });
            return ok[0];
        }
    }

    /**
     * At most MAX second-factor attempts per account in a fixed WINDOW_MS window; a success clears the count.
     * The attempt is counted before the check, so parallel requests cannot exceed the limit.
     */
    // ponytail: in-memory, one mailbox server; a restart resets the counters
    static final class Throttle {
        static final int MAX = 5;
        static final long WINDOW_MS = 10 * 60_000;
        private final ConcurrentHashMap<String, long[]> tries = new ConcurrentHashMap<>();
        private final int max;
        private final long window;

        Throttle() {
            this(MAX, WINDOW_MS);
        }

        Throttle(int max, long window) {
            this.max = max;
            this.window = window;
        }

        /** false when the key already used up its attempts in the current window. */
        boolean tryAcquire(String id, long now) {
            // keys made of client addresses are unbounded: drop expired windows before the map grows large
            if (tries.size() > 10_000) tries.values().removeIf(f -> now - f[1] >= window);
            boolean[] ok = {false};
            tries.compute(id, (k, f) -> {
                if (f == null || now - f[1] >= window) f = new long[]{0, now};
                if (f[0] >= max) return f;
                ok[0] = true;
                return new long[]{f[0] + 1, f[1]};
            });
            return ok[0];
        }

        void reset(String id) {
            tries.remove(id);
        }
    }

    /** Shared by login and the self-service page, so a code used on one cannot be replayed on the other. */
    static final Replay REPLAY = new Replay();
    static final Throttle THROTTLE = new Throttle();
    /** At most 50 wrong second factors a day per account, on top of 5 per 10 minutes: 720 guesses a day are too many. */
    static final Throttle DAILY = new Throttle(50, 24 * 3_600_000L);
    /** Password checks of "send me a login code" (login page): separate, so strangers cannot block code checks. */
    static final Throttle SEND_THROTTLE = new Throttle();

    // ---- self-test ----

    static void selftest() throws Exception {
        // RFC 6238 appendix B, SHA1 seed "12345678901234567890", truncated to 6 digits
        byte[] seed = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        String b32 = base32(seed);
        // RFC 4648 section 10 test vectors (padding left out)
        String[][] v = {{"", ""}, {"f", "MY"}, {"fo", "MZXQ"}, {"foo", "MZXW6"}, {"foob", "MZXW6YQ"}, {"fooba", "MZXW6YTB"},
                {"foobar", "MZXW6YTBOI"}};
        for (String[] x : v) {
            check(base32(x[0].getBytes(StandardCharsets.US_ASCII)).equals(x[1]), "base32 encode " + x[0]);
            check(new String(base32Decode(x[1].toLowerCase() + "======"), StandardCharsets.US_ASCII).equals(x[0]), "base32 decode " + x[1]);
        }
        byte[] key20 = new byte[20];
        RND.nextBytes(key20);
        check(java.util.Arrays.equals(base32Decode(base32(key20)), key20) && base32(key20).length() == 32, "base32 round trip of a secret");
        try {
            base32Decode("ABC1");
            check(false, "base32 rejects 1");
        } catch (IllegalArgumentException expected) {
            // "1" is outside the alphabet
        }
        check(totp(seed, 59 / 30).equals("287082"), "rfc t=59");
        check(totp(seed, 1111111109L / 30).equals("081804"), "rfc t=1111111109");
        check(totp(seed, 1234567890L / 30).equals("005924"), "rfc t=1234567890");
        check(verifyTotp(b32, "005924", 1234567890_000L), "verify current");
        check(verifyTotp(b32, totp(seed, 1234567890L / 30 - 1), 1234567890_000L), "verify -1 step");
        check(!verifyTotp(b32, totp(seed, 1234567890L / 30 - 2), 1234567890_000L), "reject -2 steps");
        check(!verifyTotp(b32, "12345", 1234567890_000L) && !verifyTotp(b32, "٠٠٥٩٢٤", 1234567890_000L), "reject short / non-ASCII digits");
        check(matchTotp(b32, "005924", 1234567890_000L) == 1234567890L / 30, "counter of current code");
        check(otpauthUri("example.com", "a@example.com", "ABC").equals("otpauth://totp/example.com:a%40example.com?secret=ABC&issuer=example.com&digits=6&period=30"), "otpauth uri");

        Replay r = new Replay();
        check(r.accept("acct", 100) && !r.accept("acct", 100) && !r.accept("acct", 99) && r.accept("acct", 101), "replay order");
        check(r.accept("other", 100), "replay per account");

        String[] codes = newBackupCodes();
        String bstored = hashBackupCodes(codes);
        check(countBackupCodes(bstored) == BACKUP_CODES && codes[0].matches("[a-z2-9]{5}-[a-z2-9]{5}"), "backup format");
        String rest = useBackupCode(bstored, codes[3].toUpperCase().replace("-", ""));
        check(rest != null && countBackupCodes(rest) == BACKUP_CODES - 1, "backup use, case and dash insensitive");
        check(useBackupCode(rest, codes[3]) == null, "backup single use");
        check(useBackupCode(bstored, "aaaaa-aaaaa") == null && useBackupCode("", codes[0]) == null, "backup reject");
        String last = hashBackupCodes(new String[]{codes[0]});
        check("".equals(useBackupCode(last, codes[0])) && countBackupCodes("") == 0, "backup last code");
        // earlier format: pbkdf2-sha256|1000|salt|hash
        byte[] salt = new byte[16];
        String legacy = "pbkdf2-sha256|1000|" + Base64.getEncoder().encodeToString(salt) + "|"
                + Base64.getEncoder().encodeToString(pbkdf2("abcdefghjk", salt, 1000));
        check("".equals(useBackupCode(legacy, "abcde-fghjk")), "backup legacy pbkdf2");

        Throttle th = new Throttle();
        for (int i = 0; i < Throttle.MAX; i++) check(th.tryAcquire("a", 0), "throttle within limit");
        check(!th.tryAcquire("a", 1) && th.tryAcquire("b", 1), "throttle limit per account");
        check(th.tryAcquire("a", Throttle.WINDOW_MS), "throttle new window");
        th.reset("a");
        check(th.tryAcquire("a", Throttle.WINDOW_MS + 1), "throttle reset");
        Throttle day = new Throttle(2, 1000);
        check(day.tryAcquire("x", 0) && day.tryAcquire("x", 1) && !day.tryAcquire("x", 2) && day.tryAcquire("x", 1000), "throttle own limits");
        Throttle many = new Throttle(1, 10);
        for (int i = 0; i < 10_002; i++) many.tryAcquire("k" + i, 0);
        many.tryAcquire("late", 100);
        check(many.tries.size() < 10, "throttle drops expired windows of a large map");

        String pw = newAppPassword();
        String[] stored = {hashAppPassword("thunderbird", pw), hashAppPassword("iphone", newAppPassword())};
        check("thunderbird".equals(matchAppPassword(stored, pw)), "app password match");
        check("thunderbird".equals(matchAppPassword(stored, pw.replace("-", "").toUpperCase())), "app password without dashes");
        check(matchAppPassword(stored, pw + "x") == null, "app password reject");
        check(matchAppPassword(new String[0], pw) == null, "app password none");
        String legacyApp = "old|pbkdf2-sha256|1000|" + Base64.getEncoder().encodeToString(salt) + "|"
                + Base64.getEncoder().encodeToString(pbkdf2("abcde-fghjk", salt, 1000));
        check("old".equals(matchAppPassword(new String[]{legacyApp}, "abcde-fghjk")), "app password legacy pbkdf2");
        check("thunderbird".equals(label(stored[0])), "label");
        RecoveryCodes.selftest();
        Secrets.selftest();
        Channels.selftest();
        System.out.println("selftest OK");
    }

    private static void check(boolean c, String what) {
        if (!c) throw new AssertionError(what);
    }

    /** CLI: selftest | secret <account> | code <secret> | apppass <label> | newkey | seal <key file> <account id> <secret> */
    public static void main(String[] a) throws Exception {
        switch (a.length > 0 ? a[0] : "") {
            case "selftest" -> selftest();
            case "secret" -> {
                String s = newSecret();
                System.out.println(s);
                System.out.println(otpauthUri(a[1].substring(a[1].indexOf('@') + 1), a[1], s));
            }
            case "code" -> System.out.println(totp(base32Decode(a[1]), System.currentTimeMillis() / 1000 / STEP));
            case "apppass" -> {
                String pw = newAppPassword();
                System.out.println(pw);
                System.out.println(hashAppPassword(a[1], pw));
            }
            case "newkey" -> System.out.println(Secrets.newKey());
            case "seal" -> {
                // "-": the secret from standard input, so it does not show up in the process list
                String stored = ("-".equals(a[3]) ? new String(System.in.readAllBytes(), StandardCharsets.US_ASCII) : a[3]).trim();
                System.out.println(stored.startsWith(Secrets.PREFIX) ? stored : Secrets.seal(
                        Secrets.parseKey(java.nio.file.Files.readString(java.nio.file.Path.of(a[1]))), a[2], stored));
            }
            default -> System.err.println("usage: selftest | secret <account> | code <secret> | apppass <label> | newkey | seal <key file> <account id> <secret>");
        }
    }
}
