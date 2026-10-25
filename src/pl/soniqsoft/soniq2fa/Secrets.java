// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP secrets encrypted in LDAP: AES-256-GCM with a key kept outside LDAP in KEY_FILE (base64 of 32 bytes,
 * root:zextras 0640), the account id as associated data, so a sealed secret cannot be moved to another account.
 * Stored form: "enc1:" + base64(12-byte IV || ciphertext with tag). Secrets without the prefix are read as plain text
 * (enrolled before encryption, or no key on the server); new secrets are sealed whenever the key is there.
 * A sealed secret without the key cannot be read, and the account cannot sign in: back the key up with the server.
 * No Carbonio classes, so the self-test runs without a mailbox.
 */
final class Secrets {
    static final Path KEY_FILE = Path.of("/opt/zextras/lib/ext/soniq2fa/totp.key");
    static final String PREFIX = "enc1:";
    private static final SecureRandom RND = new SecureRandom();
    private static volatile byte[] cachedKey;
    private static volatile long cachedStamp = -1;

    private Secrets() {
    }

    /** The key from KEY_FILE, or null when there is none; re-read when the file changes. */
    static byte[] key() throws IOException {
        if (!Files.exists(KEY_FILE)) return null;
        long stamp = Files.getLastModifiedTime(KEY_FILE).toMillis();
        if (stamp != cachedStamp) {
            cachedKey = parseKey(Files.readString(KEY_FILE, StandardCharsets.US_ASCII));
            cachedStamp = stamp;
        }
        return cachedKey;
    }

    static byte[] parseKey(String text) throws IOException {
        byte[] k;
        try {
            k = Base64.getDecoder().decode(text.trim());
        } catch (IllegalArgumentException e) {
            throw new IOException("key file is not base64");
        }
        if (k.length != 32) throw new IOException("key must be 32 bytes, is " + k.length);
        return k;
    }

    static String seal(byte[] key, String accountId, String plain) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        RND.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        c.updateAAD(accountId.getBytes(StandardCharsets.UTF_8));
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] out = Arrays.copyOf(iv, iv.length + ct.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return PREFIX + Base64.getEncoder().encodeToString(out);
    }

    static String open(byte[] key, String accountId, String stored) throws GeneralSecurityException {
        byte[] in = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, in, 0, 12));
        c.updateAAD(accountId.getBytes(StandardCharsets.UTF_8));
        return new String(c.doFinal(in, 12, in.length - 12), StandardCharsets.UTF_8);
    }

    /** The value to store for a new secret: sealed when the server has a key, plain otherwise. */
    static String forStorage(String accountId, String plain) throws IOException, GeneralSecurityException {
        byte[] k = key();
        return k == null ? plain : seal(k, accountId, plain);
    }

    /** The Base32 secret from the stored value; throws when it is sealed and cannot be opened (fail closed). */
    static String read(String accountId, String stored) throws IOException, GeneralSecurityException {
        if (stored == null || !stored.startsWith(PREFIX)) return stored;
        byte[] k = key();
        if (k == null) throw new IOException("TOTP secret is encrypted but " + KEY_FILE + " is missing");
        return open(k, accountId, stored);
    }

    static String newKey() {
        byte[] k = new byte[32];
        RND.nextBytes(k);
        return Base64.getEncoder().encodeToString(k);
    }

    static void selftest() throws Exception {
        byte[] k = parseKey(newKey());
        String sealed = seal(k, "acct-1", "JBSWY3DPEHPK3PXP");
        check(sealed.startsWith(PREFIX) && !sealed.contains("JBSWY3DPEHPK3PXP"), "secret sealed");
        check("JBSWY3DPEHPK3PXP".equals(open(k, "acct-1", sealed)), "secret opened");
        check(!sealed.equals(seal(k, "acct-1", "JBSWY3DPEHPK3PXP")), "fresh IV every time");
        try {
            open(k, "acct-2", sealed);
            check(false, "sealed secret bound to its account");
        } catch (GeneralSecurityException expected) {
            // another account id as associated data: the tag does not match
        }
        try {
            open(parseKey(newKey()), "acct-1", sealed);
            check(false, "another key cannot open it");
        } catch (GeneralSecurityException expected) {
            // wrong key
        }
        check("PLAIN".equals(read("acct-1", "PLAIN")) && read("acct-1", null) == null, "plain secrets read as before");
        try {
            parseKey("c2hvcnQ=");
            check(false, "short key refused");
        } catch (IOException expected) {
            // 5 bytes
        }
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("selftest failed: " + name);
    }
}
