/*
 * Copyright (c) 2021 Björn Raupach
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

package org.myoauth;

import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.*;

/**
 * A collection of secure and cryptographic building blocks.
 */
public class Cryptoblock {
  
    private static final Cryptoblock INSTANCE = new Cryptoblock();

    /**
     * The length of the code verifier
     */
    public static final int CODE_VERIFIER_LENGTH = 128;

    private static char[] codeVerifierSymbols =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
            .toCharArray();

    /* Instances are thread-safe */
    private final Base64.Encoder encoder;
    private final Base64.Decoder decoder;
    private final SecureRandom secureRandom;
    private final S256 s256;

    private Cryptoblock() {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        this.encoder = Base64.getUrlEncoder().withoutPadding();
        this.decoder = Base64.getUrlDecoder();
        this.s256 = new S256();
    }

    /**
     * Compares two strings for equality. This method prevents
     * timing attacks. If both strings are of equal length the
     * comparison takes the same amount to complete no matter if
     * the strings are actually equal.
     *
     * @param s1 the first string to compare, can be null
     * @param s2 the second string to compare with, can be null
     * @return true if both strings are equal
     */
    public boolean areEqual(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return false;
        }

        byte[] a = s1.getBytes(UTF_8);
        byte[] b = s2.getBytes(UTF_8);

        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    public boolean areNotEqual(String s1, String s2) {
        return !areEqual(s1, s2);
    }

    /**
     * Creates a random string
     * <p>
     * The string is in hexadecimal, all lower case.
     * This method uses a cryptographically strong random number generator.
     *
     * @param numBits  the number of random bits
     * @return random string
     */
    public String random(int numBits) {
        if (numBits < 0) {
            throw new IllegalArgumentException("bits");
        }
        BigInteger randomNumber = new BigInteger(numBits, secureRandom);
        return randomNumber.toString(16);
    }

    public byte[] base64UrlDecode(String src) {
        return decoder.decode(src);
    }

    public String base64UrlEncode(byte[] src) {
        return encoder.encodeToString(src);
    }

    /**
     * Returns a cryptographically random string using the characters [A-Z], [a-z], [0-9] and the
     * punctuation characters [-._~].
     * <p>
     * The string is 128 characters long
     *
     * @return a code verifier string, never null
     */
    public String codeVerifier() {
        StringBuilder sb = new StringBuilder(CODE_VERIFIER_LENGTH);
        for (int i = 0; i < CODE_VERIFIER_LENGTH; i++) {
            int rnd = secureRandom.nextInt(codeVerifierSymbols.length);
            sb.append(codeVerifierSymbols[rnd]);
        }
        return sb.toString();
    }

    /**
     * Creates a code challenge from a code verifier.
     * @param codeVerifier
     * @return a code challenge string
     */
    public String codeChallenge(String codeVerifier) {
        byte[] octets = codeVerifier.getBytes(US_ASCII);
        byte[] hash = s256.hash(octets);
        return base64UrlEncode(hash);
    }

    class S256 {

        public byte[] hash(byte[] bytes) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(bytes);
                return md.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

    }

    /**
     * Returns an instance of this class.
     *
     * @return instance of class
     */
    public static Cryptoblock getInstance() {
        return INSTANCE;
    }

}
