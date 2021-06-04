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

package org.myoauth.cognito;

import jakarta.json.JsonObject;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static java.util.Objects.*;

/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
 * This class represents JWK issued from Amazon Cognito. Fields represent represent properties of an RSA public key.
 * <p>
 * All fields are not null.
 * <p>
 * Instances of this class are immutable and thread-safe.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html">Verifying a JSON Web Token</a>
 */
public final class JWK {

    private final String kid;
    /* We assume this is always 'RS256' */
    private final String alg;
    private final String kty;
    private final String e;
    private final String n;
    /* We assume this is always 'sig' */
    private final String use;

    public JWK(String kid, String alg, String kty, String e, String n, String use) {
        this.kid = requireNonNull(kid, "kid");
        this.alg = requireNonNull(alg, "alg");
        this.kty = requireNonNull(kty, "kty");
        this.e   = requireNonNull(e, "e");
        this.n   = requireNonNull(n, "n");
        this.use = requireNonNull(use, "use");
    }

    /**
     * The {@code kid} is a hint that indicates which key was used to secure the JSON web signature (JWS) of the token.
     * This field must be present in a JWK.
     *
     * @return Key ID
     */
    public String getKid() {
        return kid;
    }

    /**
     * The {@code alg} header parameter represents the cryptographic algorithm used to secure the ID token.
     * User pools use an RS256 cryptographic algorithm, which is an RSA signature with SHA-256.
     *
     * @return Algorithm
     */
    public String getAlg() {
        return alg;
    }

    /**
     * The {@code kty} parameter identifies the cryptographic algorithm family used with the key,
     * such as "RSA" in this example.
     *
     * @return Key type
     */
    public String getKty() {
        return kty;
    }

    /**
     * The {@code e} parameter contains the exponent value for the RSA public key. It is represented as a
     * Base64urlUInt-encoded value.
     *
     * @return RSA exponent
     */
    public String getE() {
        return e;
    }

    /**
     * The {@code n} parameter contains the modulus value for the RSA public key. It is represented as a
     * Base64urlUInt-encoded value.
     *
     * @return RSA modulus
     */
    public String getN() {
        return n;
    }

    /**
     * The {@code use} parameter describes the intended use of the public key. For this example,
     * the use value {@code sig} represents signature.
     *
     * @return Use
     */
    public String getUse() {
        return use;
    }

    /**
     * Returns a RSA public key from the fields {@code e} and {@code n}.
     *
     * @return public key
     */
    public PublicKey getPublicKey() {
        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            BigInteger _e = new BigInteger(1, decoder.decode(e));
            BigInteger _n = new BigInteger(1, decoder.decode(n));
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(_n, _e);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return publicKey;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Returns an instance from a a {@code JsonObject}.
     *
     * @param jsonObject json object
     * @return JWK
     */
    public static JWK from(JsonObject jsonObject) {
        return new JWK(
                jsonObject.getString("kid"),
                jsonObject.getString("alg"),
                jsonObject.getString("kty"),
                jsonObject.getString("e"),
                jsonObject.getString("n"),
                jsonObject.getString("use")
        );
    }

}
