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

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.myoauth.Cryptoblock;
import org.myoauth.Either;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.text.MessageFormat;
import java.util.*;
import java.util.logging.Logger;

import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;

public class CognitoService {

    private final Logger logger = Logger.getLogger(getClass().getPackageName());

    private final CognitoConfig config;
    private final Cryptoblock cryptoblock = Cryptoblock.getInstance();

    /* AUTHORIZATION Endpoint */
    private final URI authorization;

    /* TOKEN Endpoint */
    private final URI token;

    /* Base 64 encoded client_id and client_secret */
    private final String authorizationHeaderValue;

    /* Instances are thread-safe */
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /**
     * Creates a new CognitoService
     *
     * @param config
     */
    public CognitoService(CognitoConfig config) {
        this.config = config;

        var uri = new StringBuilder()
                .append("https://")
                .append(config.getPrefixDomainName())
                .append(".auth.")
                .append(config.getRegion())
                .append(".amazoncognito.com")
                .toString();
        this.authorization = URI.create(uri + "/oauth2/authorize");
        this.token = URI.create(uri + "/oauth2/token");


        var credentials = Base64.getEncoder()
                .encodeToString((config.getClientId() + ":" + config.getClientSecret())
                        .getBytes(US_ASCII));
        this.authorizationHeaderValue = "Basic " + credentials;
    }


    /**
     * Returns the #{@code URI} of the Amazon Cognito Authorization Endpoint.
     *
     * @return an instance of {@code URI}, not null
     */
    public URI authorizationRequest(String state, String challenge) {
        var queryString = new StringJoiner("&", "?", "")
                .add(requestParameter("response_type", "code"))
                .add(requestParameter("client_id", config.getClientId()))
                .add(requestParameter("redirect_uri", config.getRedirectURI()))
                .add(requestParameter("state", state))
                .add(requestParameter("code_challenge", challenge))
                .add(requestParameter("code_challenge_method", "S256"))
                .toString();

        return URI.create(authorization.toString() + queryString);
    }

    /**
     * Authorization Code Exchange
     * Uses backchannel to aquire access token from code grant.
     * Returns either a Cognito User Pool Token or an error.
     *
     * @throws IOException if an I/O related error has occurred during the processing
     */
    public Either<CognitoError, UserPoolToken> authorizationCodeExchange(String code, String verifier) throws IOException {
        requireNonNull(code, "code");
        requireNonNull(code, "verifier");

        var parameters = new StringJoiner("&")
                .add(requestParameter("grant_type", "authorization_code"))
                .add(requestParameter("client_id", config.getClientId()))
                .add(requestParameter("code", code))
                .add(requestParameter("code_verifier", verifier))
                .add(requestParameter("redirect_uri", config.getRedirectURI()))
                .toString();

        return contactTokenEndpoint(parameters);

    }

    /**
     * Loads the JSON Web Key Set (JWKS) from Amazon Cognito for the specified user pool.
     * A JWKS is a JSON object that represents a set of JWKs.
     *
     * @return a list of public keys
     * @see <a href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.txt">JSON Web Signature (JWS)</a>
     */
    public List<JWK> jwks() throws IOException {
        List<JWK> keys = new ArrayList<>();

        var uri = URI.create(new StringBuilder()
                .append("https://cognito-idp.")
                .append(config.getRegion())
                .append(".amazonaws.com/")
                .append(config.getUserPoolId())
                .append("/.well-known/jwks.json")
                .toString());

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(uri)
                .build();

        HttpResponse<InputStream> httpResponse = null;
        try {
            httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("an interrupt happened during http");
        }

        InputStream inputStream = httpResponse.body();
        JsonReader jsonReader = Json.createReader(inputStream);
        JsonObject jsonObject = jsonReader.readObject();
        JsonArray jsonArray = jsonObject.getJsonArray("keys");
        for (int i = 0; i < jsonArray.size(); i++) {
            jsonObject = jsonArray.getJsonObject(i);
            JWK jwk = JWK.from(jsonObject);
            keys.add(jwk);
        }

        if (inputStream != null) {
            inputStream.close();
        }

        return keys;
    }

    /**
     * Verifies an Amazon Cognito JSON Web Token (JWT) with RSASSA-PKCS1-v1_5 SHA-256
     *
     * @param jwt
     * @return
     * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html">Verifying a JSON Web Token</a>
     */
    public boolean verify(String jwt, List<JWK> jwks) {
        requireNonNull(jwt, "jwt");
        requireNonNull(jwt, "jwks");

        boolean verified = false;

        // 1. Decode the ID token.
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            logger.warning(() -> "access token does not appear to be a JWT");
            return false;
        }

        String header = parts[0];
        String payload = parts[1];
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] signature = decoder.decode(parts[2]);

        // 2. Compare the local key ID (kid) to the public kid.
        String headerJson = new String(cryptoblock.base64UrlDecode(header));
        JsonReader jsonReader = Json.createReader(new StringReader(headerJson));
        JsonObject jsonObject = jsonReader.readObject();
        String kid = jsonObject.getString("kid");

        Optional<JWK> optional = jwks.stream().filter(jwk -> jwk.getKid().equals(kid)).findFirst();
        if (optional.isEmpty()) {
            logger.warning(() -> MessageFormat.format("Missing public key kid={0} in JSON Web Key Set (JWKS)", kid));
            return false;
        }

        JWK webKey = optional.get();

        // 3. Verify signature
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(webKey.getPublicKey());
            sig.update((header + "." + payload).getBytes(US_ASCII));
            verified = sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        if (!verified) {
            logger.warning(() -> MessageFormat.format("Signature mismatch. JWT invalid", kid));
        }

        return verified;
    }

    /**
     * Uses backchannel to aquire new access token from code grant. Requoires a previous user pool token.
     */
    public Either<CognitoError, UserPoolToken> refreshToken(String refreshToken) throws IOException {
        requireNonNull(refreshToken, "refreshToken");
        var parameters = new StringJoiner("&")
                .add(requestParameter("grant_type", "refresh_token"))
                .add(requestParameter("client_id", config.getClientId()))
                .add(requestParameter("refresh_token", refreshToken))
                .toString();

        return contactTokenEndpoint(parameters);
    }

    String requestParameter(String name, String value) {
        return new StringBuilder()
                .append(name)
                .append('=')
                .append(URLEncoder.encode(value, StandardCharsets.UTF_8))
                .toString();
    }

    Either<CognitoError, UserPoolToken> contactTokenEndpoint(String parameters) throws IOException {
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(token)
                .headers("Authorization", authorizationHeaderValue)
                .headers("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(parameters))
                .build();

        HttpResponse<InputStream> httpResponse = null;
        try {
            httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("an interrupt happened during http");
        }

        int statusCode = httpResponse.statusCode();
        JsonReader jsonReader = Json.createReader(httpResponse.body());
        JsonObject object = jsonReader.readObject();

        if (statusCode == SC_OK) {
            UserPoolToken token = UserPoolToken.from(object);
            return Either.ofRight(token);
        } else if (statusCode == SC_BAD_REQUEST) {
            String error = object.getString("error");
            CognitoError cognitoError = CognitoError.valueOf(error.toUpperCase());
            return Either.ofLeft(cognitoError);
        } else {
            throw new IOException(MessageFormat.format("unable to proceed with statusCode={0}", statusCode));
        }
    }


}
