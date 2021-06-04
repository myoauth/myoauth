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

import static java.util.Objects.requireNonNull;

/**
 * The {@code UserPoolToken} class represents user pool tokens handed out by Amazon Cognito.
 * <p>
 * After an successful authentication Amazon Cognito returns a JSON object with three JWT tokens:
 * <ul>
 *     <li>access token</li>
 *     <li>refresh token</li>
 *     <li>id token</li>
 * </ul>
 *
 * <p>
 * Instances are immutable and thread-safe.
 *
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html">Using Tokens with User Pools</a>
 */
public final class UserPoolToken {

    private final String access_token;
    private final String refresh_token;
    private final String id_token;
    private final String token_type;
    private final int expires_in;

    private UserPoolToken(String access_token, String refresh_token, String id_token, String token_type, int expires_in) {
        this.access_token  = requireNonNull(access_token, "access_token");
        /* Is null in the refresh token grant flow */
        this.refresh_token = refresh_token;
        this.id_token      = requireNonNull(id_token, "id_token");
        this.token_type    = requireNonNull(token_type, "token_type");
        this.expires_in    = requireNonNull(expires_in, "expires_in");
    }

    /**
     * Returns the JWT representation of the access token as a string.
     *
     * @return access token
     */
    public String getAccessToken() {
        return access_token;
    }

    /**
     * Returns the JWT representation of the refresh token.
     *
     * @return refresh token, can be null
     */
    public String getRefreshToken() {
        return refresh_token;
    }

    /**
     * Returns the JWT representation of the id token.
     *
     * @return id token
     */
    public String getIdToken() {
        return id_token;
    }

    /**
     * Returns the token type.
     *
     * @return type of token
     */
    public String getTokenType() {
        return token_type;
    }

    /**
     * Returns the expiration of the access token in seconds.
     *
     * @return expiry in seconds
     */
    public int getExpiresIn() {
        return expires_in;
    }

    /**
     * Creates a {@code UserPoolToken} from a JSON object.
     * <p>
     * This method does not verify the JSON object. It is assumed
     * the JSON object holds all required key-value pairs.
     *
     * @param jsonObject a JSON object
     * @return a user pool token
     */
    public static UserPoolToken from(JsonObject jsonObject) {
        return new UserPoolToken(
                jsonObject.getString("access_token"),
                jsonObject.getString("refresh_token", null),
                jsonObject.getString("id_token"),
                jsonObject.getString("token_type"),
                jsonObject.getInt("expires_in")
        );
    }

}
