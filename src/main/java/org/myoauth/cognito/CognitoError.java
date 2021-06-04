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

import static java.util.Objects.requireNonNull;

/**
 * Instances represent negatives responses from Amazon Cognito.
 *
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html">Cognito TOKEN Endpoint</a>
 */
public enum CognitoError {
    INVALID_REQUEST,
    INVALID_CLIENT,
    INVALID_GRANT,
    UNAUTHORIZED_CLIENT,
    UNSUPPORTED_GRANT_TYPE;

    /**
     * Returns a matching {@code CognitoError}
     *
     * @param error a string representation of a negative response
     * @return  cognito error
     */
    public static CognitoError from(String error) {
        switch (requireNonNull(error)) {
            case "invalid_request"        : return INVALID_REQUEST;
            case "invalid_client"         : return INVALID_CLIENT;
            case "invalid_grant"          : return INVALID_GRANT;
            case "unauthorized_client"    : return UNAUTHORIZED_CLIENT;
            case "unsupported_grant_type" : return UNSUPPORTED_GRANT_TYPE;
            default:
                throw new IllegalArgumentException(error + "does not match enum representation");
        }
    }

}
