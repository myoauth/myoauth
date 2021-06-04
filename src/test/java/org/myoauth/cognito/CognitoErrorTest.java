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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.myoauth.cognito.CognitoError.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class CognitoErrorTest {

    @Test
    void invalidRequest() {
        assertThat(from("invalid_request"), is(INVALID_REQUEST));
    }

    @Test
    void invalidClient() {
        assertThat(from("invalid_client"), is(INVALID_CLIENT));
    }

    @Test
    void invalidGrant() {
        assertThat(from("invalid_grant"), is(INVALID_GRANT));
    }

    @Test
    void unauthorizedClient() {
        assertThat(from("unauthorized_client"), is(UNAUTHORIZED_CLIENT));
    }

    @Test
    void unsupportedGrantType() {
        assertThat(from("unsupported_grant_type"), is(UNSUPPORTED_GRANT_TYPE));
    }

    @Test
    void unknownError() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> from("unknown"));
    }

    @Test
    void nil() {
        Assertions.assertThrows(NullPointerException.class, () -> from(null));
    }

}