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

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;

import java.net.URI;

import static org.mockito.Mockito.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

class CognitoServiceTest {

    @Test
    void authorization() throws ServletException {
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("userPoolId")).thenReturn("123");
        when(filterConfig.getInitParameter("clientId")).thenReturn("34098ugf");
        when(filterConfig.getInitParameter("clientSecret")).thenReturn("xxx");
        when(filterConfig.getInitParameter("prefixDomainName")).thenReturn("hello");
        when(filterConfig.getInitParameter("region")).thenReturn("eu-central-1");
        when(filterConfig.getInitParameter("redirectURI")).thenReturn("https://foo.example.com/oauth/callback");

        CognitoConfig cognitoConfig = CognitoConfig.from(filterConfig);
        CognitoService cognitoService = new CognitoService(cognitoConfig);

        String state = "abcdefgh";

        URI actual = cognitoService.authorizationRequest(state, "axbc");
        URI expected = URI.create("https://hello.auth.eu-central-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=34098ugf&redirect_uri=https%3A%2F%2Ffoo.example.com%2Foauth%2Fcallback&state=abcdefgh&code_challenge=axbc&code_challenge_method=S256");

        assertThat(actual, is(expected));
    }

}