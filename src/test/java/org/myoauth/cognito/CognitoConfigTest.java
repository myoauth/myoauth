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

import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CognitoConfigTest {

    @Test
    void from_successful() throws ServletException {
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("userPoolId")).thenReturn("1234567890");
        when(filterConfig.getInitParameter("clientId")).thenReturn("1234567890");
        when(filterConfig.getInitParameter("clientSecret")).thenReturn("xxx");
        when(filterConfig.getInitParameter("prefixDomainName")).thenReturn("ohmyauth");
        when(filterConfig.getInitParameter("region")).thenReturn("eu-central-1");
        when(filterConfig.getInitParameter("redirectURI")).thenReturn("https://foo.example.com/oauth/callback");
        CognitoConfig cognitoConfig = CognitoConfig.from(filterConfig);
        assertThat(cognitoConfig, is(notNullValue()));
    }

    @Test
    void from_missingParameter() {
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("userPoolId")).thenReturn("1234567890");
        when(filterConfig.getInitParameter("clientId")).thenReturn("1234567890");
        when(filterConfig.getInitParameter("clientSecret")).thenReturn("xxx");
        when(filterConfig.getInitParameter("prefixDomainName")).thenReturn("ohmyauth");
        // when(filterConfig.getInitParameter("region")).thenReturn("eu-central-1");
        when(filterConfig.getInitParameter("redirectURI")).thenReturn("https://foo.example.com/oauth/callback");
        assertThrows(ServletException.class, () -> CognitoConfig.from(filterConfig));
    }
}