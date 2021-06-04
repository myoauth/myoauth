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

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

/**
 * A configuration object used by {@code CognitoService}.
 * <p>
 * Instances of this class are immutable and thread-safe.
 */
public class CognitoConfig {

    private final String userPoolId;
    private final String clientId;
    private final String clientSecret;
    private final String prefixDomainName;
    private final String region;
    private final String redirectURI;

    private CognitoConfig(String userPoolId, String clientId, String clientSecret, String prefixDomainName, String region, String redirectURI) {
        this.userPoolId       = requireNonNull(userPoolId, "userPoolId") ;
        this.clientId         = requireNonNull(clientId, "clientId");
        this.clientSecret     = requireNonNull(clientSecret, "clientSecret");
        this.prefixDomainName = requireNonNull(prefixDomainName, "prefixDomainName");
        this.region           = requireNonNull(region, "region");
        this.redirectURI      = requireNonNull(redirectURI, "redirectURI");
    }

    public String getUserPoolId() {
        return userPoolId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getPrefixDomainName() {
        return prefixDomainName;
    }

    public String getRegion() {
        return region;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    /**
     * Returns an instance of {@code CognitoConfig} from a {@code FilterConfig}, or
     * throws an exception if required init parameters are missing.
     *
     * @param filterConfig a filter configuration object, not null
     * @return an instance of {@code CognitoConfig}, not null
     * @throws jakarta.servlet.ServletException if required parameters are missing.
     */
    public static CognitoConfig from(FilterConfig filterConfig) throws ServletException {
        requireNonNull(filterConfig, "filterConfig");

        /* Accumulator of missing parameters */
        Set<String> missing = new HashSet<>();

        String userPoolId       = from(filterConfig, "userPoolId", missing);
        String clientId         = from(filterConfig, "clientId", missing);
        String clientSecret     = from(filterConfig, "clientSecret", missing);
        String region           = from(filterConfig, "region", missing);
        String prefixDomainName = from(filterConfig, "prefixDomainName", missing);
        String redirectURI      = from(filterConfig, "redirectURI", missing);

        if (missing.isEmpty()) {
            return new CognitoConfig(userPoolId, clientId, clientSecret, prefixDomainName, region, redirectURI);
        } else {
            String missingParameters = missing.stream().collect(Collectors.joining(", ", "[", "]"));
            throw new ServletException("Missing required init parameters: " + missingParameters  + "\nCheck your OAuthFilter configuration in web.xml");
        }
    }

    private static String from(FilterConfig filterConfig, String name, Set<String> missing) {
        String value = filterConfig.getInitParameter(name);
        if (value == null) {
            missing.add(name);
        }
        return value;
    }

}
