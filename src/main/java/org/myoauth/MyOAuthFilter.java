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


import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.myoauth.cognito.*;

import java.io.IOException;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A servlet filter for confidential clients.
 * <p>
 * This filter is capable of handling the OAuth 2.0 backchannel in the Authorization Code Flow. It can exchange
 * an authorization code for an access token.
 * <p>
 * The MyOAuthFilter stores the access and identity token in the http session. The refresh token is stored
 * as a secure cookie.
 */
public class MyOAuthFilter implements Filter {

    private final Logger logger = Logger.getLogger(getClass().getPackageName());

    /* These keys are used in the servlet context */
    public static final String OAUTH_SERVICE_ATTRIBUTE_NAME  = "org.myoauth.provider";

    /* These keys are used in the http session */
    public static final String ACCESS_TOKEN_ATTRIBUTE_NAME            = "org.myoauth.access_token";
    public static final String ACCESS_TOKEN_EXPIRATION_ATTRIBUTE_NAME = "org.myoauth.access_token.expiration";
    public static final String IDENTITY_TOKEN_ATTRIBUTE_NAME          = "org.myoauth.identity_token";
    public static final String STATE_ATTRIBUTE_NAME                   = "org.myoauth.state";
    public static final String CODE_VERIFIER_ATTRIBUTE_NAME           = "org.myoauth.code_verifier";

    /* Configuration of the refresh token cookie */
    public static final String REFRESH_TOKEN_COOKIE_NAME        = "__Host-myoauth_refresh_token";
    // TODO Do not hardcode
    public static final int    REFRESH_TOKEN_COOKIE_EXPIRATION  = (int) Duration.ofDays(30).getSeconds();

    private CognitoConfig config;
    private CognitoService cognito;
    private Cryptoblock cryptoblock;
    private List<JWK> webKeySet;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("Using MyOAuthFilter version 0.9 with Amazon Cognito.");
        config = CognitoConfig.from(filterConfig);
        logger.info(MessageFormat.format("userPoolId={0}", config.getUserPoolId()));
        logger.info(MessageFormat.format("region={0}", config.getRegion()));
        logger.info(MessageFormat.format("clientId={0}", config.getClientId()));
        cognito = new CognitoService(config);
        cryptoblock = Cryptoblock.getInstance();
        try {
            this.webKeySet = cognito.jwks();
            for (JWK jwk : webKeySet) {
                logger.info("kid=" + jwk.getKid());
            }
        } catch (IOException e) {
            throw new ServletException("unable to load web keys", e);
        }
        filterConfig.getServletContext().setAttribute(OAUTH_SERVICE_ATTRIBUTE_NAME, cognito);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain);
    }

    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (isRedirectionURI(request)) {
            tryAuthorizationCodeExchange(request, response, filterChain);
        } else if (hasAccessToken(request) && !isAccessTokenExpired(request)) {
            passthrough(request, response, filterChain);
        } else if (hasRefreshToken(request)) {
            tryRefreshTokenGrant(request, response, filterChain);
        } else {
            passthrough(request, response, filterChain);
        }
    }

    /**
     * Returns true if the http request matches the redirection URI. This should mean that the
     * request is from a redirect of the authorization server.
     *
     * @param request the http request
     * @return true, if this request is redirected from an authorization server
     */
    public boolean isRedirectionURI(HttpServletRequest request) {
        String requestURI = request.getRequestURL().toString();
        String redirectionURI = config.getRedirectURI();
        return cryptoblock.areEqual(requestURI, redirectionURI);
    }

    /**
     * Part of the Authorization Code Grant Flow
     * This method is called if the incoming request matches the redirection uri. This methods first checks if
     * the states match.
     * the request parameters, namely state and code, from the request and tries to exchange an authorization code for an
     * access token with the backchannel.
     *
     * @param request the http request
     * @param response the http response
     * @param filterChain the filter chain
     * @throws IOException if an I/O related error has occurred during the processing
     * @throws ServletException if an exception has occurred that interferes with anything else
     */
    public void tryAuthorizationCodeExchange(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String state = request.getParameter("state");
        String code = request.getParameter("code");

        HttpSession httpSession = request.getSession();
        String savedState = (String) httpSession.getAttribute(STATE_ATTRIBUTE_NAME);
        String verifier = (String) httpSession.getAttribute(CODE_VERIFIER_ATTRIBUTE_NAME);

        if (cryptoblock.areNotEqual(state, savedState)) {
            logger.log(Level.WARNING, "sessionid={0}, outcome={1}, message=\"{2}\"", new Object[] { httpSession.getId(), "denied", "state mismatch" });
            deny(request, response, filterChain);
            return;
        }

        Either<CognitoError, UserPoolToken> either = cognito.authorizationCodeExchange(code, verifier);
        if (either.isLeft()) {
            logger.log(Level.WARNING, "sessionid={0}, outcome={1}, message=\"{2}\"", new Object[] { httpSession.getId(), "denied", "authorization code exchange failed: " + either.getLeft() });
            deny(request, response, filterChain);
            return;
        }

        UserPoolToken userPoolToken = either.getRight();
        Instant exp = Instant.now().plusSeconds(userPoolToken.getExpiresIn());
        logger.log(Level.INFO, "sessionid={0}, outcome={1} message=\"{2}\", expires_in={3}", new Object[] { httpSession.getId(), "success", "authorization code exchange succeeded. new access token issued.", userPoolToken.getExpiresIn() });

        if (!cognito.verify(userPoolToken.getAccessToken(), webKeySet)) {
            logger.log(Level.WARNING, "sessionid={0}, outcome={1} message=\"{2}\"", new Object[] { httpSession.getId(), "denied", "authorization code exchange succeeded, but failed to verify the access token." });
            deny(request, response, filterChain);
            return;
        }

        if (!cognito.verify(userPoolToken.getIdToken(), webKeySet)) {
            logger.log(Level.WARNING, "sessionid={0}, outcome={1} message=\"{2}\"", new Object[] { httpSession.getId(), "denied", "authorization code exchange succeeded, but failed to verify the identity token." });
            deny(request, response, filterChain);
            return;
        }

        /* Save user pool token in the http session */
        httpSession.setAttribute(ACCESS_TOKEN_ATTRIBUTE_NAME, userPoolToken.getAccessToken());
        httpSession.setAttribute(ACCESS_TOKEN_EXPIRATION_ATTRIBUTE_NAME, exp);
        httpSession.setAttribute(IDENTITY_TOKEN_ATTRIBUTE_NAME, userPoolToken.getIdToken());

        /* Save the refresh token in a cookie */
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, userPoolToken.getRefreshToken());
        cookie.setPath("/");
        cookie.setMaxAge(REFRESH_TOKEN_COOKIE_EXPIRATION);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);

        /* cleaning up */
        httpSession.removeAttribute(STATE_ATTRIBUTE_NAME);
        httpSession.removeAttribute(CODE_VERIFIER_ATTRIBUTE_NAME);

        /* redirect the user somewhere */
        response.sendRedirect("/index.xhtml");
    }

    public boolean hasAccessToken(HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        return httpSession.getAttribute(ACCESS_TOKEN_ATTRIBUTE_NAME) != null;
    }

    public boolean isAccessTokenExpired(HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        Instant exp = (Instant) httpSession.getAttribute(ACCESS_TOKEN_EXPIRATION_ATTRIBUTE_NAME);
        return !(Instant.now().isBefore(exp));
    }

    public boolean hasRefreshToken(HttpServletRequest request) {
        Cookie refreshTokenCookie = null;
        // {@link HttpServletRequest#getCookies}
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(REFRESH_TOKEN_COOKIE_NAME)) {
                    refreshTokenCookie = cookie;
                }
            }
        }
        // TODO instead of looping, maybe store the information if a refresh token is present
        // in the http session? Implications?

        return refreshTokenCookie != null;
    }

    /**
     * Initiates refresh token flow
     */
    public void tryRefreshTokenGrant(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException  {
        HttpSession httpSession  = request.getSession();

        Cookie refreshTokenCookie = null;
        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(REFRESH_TOKEN_COOKIE_NAME)) {
                refreshTokenCookie = cookie;
            }
        }

        Either<CognitoError, UserPoolToken> either = cognito.refreshToken(refreshTokenCookie.getValue());
        if (either.isLeft()) {
            logger.log(Level.WARNING, "sessionid={0}, outcome={1} message=\"{2}\"", new Object[] { httpSession.getId(), "denied", "refresh token grant flow failed: " + either.getLeft() });
            deny(request, response, filterChain);
            return;
        }

        UserPoolToken userPoolToken = either.getRight();
        Instant exp = Instant.now().plusSeconds(userPoolToken.getExpiresIn());

        logger.log(Level.INFO, "sessionid={0}, outcome={1}, message={2}, expires_in={3}", new Object[] { httpSession.getId(), "success", "refresh token grant flow succeeded. new access token issued.", userPoolToken.getExpiresIn() });

        if (!cognito.verify(userPoolToken.getAccessToken(), webKeySet)) {
            logger.log(Level.WARNING, "sessionid={0}, outcome={1} message=\"{2}\"", new Object[] { httpSession.getId(), "denied", "authorization code exchange succeeded, but failed to verify the access token." });
            deny(request, response, filterChain);
            return;
        }

        /* Save user pool token in the http session */
        httpSession.setAttribute(ACCESS_TOKEN_ATTRIBUTE_NAME, userPoolToken.getAccessToken());
        httpSession.setAttribute(ACCESS_TOKEN_EXPIRATION_ATTRIBUTE_NAME, exp);
        httpSession.setAttribute(IDENTITY_TOKEN_ATTRIBUTE_NAME, userPoolToken.getIdToken());

        passthrough(request, response, filterChain);
    }

    public void passthrough(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException  {
        filterChain.doFilter(request, response);
    }

    public void deny(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException  {
        response.sendError(401);
    }

    @Override
    public void destroy() { }

}
