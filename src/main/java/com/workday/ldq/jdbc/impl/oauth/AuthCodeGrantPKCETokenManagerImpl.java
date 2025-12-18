/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Token manager implementation for OAuth 2.0 Authorization Code Grant with PKCE (RFC 7636).
 * <p>
 * Extends the standard auth code flow with Proof Key for Code Exchange, enabling public
 * clients (no client secret) to authenticate securely.
 *
 */
final class AuthCodeGrantPKCETokenManagerImpl
    implements TokenManager {

    private final OAuth2CodeGrantClient authorizeClient;
    private final OAuth2Config config;

    public AuthCodeGrantPKCETokenManagerImpl(@Nonnull final OAuth2Config config,
                                             @Nonnull final OkHttpClient httpClient) {
        this(new OAuth2CodeGrantClient(httpClient), config);
    }

    @VisibleForTesting
    AuthCodeGrantPKCETokenManagerImpl(final OAuth2CodeGrantClient authorizeClient, final OAuth2Config config) {
        this.authorizeClient = authorizeClient;
        this.config = config;
    }

    /**
     * Acquires a token via the Authorization Code with PKCE flow (RFC 7636).
     * Generates a fresh verifier/challenge pair on every call.
     *
     * @return TokenResponse containing an access token and optional refresh token
     */
    @Override
    public TokenResponse acquireToken() {
        final String codeVerifier = OAuth2TokenUtil.generateCodeVerifier();
        final String codeChallenge = OAuth2TokenUtil.generateCodeChallenge(codeVerifier);
        final String authorizationCode = this.authorizeClient.getAuthorizationCodeWithPkce(
            this.config.getAuthorizationEndpoint(),
            this.config.getClientId(),
            this.config.getAuthorizationRedirectUrl(),
            codeChallenge
        );
        return this.authorizeClient.exchangeCodeForTokenResponseWithVerifier(
            authorizationCode,
            this.config.getTokenEndpoint(),
            this.config.getClientId(),
            this.config.getAuthorizationRedirectUrl(),
            codeVerifier
        );
    }

    /**
     * Refreshes an access token using a refresh token without a client secret.
     *
     * @param refreshToken The refresh token from a previous authorization
     * @return TokenResponse containing a new access token and possibly a new refresh token
     */
    @Override
    public TokenResponse getTokenUsingRefreshToken(@Nonnull final String refreshToken) {
        return this.authorizeClient.getTokenUsingRefreshTokenPublicClient(
            refreshToken,
            this.config.getTokenEndpoint(),
            this.config.getClientId()
        );
    }

    @Override
    public void close() {
    }
}
