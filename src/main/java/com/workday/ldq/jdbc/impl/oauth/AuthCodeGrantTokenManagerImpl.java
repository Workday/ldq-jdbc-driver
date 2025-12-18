/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Token manager implementation for OAuth 2.0 Authorization Code Grant flow.
 * <p>
 * This implementation handles the interactive browser-based authorization flow:
 * <ol>
 * <li>Opens system browser to Workday authorization endpoint</li>
 * <li>Starts local HTTP server to receive authorization code callback</li>
 * <li>Exchanges authorization code for access token (and optional refresh token)</li>
 * </ol>
 * <p>
 * Required configuration properties:
 * <ul>
 * <li>{@code wd.authorization.endpoint} - Workday authorization URL</li>
 * <li>{@code wd.token.endpoint} - Workday token URL</li>
 * <li>{@code wd.client.id} - OAuth 2.0 client ID</li>
 * <li>{@code wd.client.secret} - OAuth 2.0 client secret</li>
 * <li>{@code wd.authorization.redirect.url} - Redirect URI</li>
 * </ul>
 *
 */
final class AuthCodeGrantTokenManagerImpl
    implements TokenManager {

    private final OAuth2CodeGrantClient authorizeClient;
    private final OAuth2Config config;

    public AuthCodeGrantTokenManagerImpl(@Nonnull final OAuth2Config config, final OkHttpClient httpClient) {
        this(new OAuth2CodeGrantClient(httpClient), config);
    }

    @VisibleForTesting
    AuthCodeGrantTokenManagerImpl(@Nonnull final OAuth2CodeGrantClient authorizeClient,
                                  @Nonnull final OAuth2Config config) {
        this.authorizeClient = authorizeClient;
        this.config = config;
    }

    @Override
    public TokenResponse acquireToken() {
        final String authorizationCode = this.authorizeClient.getAuthorizationCode(
            this.config.getAuthorizationEndpoint(),
            this.config.getClientId(),
            this.config.getAuthorizationRedirectUrl()
        );
        // Use authorization code to get an access token and refresh token
        return this.authorizeClient.exchangeCodeForTokenResponse(
            authorizationCode,
            this.config.getTokenEndpoint(),
            this.config.getClientId(),
            this.config.getClientSecret(),
            this.config.getAuthorizationRedirectUrl()
        );
    }

    @Override
    public TokenResponse getTokenUsingRefreshToken(@Nonnull final String refreshToken) {
        return this.authorizeClient.getTokenUsingRefreshToken(
            refreshToken,
            this.config.getTokenEndpoint(),
            this.config.getClientId(),
            this.config.getClientSecret()
        );
    }

    @Override
    public void close() {
    }
}
