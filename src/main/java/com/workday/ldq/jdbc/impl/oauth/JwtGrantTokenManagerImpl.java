/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * TokenManager implementation for OAuth 2.0 JWT Bearer Grant Type (RFC 7523).
 * <p>
 * This implementation does NOT support refresh tokens because JWT Bearer grant
 * creates a new JWT assertion for each token request rather than using a refresh token.
 *
 */
final class JwtGrantTokenManagerImpl
    implements TokenManager {

    private final OAuth2JwtTokenClient tokenClient;
    private final OAuth2Config config;

    public JwtGrantTokenManagerImpl(@Nonnull final OAuth2Config config, final OkHttpClient httpClient) {
        this.config = config;
        this.tokenClient = new OAuth2JwtTokenClient(httpClient);
    }

    @Override
    public TokenResponse acquireToken() {
        final String jwtAssertion = OAuth2TokenUtil.createJWTAssertion(this.config);
        return this.tokenClient.requestToken(jwtAssertion, this.config.getTokenEndpoint());
    }

    @Override
    public TokenResponse getTokenUsingRefreshToken(@Nonnull final String refreshToken) {
        // JWT Bearer grant does not use refresh tokens.
        // Instead, we create a new JWT assertion and get a new access token.
        throw new LDQJdbcDriverRuntimeException(
            "JWT Bearer grant does not support refresh tokens. " +
                "Use acquireToken() to obtain a new access token."
        );
    }

    @Override
    public void close() {
    }
}
