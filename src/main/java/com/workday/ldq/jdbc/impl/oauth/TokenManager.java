/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * TokenManager provides an abstraction to acquire and refresh access tokens given an OAuth2Config.
 * <p>
 * Use the static factory method {@link #create(OAuth2Config, OkHttpClient)} to get an instance
 * appropriate for the authentication model specified in the configuration.
 * </p>
 *
 */
public interface TokenManager
    extends AutoCloseable {

    /**
     * Acquires a new token response (access token and optional refresh token).
     *
     * @return TokenResponse containing an access token and optional refresh token
     * @throws LDQJdbcDriverRuntimeException if token acquisition fails
     */
    TokenResponse acquireToken();

    /**
     * Refreshes using a refresh token to get a new access token.
     * <p>
     * Note: Not all authentication models support refresh tokens. JWT Bearer grant,
     * for example, will throw an exception as it does not use refresh tokens.
     *
     * @param refreshToken The refresh token to use for getting a new access token
     * @return TokenResponse with a new access token and possibly a new refresh token
     * @throws LDQJdbcDriverRuntimeException if refresh fails or is not supported
     */
    TokenResponse getTokenUsingRefreshToken(@Nonnull String refreshToken);

    /**
     * Acquires an access token using the provided OAuth2 configuration.
     * <p>
     * This method is maintained for backward compatibility. New code should use
     * {@link #acquireToken()} which returns the full TokenResponse.
     *
     * @return Bearer access token
     * @throws LDQJdbcDriverRuntimeException if token acquisition fails
     * @deprecated Use {@link #acquireToken()} instead
     */
    @Deprecated
    default BearerAccessToken acquireAccessToken() {
        return acquireToken().getAccessToken();
    }

    @Override
    void close();

    /**
     * Creates a TokenManager instance based on the authentication model in the config.
     * <p>
     * Supported authentication models:
     * <ul>
     * <li>{@link AuthModel#JWT_BEARER} - Returns {@link JwtGrantTokenManagerImpl}</li>
     * <li>{@link AuthModel#AUTHORIZATION_CODE} - Returns {@link AuthCodeGrantTokenManagerImpl}</li>
     * <li>{@link AuthModel#AUTHORIZATION_CODE_PKCE} - Returns {@link AuthCodeGrantPKCETokenManagerImpl}</li>
     * <li>{@link AuthModel#ACCESS_TOKEN} - Returns {@link AccessTokenTokenManagerImpl}</li>
     * </ul>
     *
     * @param config     OAuth2 configuration containing the authentication model
     * @param httpClient HTTP client to use for token requests
     * @return TokenManager implementation appropriate for the authentication model
     * @throws LDQJdbcDriverRuntimeException if the authentication model is not supported
     */
    static TokenManager create(@Nonnull final OAuth2Config config,
                               @Nonnull final OkHttpClient httpClient) {
        return TokenManagerFactory.create(config, httpClient);
    }
}
