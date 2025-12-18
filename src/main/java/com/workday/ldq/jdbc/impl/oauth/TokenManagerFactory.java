/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Factory for creating {@link TokenManager} instances based on the authentication model.
 * <p>
 * This factory provides a centralized way to instantiate the appropriate TokenManager
 * implementation based on the {@link AuthModel} specified in the {@link OAuth2Config}.
 * <p>
 *
 */
final class TokenManagerFactory {

    private TokenManagerFactory() {
        // Utility class - prevent instantiation
    }

    /**
     * Creates a TokenManager instance based on the authentication model in the config.
     * Using a single instance of HTTPClient for all token requests. This optimizes connection reuse.
     * No State is stored in the HTTPClient and is safe to share. If this assumption changes in the future,
     * we can create a new instance for each TokenManager.
     *
     * @param config     OAuth2 configuration containing the authentication model
     * @param httpClient HTTP client to use for token requests
     * @return TokenManager implementation appropriate for the authentication model
     * @throws LDQJdbcDriverRuntimeException if the authentication model is not supported
     */
    public static TokenManager create(@Nonnull final OAuth2Config config,
                                      @Nonnull final OkHttpClient httpClient) {
        final AuthModel authModel = config.getAuthModel();

        switch (authModel) {
            case JWT_BEARER:
                return new JwtGrantTokenManagerImpl(config, httpClient);
            case AUTHORIZATION_CODE:
                return new AuthCodeGrantTokenManagerImpl(config, httpClient);
            case AUTHORIZATION_CODE_PKCE:
                return new AuthCodeGrantPKCETokenManagerImpl(config, httpClient);
            case ACCESS_TOKEN:
                return new AccessTokenTokenManagerImpl(config.getAccessToken());
            default:
                throw new LDQJdbcDriverRuntimeException(
                    "Unknown authentication model: " + authModel);
        }
    }
}
