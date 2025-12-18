/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth.token;

import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Represents the complete response from an OAuth 2.0 token endpoint.
 * Contains both access token and optional refresh token.
 * <p>
 * This class maintains a clear separation between access tokens (short-lived authorization credentials)
 * and refresh tokens (long-lived renewal credentials) as per OAuth 2.0 specification.
 *
 */
public class TokenResponse {

    private final BearerAccessToken accessToken;
    private final String refreshToken;

    /**
     * Creates a new TokenResponse with the given access token and optional refresh token.
     *
     * @param accessToken  The bearer access token (required)
     * @param refreshToken The refresh token (optional, can be null)
     * @throws LDQJdbcDriverRuntimeException if accessToken is null
     */
    public TokenResponse(final BearerAccessToken accessToken,
                         final String refreshToken) {
        if (accessToken == null) {
            throw new LDQJdbcDriverRuntimeException("Access token cannot be null");
        }
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * Creates a TokenResponse with only an access token (no refresh token).
     *
     * @param accessToken The bearer access token
     */
    public TokenResponse(final BearerAccessToken accessToken) {
        this(accessToken, null);
    }

    /**
     * Returns the access token.
     *
     * @return the bearer access token
     */
    public BearerAccessToken getAccessToken() {
        return this.accessToken;
    }

    /**
     * Returns the refresh token if present.
     *
     * @return the refresh token, or null if not available
     */
    public String getRefreshToken() {
        return this.refreshToken;
    }


    /**
     * Checks if this response contains a refresh token.
     *
     * @return true if a refresh token is present and not empty, false otherwise
     */
    public boolean hasRefreshToken() {
        return IS_NOT_EMPTY.test(this.refreshToken);
    }

    @Override
    public String toString() {
        return String.format("TokenResponse{ accessToken=[PRESENT], refreshToken= %s }",
            hasRefreshToken() ? "[PRESENT]" : "null");
    }
}
