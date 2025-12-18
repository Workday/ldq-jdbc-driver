/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;

import java.text.ParseException;
import java.util.Date;

import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * TokenManager implementation for the {@link AuthModel#ACCESS_TOKEN} authentication model.
 * <p>
 * Wraps a caller-supplied access token (e.g. a Workday system identity token).
 *
 */
final class AccessTokenTokenManagerImpl
    implements TokenManager {

    // BearerAccessToken.Builder requires a non-empty clientId, but nothing reads it for this
    // auth model; the caller's token is used exactly as supplied.
    private static final String UNUSED_CLIENT_ID = "n/a";

    private final String accessToken;

    public AccessTokenTokenManagerImpl(@Nonnull final String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public TokenResponse acquireToken() {
        try {
            final Date expiryTime = SignedJWT.parse(this.accessToken).getJWTClaimsSet().getExpirationTime();
            if (expiryTime == null) {
                throw new LDQJdbcDriverRuntimeException(
                    "Supplied access token is missing an expiration (exp) claim");
            }
            final BearerAccessToken bearerAccessToken = BearerAccessToken.builder()
                .token(this.accessToken)
                .expiryTime(expiryTime)
                .clientId(UNUSED_CLIENT_ID)
                .build();
            return new TokenResponse(bearerAccessToken);
        }
        catch (final ParseException e) {
            throw new LDQJdbcDriverRuntimeException("Failed to parse supplied access token as a JWT", e);
        }
    }

    @Override
    public TokenResponse getTokenUsingRefreshToken(@Nonnull final String refreshToken) {
        throw new LDQJdbcDriverRuntimeException(
            "Access token authentication does not support refresh tokens. Supply a new access token and reconnect.");
    }

    @Override
    public void close() {
    }
}
