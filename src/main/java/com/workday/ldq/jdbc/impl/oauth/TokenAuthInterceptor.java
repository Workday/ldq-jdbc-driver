/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_KEY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.AUTHORIZATION_HEADER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.BEARER_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_GATEWAY_PATH_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_EARLY_REFRESH_SKEW_MIN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.EARLY_REFRESH_SKEW_MIN_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ERROR_PARSING_JWT_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TENANT_CLAIM_IS_MISSING;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TENANT_CLAIM_NAME;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.X_TENANT_HEADER;
import static io.trino.jdbc.$internal.client.ProtocolHeaders.TRINO_HEADERS;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.jakarta.annotation.Nullable;
import io.trino.jdbc.$internal.okhttp3.HttpUrl;
import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;

import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * OkHttp interceptor that attaches and refreshes OAuth2 Bearer tokens.
 * Caches a per-connection token response and refreshes it when near expiry; retries once on 401.
 * <p>
 * This interceptor supports refresh tokens when available. If a refresh token is present,
 * it will be used to get a new access token. Otherwise, a full authentication flow is initiated.
 *
 */
public final class TokenAuthInterceptor
    implements Interceptor {

    private static final Logger LOG = Logger.getLogger(TokenAuthInterceptor.class.getName());

    private final TokenManager tokenManager;
    private final Duration earlyRefreshSkew;

    private volatile TokenResponse cachedTokenResponse;

    /**
     * Creates a new TokenAuthInterceptor.
     *
     * @param tokenManager TokenManager for acquiring and refreshing tokens
     */
    public TokenAuthInterceptor(@Nonnull final TokenManager tokenManager) {
        this.tokenManager = tokenManager;
        this.earlyRefreshSkew = Duration.ofMinutes(Long.getLong(EARLY_REFRESH_SKEW_MIN_PROP,
            DEFAULT_EARLY_REFRESH_SKEW_MIN));
    }

    @Override
    public Response intercept(@Nonnull final Chain chain)
        throws IOException {
        final Request originalRequest = chain.request();
        final Request modifiedRequest = getModifiedRequest(originalRequest);

        final String tokenToUse = getExistingOrRefreshToken();
        Response response = proceedWithToken(chain, tokenToUse, modifiedRequest);

        // Retry once on 401, to allow failures due to network delays
        if (response.code() == HTTP_UNAUTHORIZED) {
            try {
                response.close();
            }
            catch (final Exception ignored) {
                // ignored
            }
            // Force-refresh and retry. If this response also 401s, we don't retry again.
            final String refreshedToken = refreshAndCacheToken();
            response = proceedWithToken(chain, refreshedToken, modifiedRequest);
        }
        return response;
    }

    @VisibleForTesting
    static Request getModifiedRequest(final Request originalRequest) {
        final boolean hasLdqGatewayPathPrefix =
            originalRequest.url().encodedPath().startsWith(LDQ_GATEWAY_PATH_PREFIX);

        if (hasLdqGatewayPathPrefix) {
            return originalRequest;
        }
        else {
            final String prefixedPath = LDQ_GATEWAY_PATH_PREFIX + originalRequest.url().encodedPath();
            final HttpUrl modifiedUrl = originalRequest.url()
                .newBuilder()
                .encodedPath(prefixedPath)
                .build();
            return originalRequest
                .newBuilder()
                .url(modifiedUrl)
                .build();
        }
    }

    private Response proceedWithToken(@Nonnull final Chain chain,
                                      @Nonnull final String tokenToUse,
                                      @Nonnull final Request request)
        throws IOException {
        final String tenantClaim = extractTenantFromToken(tokenToUse);
        final String tokenCredential = String.format("%s=%s", ACCESS_TOKEN_KEY, tokenToUse);
        final Request requestWithAuth = request.newBuilder()
            .header(AUTHORIZATION_HEADER, BEARER_PREFIX + tokenToUse)
            .header(X_TENANT_HEADER, tenantClaim)
            .header(TRINO_HEADERS.requestExtraCredential(), tokenCredential)
            .build();
        return chain.proceed(requestWithAuth);
    }

    @VisibleForTesting
    static @Nonnull String extractTenantFromToken(final String tokenToUse) {
        try {
            final JWTClaimsSet claimsSet = SignedJWT.parse(tokenToUse).getJWTClaimsSet();
            final String tenantClaim = claimsSet.getStringClaim(TENANT_CLAIM_NAME);
            if (tenantClaim == null || tenantClaim.isBlank()) {
                // this should not happen as a tenant is a valid claim in the Workday Auth provided access token
                throw new LDQJdbcDriverRuntimeException(TENANT_CLAIM_IS_MISSING);
            }
            return tenantClaim;
        }
        catch (final ParseException e) {
            // A valid token should not throw this exception
            throw new LDQJdbcDriverRuntimeException(ERROR_PARSING_JWT_ACCESS_TOKEN);
        }
    }

    private String getExistingOrRefreshToken() {
        final TokenResponse cached = this.cachedTokenResponse;
        if (cached != null && isAccessTokenValid(cached.getAccessToken())) {
            return cached.getAccessToken().getToken();
        }
        return refreshAndCacheToken();
    }

    private String refreshAndCacheToken() {
        synchronized (this) {
            // Double-check after acquiring the lock
            if (this.cachedTokenResponse != null &&
                isAccessTokenValid(this.cachedTokenResponse.getAccessToken())) {
                return this.cachedTokenResponse.getAccessToken().getToken();
            }

            // Try to use a refresh token first if available
            if (this.cachedTokenResponse != null && this.cachedTokenResponse.hasRefreshToken()) {
                try {
                    this.cachedTokenResponse = this.tokenManager.getTokenUsingRefreshToken(
                        this.cachedTokenResponse.getRefreshToken()
                    );
                    return this.cachedTokenResponse.getAccessToken().getToken();
                }
                catch (final Exception e) {
                    // If a refresh token fails, fall through to full authentication
                    // This handles cases like:
                    // - Refresh token expired
                    // - Refresh token revoked
                    LOG.log(Level.WARNING,
                        "Refresh token request failed, falling back to full authentication: " + e.getMessage(), e);
                }
            }

            // Fallback: Acquire a new token using the authentication flow
            this.cachedTokenResponse = this.tokenManager.acquireToken();
            return this.cachedTokenResponse.getAccessToken().getToken();
        }
    }

    private boolean isAccessTokenValid(@Nullable final BearerAccessToken token) {
        if (token == null) {
            return false;
        }
        final Date exp = token.getExpiryTime();
        return exp != null && !isNearExpiry(exp);
    }

    private boolean isNearExpiry(final Date expiry) {
        return expiry != null && expiry.toInstant()
            .minusSeconds(this.earlyRefreshSkew.toSeconds())
            .isBefore(Instant.now());
    }
}
