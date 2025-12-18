/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Date;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Unit tests for AccessTokenTokenManagerImpl.
 *
 */
class AccessTokenTokenManagerImplTest {

    private static final String SECRET = "test-secret-key-for-jwt-signing-32-bytes-long"; // gitleaks:allow
    private static final String TEST_SUBJECT = "datalake-extract";
    private static final String TEST_TENANT = "super";
    // JWT "exp" claims are whole seconds since the epoch, so truncate to keep the round-tripped
    // expiry equal to this value.
    private static final Date TEST_EXPIRY = new Date((System.currentTimeMillis() / 1000 + 60) * 1000);

    private AccessTokenTokenManagerImpl tokenManager;

    private AccessTokenTokenManagerImpl managerFor(final String accessToken) {
        return new AccessTokenTokenManagerImpl(accessToken);
    }

    @Test
    @DisplayName("acquireToken - wraps the supplied token as-is")
    void testAcquireToken()
        throws Exception {
        final String jwt = createJwt(TEST_SUBJECT, TEST_TENANT, TEST_EXPIRY);
        this.tokenManager = managerFor(jwt);

        final TokenResponse response = this.tokenManager.acquireToken();

        assertEquals(jwt, response.getAccessToken().getToken());
        assertEquals(TEST_EXPIRY, response.getAccessToken().getExpiryTime());
    }

    @Test
    @DisplayName("acquireToken - throws when the supplied token is not a valid JWT")
    void testAcquireTokenInvalidJwtThrows() {
        this.tokenManager = managerFor("not-a-jwt");

        assertThrows(LDQJdbcDriverRuntimeException.class, () -> this.tokenManager.acquireToken());
    }

    @Test
    @DisplayName("acquireToken - throws when the supplied token has no expiration claim")
    void testAcquireTokenMissingExpirationThrows()
        throws Exception {
        this.tokenManager = managerFor(createJwt(TEST_SUBJECT, TEST_TENANT, null));

        assertThrows(LDQJdbcDriverRuntimeException.class, () -> this.tokenManager.acquireToken());
    }

    @Test
    @DisplayName("getTokenUsingRefreshToken - throws, refresh is not supported")
    void testGetTokenUsingRefreshTokenThrows()
        throws Exception {
        this.tokenManager = managerFor(createJwt(TEST_SUBJECT, TEST_TENANT, TEST_EXPIRY));

        assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> this.tokenManager.getTokenUsingRefreshToken("some-refresh-token"));
    }

    private String createJwt(final String subject, final String tenant, final Date expiry)
        throws Exception {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).build();

        final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
            .subject(subject)
            .claim(JWTClaimNames.TENANT, tenant);
        if (expiry != null) {
            claimsSetBuilder.expirationTime(expiry);
        }
        final JWTClaimsSet claimsSet = claimsSetBuilder.build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new MACSigner(SECRET));
        return signedJWT.serialize();
    }
}
