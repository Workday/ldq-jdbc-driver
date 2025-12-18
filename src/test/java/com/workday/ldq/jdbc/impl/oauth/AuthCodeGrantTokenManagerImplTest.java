/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;
import com.workday.ldq.jdbc.impl.property.DriverProperty;

/**
 * Unit tests for AuthCodeGrantTokenManagerImpl.
 * Tests token acquisition and refresh token functionality.
 *
 */
@ExtendWith(MockitoExtension.class)
class AuthCodeGrantTokenManagerImplTest {

    private static final String TEST_AUTH_ENDPOINT = "https://example.com/authorize";
    private static final String TEST_TOKEN_ENDPOINT = "https://example.com/token";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String TEST_REDIRECT_URI = "http://localhost:8888/callback";
    private static final String TEST_AUTH_CODE = "test-auth-code";
    private static final String TEST_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_REFRESH_TOKEN = "test-refresh-token";
    private static final String TEST_NEW_ACCESS_TOKEN = "test-new-access-token";
    private static final String TEST_NEW_REFRESH_TOKEN = "test-new-refresh-token";

    @Mock
    private OAuth2CodeGrantClient mockAuthorizeClient;

    private AuthCodeGrantTokenManagerImpl tokenManager;
    private OAuth2Config config;

    @BeforeEach
    void setUp() {
        // Create a test configuration
        final Properties props = new Properties();
        props.setProperty(DriverProperty.WD_AUTHORIZATION_ENDPOINT.getKey(), TEST_AUTH_ENDPOINT);
        props.setProperty(DriverProperty.WD_TOKEN_ENDPOINT.getKey(), TEST_TOKEN_ENDPOINT);
        props.setProperty(DriverProperty.WD_CLIENT_ID.getKey(), TEST_CLIENT_ID);
        props.setProperty(DriverProperty.WD_CLIENT_SECRET.getKey(), TEST_CLIENT_SECRET);
        props.setProperty(DriverProperty.WD_AUTHORIZATION_REDIRECT_URL.getKey(), TEST_REDIRECT_URI);

        this.config = new OAuth2Config(props);

        // Create a token manager with mocked authorize a client using package-private constructor
        this.tokenManager = new AuthCodeGrantTokenManagerImpl(this.mockAuthorizeClient, this.config);
    }

    @Test
    @DisplayName("getTokenUsingRefreshToken - Success: Returns new access token when refresh token is valid")
    void testGetTokenUsingRefreshToken_Success() {
        final BearerAccessToken newAccessToken = createAccessToken(TEST_NEW_ACCESS_TOKEN, Duration.ofHours(1));
        final TokenResponse expectedResponse = new TokenResponse(newAccessToken, TEST_NEW_REFRESH_TOKEN);

        when(this.mockAuthorizeClient.getTokenUsingRefreshToken(
            eq(TEST_REFRESH_TOKEN),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_CLIENT_SECRET)
        )).thenReturn(expectedResponse);

        // Act
        final TokenResponse actualResponse =
            this.tokenManager.getTokenUsingRefreshToken(TEST_REFRESH_TOKEN);

        // Assert
        assertNotNull(actualResponse);
        assertEquals(TEST_NEW_ACCESS_TOKEN, actualResponse.getAccessToken().getToken());
        assertTrue(actualResponse.hasRefreshToken());
        assertEquals(TEST_NEW_REFRESH_TOKEN, actualResponse.getRefreshToken());

        verify(this.mockAuthorizeClient, times(1)).getTokenUsingRefreshToken(
            eq(TEST_REFRESH_TOKEN),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_CLIENT_SECRET)
        );
    }

    @Test
    @DisplayName("getTokenUsingRefreshToken - Success: Returns new access token without new refresh token")
    void testGetTokenUsingRefreshToken_SuccessWithoutNewRefreshToken() {
        // Arrange
        final BearerAccessToken newAccessToken = createAccessToken(TEST_NEW_ACCESS_TOKEN, Duration.ofHours(1));
        final TokenResponse expectedResponse = new TokenResponse(newAccessToken); // No new refresh token

        when(this.mockAuthorizeClient.getTokenUsingRefreshToken(
            eq(TEST_REFRESH_TOKEN),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_CLIENT_SECRET)
        )).thenReturn(expectedResponse);

        // Act
        final TokenResponse actualResponse =
            this.tokenManager.getTokenUsingRefreshToken(TEST_REFRESH_TOKEN);

        // Assert
        assertNotNull(actualResponse);
        assertEquals(TEST_NEW_ACCESS_TOKEN, actualResponse.getAccessToken().getToken());
        assertFalse(actualResponse.hasRefreshToken());
    }

    @Test
    @DisplayName("getTokenUsingRefreshToken - Failure: Throws exception when refresh token is expired")
    void testGetTokenUsingRefreshToken_ExpiredRefreshToken() {
        // Arrange
        when(this.mockAuthorizeClient.getTokenUsingRefreshToken(
            eq(TEST_REFRESH_TOKEN),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_CLIENT_SECRET)
        )).thenThrow(new LDQJdbcDriverRuntimeException("Refresh token expired"));

        // Act & Assert
        assertThrows(LDQJdbcDriverRuntimeException.class, () -> this.tokenManager.getTokenUsingRefreshToken(
            TEST_REFRESH_TOKEN));
    }

    @Test
    @DisplayName("getTokenUsingRefreshToken - Failure: Throws exception when refresh token is revoked")
    void testGetTokenUsingRefreshToken_RevokedRefreshToken() {
        // Arrange
        when(this.mockAuthorizeClient.getTokenUsingRefreshToken(
            eq(TEST_REFRESH_TOKEN),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_CLIENT_SECRET)
        )).thenThrow(new LDQJdbcDriverRuntimeException("Refresh token revoked"));

        // Act & Assert
        assertThrows(LDQJdbcDriverRuntimeException.class, () -> this.tokenManager.getTokenUsingRefreshToken(
            TEST_REFRESH_TOKEN));
    }

    @Test
    @DisplayName("acquireToken - Success: Returns access token and refresh token via auth code flow")
    void testAcquireToken_Success() {
        // Arrange
        final BearerAccessToken accessToken = createAccessToken(TEST_ACCESS_TOKEN, Duration.ofHours(1));
        final TokenResponse expectedResponse = new TokenResponse(accessToken, TEST_REFRESH_TOKEN);

        when(this.mockAuthorizeClient.getAuthorizationCode(
            eq(TEST_AUTH_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_REDIRECT_URI)
        )).thenReturn(TEST_AUTH_CODE);

        when(this.mockAuthorizeClient.exchangeCodeForTokenResponse(
            eq(TEST_AUTH_CODE),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_CLIENT_SECRET),
            eq(TEST_REDIRECT_URI)
        )).thenReturn(expectedResponse);

        // Act
        final TokenResponse actualResponse = this.tokenManager.acquireToken();

        // Assert
        assertNotNull(actualResponse);
        assertEquals(TEST_ACCESS_TOKEN, actualResponse.getAccessToken().getToken());
        assertTrue(actualResponse.hasRefreshToken());
        assertEquals(TEST_REFRESH_TOKEN, actualResponse.getRefreshToken());

        verify(this.mockAuthorizeClient, times(1)).getAuthorizationCode(anyString(), anyString(), anyString());
        verify(this.mockAuthorizeClient, times(1)).exchangeCodeForTokenResponse(
            anyString(), anyString(), anyString(), anyString(), anyString()
        );
    }

    private BearerAccessToken createAccessToken(final String token, final Duration expiration) {
        return BearerAccessToken.builder()
            .token(token)
            .expiryTime(Instant.now().plus(expiration).toEpochMilli())
            .clientId(TEST_CLIENT_ID)
            .build();
    }
}
