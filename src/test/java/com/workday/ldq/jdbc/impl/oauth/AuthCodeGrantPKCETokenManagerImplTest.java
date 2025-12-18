/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;
import com.workday.ldq.jdbc.impl.property.DriverProperty;

/**
 * Unit tests for {@link AuthCodeGrantPKCETokenManagerImpl}.
 * Verifies that the PKCE flow uses the correct RFC 7636 methods and never falls back to
 * the standard auth code flow (which requires a client secret).
 *
 */
@ExtendWith(MockitoExtension.class)
class AuthCodeGrantPKCETokenManagerImplTest {

    private static final String TEST_AUTH_ENDPOINT = "https://example.com/authorize";
    private static final String TEST_TOKEN_ENDPOINT = "https://example.com/token";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_REDIRECT_URI = "https://localhost:8888/callback";
    private static final String TEST_AUTH_CODE = "test-auth-code";
    private static final String TEST_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_REFRESH_TOKEN = "test-refresh-token";
    private static final String TEST_NEW_REFRESH_TOKEN = "test-new-refresh-token";

    @Mock
    private OAuth2CodeGrantClient mockAuthorizeClient;

    private AuthCodeGrantPKCETokenManagerImpl pkceTokenManager;

    @BeforeEach
    void setUp() {
        final Properties props = new Properties();
        props.setProperty(DriverProperty.WD_AUTH_MODEL.getKey(), "AUTHORIZATION_CODE_PKCE");
        props.setProperty(DriverProperty.WD_AUTHORIZATION_ENDPOINT.getKey(), TEST_AUTH_ENDPOINT);
        props.setProperty(DriverProperty.WD_TOKEN_ENDPOINT.getKey(), TEST_TOKEN_ENDPOINT);
        props.setProperty(DriverProperty.WD_CLIENT_ID.getKey(), TEST_CLIENT_ID);
        props.setProperty(DriverProperty.WD_AUTHORIZATION_REDIRECT_URL.getKey(), TEST_REDIRECT_URI);

        final OAuth2Config config = new OAuth2Config(props);
        this.pkceTokenManager = new AuthCodeGrantPKCETokenManagerImpl(this.mockAuthorizeClient, config);
    }

    // ==================== acquireToken() ====================

    @Test
    @DisplayName("acquireToken - calls getAuthorizationCodeWithPkce, not getAuthorizationCode")
    void testAcquireTokenCallsPkceAuthorizationMethod() {
        stubAcquireToken();

        this.pkceTokenManager.acquireToken();

        verify(this.mockAuthorizeClient, times(1))
            .getAuthorizationCodeWithPkce(anyString(), anyString(), anyString(), anyString());
        verify(this.mockAuthorizeClient, never())
            .getAuthorizationCode(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("acquireToken - calls exchangeCodeForTokenResponseWithVerifier, not exchangeCodeForTokenResponse")
    void testAcquireTokenCallsExchangeWithVerifier() {
        stubAcquireToken();

        this.pkceTokenManager.acquireToken();

        verify(this.mockAuthorizeClient, times(1))
            .exchangeCodeForTokenResponseWithVerifier(anyString(), anyString(), anyString(), anyString(), anyString());
        verify(this.mockAuthorizeClient, never())
            .exchangeCodeForTokenResponse(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("acquireToken - passes config values to getAuthorizationCodeWithPkce")
    void testAcquireTokenPassesConfigToAuthorizationRequest() {
        stubAcquireToken();

        this.pkceTokenManager.acquireToken();

        verify(this.mockAuthorizeClient).getAuthorizationCodeWithPkce(
            eq(TEST_AUTH_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_REDIRECT_URI),
            anyString()
        );
    }

    @Test
    @DisplayName("acquireToken - passes config values to exchangeCodeForTokenResponseWithVerifier")
    void testAcquireTokenPassesConfigToTokenExchange() {
        stubAcquireToken();

        this.pkceTokenManager.acquireToken();

        verify(this.mockAuthorizeClient).exchangeCodeForTokenResponseWithVerifier(
            eq(TEST_AUTH_CODE),
            eq(TEST_TOKEN_ENDPOINT),
            eq(TEST_CLIENT_ID),
            eq(TEST_REDIRECT_URI),
            anyString()
        );
    }

    @Test
    @DisplayName("acquireToken - code_challenge is the S256 hash of the code_verifier sent to token endpoint")
    void testAcquireTokenVerifierAndChallengeFormValidPkcePair() {
        final ArgumentCaptor<String> challengeCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<String> verifierCaptor = ArgumentCaptor.forClass(String.class);

        final TokenResponse tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, null);
        when(this.mockAuthorizeClient.getAuthorizationCodeWithPkce(
            anyString(), anyString(), anyString(), challengeCaptor.capture())).thenReturn(TEST_AUTH_CODE);
        when(this.mockAuthorizeClient.exchangeCodeForTokenResponseWithVerifier(
            anyString(), anyString(), anyString(), anyString(), verifierCaptor.capture())).thenReturn(tokenResponse);

        this.pkceTokenManager.acquireToken();

        final String capturedChallenge = challengeCaptor.getValue();
        final String capturedVerifier = verifierCaptor.getValue();
        assertEquals(capturedChallenge, OAuth2TokenUtil.generateCodeChallenge(capturedVerifier),
            "code_challenge must equal BASE64URL(SHA-256(code_verifier))");
    }

    @Test
    @DisplayName("acquireToken - generates a unique code_verifier on each call")
    void testAcquireTokenGeneratesUniqueCodeVerifierPerCall() {
        final ArgumentCaptor<String> verifierCaptor = ArgumentCaptor.forClass(String.class);
        final TokenResponse tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, null);

        when(this.mockAuthorizeClient.getAuthorizationCodeWithPkce(
            anyString(), anyString(), anyString(), anyString())).thenReturn(TEST_AUTH_CODE);
        when(this.mockAuthorizeClient.exchangeCodeForTokenResponseWithVerifier(
            anyString(), anyString(), anyString(), anyString(), verifierCaptor.capture())).thenReturn(tokenResponse);

        // Call acquireToken 3 times
        this.pkceTokenManager.acquireToken();
        this.pkceTokenManager.acquireToken();
        this.pkceTokenManager.acquireToken();

        // Verify exchangeCodeForTokenResponseWithVerifier was called 3 times
        verify(this.mockAuthorizeClient, times(3))
            .exchangeCodeForTokenResponseWithVerifier(anyString(), anyString(), anyString(), anyString(), anyString());

        // Verify all 3 captured verifiers are unique
        final List<String> verifiers = verifierCaptor.getAllValues();
        assertEquals(3, verifiers.size(), "Should have captured 3 verifiers");
        assertEquals(3, verifiers.stream().distinct().count(),
            "Each acquireToken() call must generate a distinct code_verifier");
    }

    @Test
    @DisplayName("acquireToken - returns the TokenResponse from the token exchange")
    void testAcquireTokenReturnsTokenResponse() {
        final TokenResponse expected = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);
        when(this.mockAuthorizeClient.getAuthorizationCodeWithPkce(
            anyString(), anyString(), anyString(), anyString())).thenReturn(TEST_AUTH_CODE);
        when(this.mockAuthorizeClient.exchangeCodeForTokenResponseWithVerifier(
            anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(expected);

        final TokenResponse actual = this.pkceTokenManager.acquireToken();

        assertNotNull(actual);
        assertEquals(TEST_ACCESS_TOKEN, actual.getAccessToken().getToken());
        assertEquals(TEST_REFRESH_TOKEN, actual.getRefreshToken());
    }

    // ==================== getTokenUsingRefreshToken() ====================

    @Test
    @DisplayName("getTokenUsingRefreshToken - delegates to getTokenUsingRefreshTokenPublicClient, not " +
        "getTokenUsingRefreshToken")
    void testRefreshTokenDelegatesToPublicClientMethod() {
        final TokenResponse expected = createTokenResponse(TEST_ACCESS_TOKEN, TEST_NEW_REFRESH_TOKEN);
        when(this.mockAuthorizeClient.getTokenUsingRefreshTokenPublicClient(
            eq(TEST_REFRESH_TOKEN), eq(TEST_TOKEN_ENDPOINT), eq(TEST_CLIENT_ID))).thenReturn(expected);

        this.pkceTokenManager.getTokenUsingRefreshToken(TEST_REFRESH_TOKEN);

        verify(this.mockAuthorizeClient, times(1))
            .getTokenUsingRefreshTokenPublicClient(eq(TEST_REFRESH_TOKEN), eq(TEST_TOKEN_ENDPOINT), eq(TEST_CLIENT_ID));
        verify(this.mockAuthorizeClient, never())
            .getTokenUsingRefreshToken(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("getTokenUsingRefreshToken - passes config values to public client method")
    void testRefreshTokenPassesConfigValues() {
        final TokenResponse expected = createTokenResponse(TEST_ACCESS_TOKEN, TEST_NEW_REFRESH_TOKEN);
        when(this.mockAuthorizeClient.getTokenUsingRefreshTokenPublicClient(
            anyString(), anyString(), anyString())).thenReturn(expected);

        final TokenResponse actual = this.pkceTokenManager.getTokenUsingRefreshToken(TEST_REFRESH_TOKEN);

        assertNotNull(actual);
        assertEquals(TEST_ACCESS_TOKEN, actual.getAccessToken().getToken());
        verify(this.mockAuthorizeClient).getTokenUsingRefreshTokenPublicClient(
            eq(TEST_REFRESH_TOKEN), eq(TEST_TOKEN_ENDPOINT), eq(TEST_CLIENT_ID));
    }

    // ==================== Helpers ====================

    private void stubAcquireToken() {
        final TokenResponse tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, null);
        when(this.mockAuthorizeClient.getAuthorizationCodeWithPkce(
            anyString(), anyString(), anyString(), anyString())).thenReturn(TEST_AUTH_CODE);
        when(this.mockAuthorizeClient.exchangeCodeForTokenResponseWithVerifier(
            anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(tokenResponse);
    }

    private TokenResponse createTokenResponse(final String token, final String refreshToken) {
        final BearerAccessToken accessToken = BearerAccessToken.builder()
            .token(token)
            .expiryTime(Instant.now().plus(Duration.ofHours(1)).toEpochMilli())
            .clientId(TEST_CLIENT_ID)
            .build();
        return new TokenResponse(accessToken, refreshToken);
    }
}
