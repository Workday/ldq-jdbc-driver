/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.AUTHORIZATION_CODE_CANNOT_BE_NULL;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.MSG_INVALID_REFRESH_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.NO_ACCESS_TOKEN_FIELD_IN_RESPONSE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.NO_ACCESS_TOKEN_FOUND_IN_RESPONSE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Tests for {@link OAuth2CodeGrantClient}.
 * Tests authorization code flow implementation.
 *
 */
class OAuth2CodeGrantClientTest {

    private OAuth2CodeGrantClient client;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Synthetic OAuth endpoints for unit tests (not a real environment)
    private static final String WORKDAY_HOST = "host.workday.com";
    private static final String TOKEN_ENDPOINT = "https://" + WORKDAY_HOST + "/ccx/oauth2/example/token";
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_SECRET = "test-client-secret";
    private static final String REDIRECT_URI = "https://localhost:8888/callback";
    private static final String TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String TEST_REFRESH_TOKEN = "test-refresh-token-12345";
    private static final String NEW_REFRESH_TOKEN = "new-refresh-token-67890";
    private static final String SECRET = "test-secret-key-for-jwt-signing-32-bytes-long"; // gitleaks:allow
    private static final String TEST_TENANT = "test-tenant";
    private static final String TEST_SUBJECT = "test-user";
    private static final String TEST_ID_TOKEN = "test-id-token";
    private static final long TEST_EXPIRY_TIME = System.currentTimeMillis() + 3600000; // 1 hour from now
    private static final OkHttpClient httpClient = OAuth2HttpClientFactory.createOAuthHttpClient();

    @BeforeEach
    void setUp() {
        this.client = new OAuth2CodeGrantClient(httpClient);
    }

    @AfterAll
    static void tearDown() {
        OAuth2TokenUtil.shutdownExecutorService(httpClient.dispatcher().executorService());
        httpClient.connectionPool().evictAll();
    }

    /**
     * Test that state generation produces non-null, non-empty values.
     */
    @Test
    void testGenerateState() {
        final String state = OAuth2CodeGrantClient.generateState();

        assertNotNull(state, "State should not be null");
        assertFalse(state.isEmpty(), "State should not be empty");
    }

    /**
     * Test that each state generation produces unique values.
     */
    @Test
    void testGenerateStateIsUnique() {
        final String state1 = OAuth2CodeGrantClient.generateState();
        final String state2 = OAuth2CodeGrantClient.generateState();

        assertNotNull(state1);
        assertNotNull(state2);
        assertNotEquals(state1, state2, "Each state should be unique");
    }

    /**
     * Test parsing query parameters from callback URL.
     */
    @Test
    void testParseQueryParams() {
        final String query = "code=AUTH_CODE_123&state=test-state";
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertNotNull(params);
        assertEquals(2, params.size());
        assertEquals("AUTH_CODE_123", params.get("code"));
        assertEquals("test-state", params.get("state"));
    }

    /**
     * Test parsing query parameters from callback URL, without the "=" after param, the param is not added to the map.
     */
    @Test
    void testParseQueryParamsValueMissing() {
        final String query = "code=AUTH_CODE_123&state";
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertNotNull(params);
        assertEquals(1, params.size());
        assertEquals("AUTH_CODE_123", params.get("code"));
    }

    /**
     * Test parsing query parameters from callback URL.
     * With no value after "=", it should be an empty string.
     */
    @Test
    void testParseQueryParamsValueMissing2() {
        final String query = "code=AUTH_CODE_123&state=";
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertNotNull(params);
        assertEquals(2, params.size());
        assertEquals("AUTH_CODE_123", params.get("code"));
        assertEquals("", params.get("state"));
    }

    /**
     * Test parsing query parameters with URL-encoded error response.
     * URLDecoder decodes '+' as a space character.
     */
    @Test
    void testParseQueryParamsWithError() {
        final String query = "error=access_denied&error_description=User+denied+access";
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertNotNull(params);
        assertEquals("access_denied", params.get("error"));
        assertEquals("User denied access", params.get("error_description"));
    }

    /**
     * Test parsing empty query string.
     */
    @Test
    void testParseQueryParamsEmpty() {
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams("");

        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    /**
     * Test parsing null query string.
     */
    @Test
    void testParseQueryParamsNull() {
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(null);

        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    // ========================================
    // Tests for getTokenUsingRefreshToken()
    // ========================================

    /**
     * Test getTokenUsingRefreshToken with null refresh token.
     */
    @Test
    void testGetTokenUsingRefreshTokenNullRefreshToken() {
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.client.getTokenUsingRefreshToken(null, TOKEN_ENDPOINT, CLIENT_ID, CLIENT_SECRET)
        );
        assertEquals(MSG_INVALID_REFRESH_TOKEN, exception.getMessage());
    }

    /**
     * Test getTokenUsingRefreshToken with an empty refresh token.
     */
    @Test
    void testGetTokenUsingRefreshTokenEmptyRefreshToken() {
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.client.getTokenUsingRefreshToken("", TOKEN_ENDPOINT, CLIENT_ID, CLIENT_SECRET)
        );
        assertEquals(MSG_INVALID_REFRESH_TOKEN, exception.getMessage());
    }

    /**
     * Test getTokenUsingRefreshToken with invalid token endpoint (network error).
     */
    @Test
    void testGetTokenUsingRefreshTokenNetworkError() {
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.client.getTokenUsingRefreshToken(
                TEST_REFRESH_TOKEN,
                "https://invalid-nonexistent-domain-12345.com/token",
                CLIENT_ID,
                CLIENT_SECRET
            )
        );
        assertTrue(exception.getMessage().contains("network error"));
    }

    /**
     * Test a successful token refresh without a new refresh token.
     * Server returns only an access token, no new refresh token.
     */
    @Test
    void testGetTokenUsingRefreshTokenSuccessNoNewRefreshToken()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, null);

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshToken(
                                                                  final String refreshToken,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String clientSecret) {
                return mockResponse;
            }
        };
        final TokenResponse result = testClient.getTokenUsingRefreshToken(
            TEST_REFRESH_TOKEN,
            TOKEN_ENDPOINT,
            CLIENT_ID,
            CLIENT_SECRET
        );

        assertNotNull(result, "TokenResponse should not be null");
        assertNotNull(result.getAccessToken(), "Access token should not be null");
        assertEquals(validAccessToken, result.getAccessToken().getToken());
        assertEquals(TEST_REFRESH_TOKEN, result.getRefreshToken(), "Should return original refresh token");
        assertEquals(TEST_TENANT, result.getAccessToken().getTenant());
        assertEquals(TEST_SUBJECT, result.getAccessToken().getSubject());
        assertEquals(CLIENT_ID, result.getAccessToken().getClientId());
    }

    /**
     * Test a successful token refresh with a new refresh token (token rotation).
     * Server returns both a new access token and a new refresh token.
     */
    @Test
    void testGetTokenUsingRefreshTokenSuccessWithNewRefreshToken()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, NEW_REFRESH_TOKEN);

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshToken(
                                                                  final String refreshToken,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String clientSecret) {
                return mockResponse;
            }
        };
        final TokenResponse result = testClient.getTokenUsingRefreshToken(
            TEST_REFRESH_TOKEN,
            TOKEN_ENDPOINT,
            CLIENT_ID,
            CLIENT_SECRET
        );

        assertNotNull(result, "TokenResponse should not be null");
        assertNotNull(result.getAccessToken(), "Access token should not be null");
        assertEquals(validAccessToken, result.getAccessToken().getToken());
        assertEquals(NEW_REFRESH_TOKEN, result.getRefreshToken(), "Should return new refresh token");
        assertEquals(TEST_TENANT, result.getAccessToken().getTenant());
        assertEquals(TEST_SUBJECT, result.getAccessToken().getSubject());
    }

    /**
     * Test token refresh with a missing access_token field in response.
     */
    @Test
    void testGetTokenUsingRefreshTokenMissingAccessToken() {
        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshToken(
                                                                  final String refreshToken,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String clientSecret) {
                final ObjectNode response = OBJECT_MAPPER.createObjectNode();
                response.put("refresh_token", NEW_REFRESH_TOKEN);
                return response;
            }
        };
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> testClient.getTokenUsingRefreshToken(
                TEST_REFRESH_TOKEN,
                TOKEN_ENDPOINT,
                CLIENT_ID,
                CLIENT_SECRET
            )
        );
        assertTrue(exception.getMessage().contains(NO_ACCESS_TOKEN_FIELD_IN_RESPONSE));
    }

    /**
     * Test token refresh with an empty access_token value in response.
     */
    @Test
    void testGetTokenUsingRefreshToken_EmptyAccessToken() {
        final LDQJdbcDriverRuntimeException exception;
        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshToken(
                                                                  final String refreshToken,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String clientSecret) {
                final ObjectNode response = OBJECT_MAPPER.createObjectNode();
                response.put("access_token", "");
                return response;
            }
        };
        exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> testClient.getTokenUsingRefreshToken(
                TEST_REFRESH_TOKEN,
                TOKEN_ENDPOINT,
                CLIENT_ID,
                CLIENT_SECRET
            )
        );
        assertTrue(exception.getMessage().contains(NO_ACCESS_TOKEN_FOUND_IN_RESPONSE));
    }

    /**
     * Test token refresh with invalid JWT in response.
     */
    @Test
    void testGetTokenUsingRefreshToken_InvalidJwt() {
        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshToken(
                                                                  final String refreshToken,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String clientSecret) {
                final ObjectNode response = OBJECT_MAPPER.createObjectNode();
                response.put("access_token", "invalid.jwt.token");
                return response;
            }
        };

        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> testClient.getTokenUsingRefreshToken(
                TEST_REFRESH_TOKEN,
                TOKEN_ENDPOINT,
                CLIENT_ID,
                CLIENT_SECRET
            )
        );
        assertTrue(exception.getMessage().contains(FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE));
    }

    /**
     * Test token refresh with HTTP error response.
     */
    @Test
    void testGetTokenUsingRefreshToken_HttpError() {
        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshToken(
                                                                  final String refreshToken,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String clientSecret)
                throws IOException {
                throw new IOException("HTTP 401 - Unauthorized");
            }
        };
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> testClient.getTokenUsingRefreshToken(
                TEST_REFRESH_TOKEN,
                TOKEN_ENDPOINT,
                CLIENT_ID,
                CLIENT_SECRET
            )
        );
        assertTrue(exception.getMessage().contains(ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("exchangeCodeForTokenResponseWithVerifier - null/empty code throws exception")
    void testExchangeCodeForTokenResponseWithVerifierInvalidCode(final String code) {
        final LDQJdbcDriverRuntimeException ex = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.client.exchangeCodeForTokenResponseWithVerifier(
                code, TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_URI, TEST_CODE_VERIFIER));
        assertEquals(AUTHORIZATION_CODE_CANNOT_BE_NULL, ex.getMessage());
    }

    @Test
    @DisplayName("exchangeCodeForTokenResponseWithVerifier - network error wraps IOException")
    void testExchangeCodeForTokenResponseWithVerifierNetworkError() {
        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithCodeVerifier(final String authorizationCode,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String redirectUri,
                                                                  final String codeVerifier)
                throws IOException {
                throw new IOException("connection refused");
            }
        };
        final LDQJdbcDriverRuntimeException ex = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> testClient.exchangeCodeForTokenResponseWithVerifier(
                "some-code", TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_URI, TEST_CODE_VERIFIER));
        assertEquals(ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR, ex.getMessage());
    }

    @Test
    @DisplayName("exchangeCodeForTokenResponseWithVerifier - success returns correct TokenResponse")
    void testExchangeCodeForTokenResponseWithVerifierSuccess()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, NEW_REFRESH_TOKEN);

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithCodeVerifier(final String authorizationCode,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String redirectUri,
                                                                  final String codeVerifier) {
                return mockResponse;
            }
        };
        final TokenResponse result = testClient.exchangeCodeForTokenResponseWithVerifier(
            "some-code", TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_URI, TEST_CODE_VERIFIER);

        assertNotNull(result.getAccessToken());
        assertEquals(validAccessToken, result.getAccessToken().getToken());
        assertEquals(NEW_REFRESH_TOKEN, result.getRefreshToken());
    }

    @Test
    @DisplayName("exchangeCodeForTokenResponseWithVerifier - success with no refresh token in response")
    void testExchangeCodeForTokenResponseWithVerifierSuccessNoRefreshToken()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, null);

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithCodeVerifier(final String authorizationCode,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String redirectUri,
                                                                  final String codeVerifier) {
                return mockResponse;
            }
        };

        final TokenResponse result = testClient.exchangeCodeForTokenResponseWithVerifier(
            "some-code", TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_URI, TEST_CODE_VERIFIER);

        assertNotNull(result.getAccessToken());
        assertNull(result.getRefreshToken());
    }

    @Test
    @DisplayName("exchangeCodeForTokenResponseWithVerifier - passes codeVerifier to inner method, not clientSecret")
    void testExchangeCodeForTokenResponseWithVerifierPassesVerifier()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, null);
        final String[] capturedVerifier = new String[1];

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithCodeVerifier(final String authorizationCode,
                                                                  final String tokenEndpoint,
                                                                  final String clientId,
                                                                  final String redirectUri,
                                                                  final String codeVerifier) {
                capturedVerifier[0] = codeVerifier;
                return mockResponse;
            }
        };

        testClient.exchangeCodeForTokenResponseWithVerifier(
            "some-code", TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_URI, TEST_CODE_VERIFIER);

        assertEquals(TEST_CODE_VERIFIER, capturedVerifier[0]);
    }

    // ========================================
    // Tests for getTokenUsingRefreshTokenPublicClient()
    // ========================================

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("getTokenUsingRefreshTokenPublicClient - null/empty refresh token throws exception")
    void testGetTokenUsingRefreshTokenPublicClientInvalidToken(final String refreshToken) {
        final LDQJdbcDriverRuntimeException ex = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.client.getTokenUsingRefreshTokenPublicClient(refreshToken, TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(MSG_INVALID_REFRESH_TOKEN, ex.getMessage());
    }

    @Test
    @DisplayName("getTokenUsingRefreshTokenPublicClient - network error wraps IOException")
    void testGetTokenUsingRefreshTokenPublicClientNetworkError() {
        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshTokenPublicClient(final String refreshToken,
                                                                              final String tokenEndpoint,
                                                                              final String clientId)
                throws IOException {
                throw new IOException("connection refused");
            }
        };
        final LDQJdbcDriverRuntimeException ex = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> testClient.getTokenUsingRefreshTokenPublicClient(
                TEST_REFRESH_TOKEN, TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR, ex.getMessage());
    }

    @Test
    @DisplayName("getTokenUsingRefreshTokenPublicClient - success, server returns no new refresh token")
    void testGetTokenUsingRefreshTokenPublicClientSuccessNoNewRefreshToken()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, null);

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshTokenPublicClient(final String refreshToken,
                                                                              final String tokenEndpoint,
                                                                              final String clientId) {
                return mockResponse;
            }
        };
        final TokenResponse result = testClient.getTokenUsingRefreshTokenPublicClient(
            TEST_REFRESH_TOKEN, TOKEN_ENDPOINT, CLIENT_ID);

        assertNotNull(result.getAccessToken());
        assertEquals(TEST_REFRESH_TOKEN, result.getRefreshToken(), "Should return original refresh token");
    }

    @Test
    @DisplayName("getTokenUsingRefreshTokenPublicClient - success, server rotates refresh token")
    void testGetTokenUsingRefreshTokenPublicClientSuccessWithNewRefreshToken()
        throws Exception {
        final String validAccessToken = createValidJwtToken();
        final JsonNode mockResponse = createTokenResponse(validAccessToken, NEW_REFRESH_TOKEN);

        final OAuth2CodeGrantClient testClient = new OAuth2CodeGrantClient(httpClient) {
            @Override
            protected JsonNode requestAccessTokenWithRefreshTokenPublicClient(final String refreshToken,
                                                                              final String tokenEndpoint,
                                                                              final String clientId) {
                return mockResponse;
            }
        };

        final TokenResponse result = testClient.getTokenUsingRefreshTokenPublicClient(
            TEST_REFRESH_TOKEN, TOKEN_ENDPOINT, CLIENT_ID);

        assertNotNull(result.getAccessToken());
        assertEquals(NEW_REFRESH_TOKEN, result.getRefreshToken(), "Should return rotated refresh token");
    }

    /**
     * Creates a valid JWT token for testing purposes using a Nimbus JWT library.
     * This creates a properly signed JWT that will pass SignedJWT.parse() validation.
     */
    private String createValidJwtToken()
        throws Exception {
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
            .keyID(TEST_ID_TOKEN)
            .build();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(TEST_SUBJECT)
            .expirationTime(new Date(TEST_EXPIRY_TIME))
            .claim(JWTClaimNames.TENANT, TEST_TENANT)
            .claim(JWTClaimNames.CLIENT_ID, CLIENT_ID)
            .build();

        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        final MACSigner signer = new MACSigner(SECRET);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    /**
     * Creates a mock token response JSON with access token and optional refresh token.
     *
     * @param accessToken  The access token (JWT) to include
     * @param refreshToken The refresh token to include (null if not rotating)
     * @return JsonNode representing the token response
     */
    private JsonNode createTokenResponse(final String accessToken, final String refreshToken) {
        final ObjectNode response = OBJECT_MAPPER.createObjectNode();
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);

        if (refreshToken != null) {
            response.put("refresh_token", refreshToken);
            response.put("refresh_expires_in", 7200);
        }

        return response;
    }
}
