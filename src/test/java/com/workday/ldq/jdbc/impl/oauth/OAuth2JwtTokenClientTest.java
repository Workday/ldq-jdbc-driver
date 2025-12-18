/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.JWT_ASSERTION_CANNOT_BE_NULL_OR_EMPTY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TOKEN_URL_CANNOT_BE_NULL_OR_EMPTY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames;

/**
 * Unit tests for OAuth2JwtTokenClient HTTP functionality.
 * Tests the requestAccessToken method with proper arguments.
 *
 */
public class OAuth2JwtTokenClientTest {

    private static final String TEST_JWT_ASSERTION = "test-jwt-assertion";
    private static final String TEST_TOKEN_URL = "https://test.example.com/oauth/token";
    private static final String INVALID_URL = "invalid-url";
    private static final String TEST_TENANT = "test-tenant";
    private static final String TEST_SUBJECT = "test-user";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_ID_TOKEN = "test-id-token";
    private static final String SECRET = "test-secret-key-for-jwt-signing-32-bytes-long"; // gitleaks:allow
    private static final int MAX_RETRIES = Integer.getInteger(
        LDQJdbcAuthnConstants.HTTP_RETRY_MAX_RETRIES_PROP,
        LDQJdbcAuthnConstants.DEFAULT_MAX_RETRIES);
    private static final int NUM_TEST_RETRIES = MAX_RETRIES - 1;
    private static final long TEST_EXPIRY_TIME = 1634567800000L; // Future timestamp
    private static final String TEST_ENDPOINT = "https://test.example.com";
    private static final long BASE_DELAY_MS = Long.getLong(
        LDQJdbcAuthnConstants.HTTP_RETRY_DELAY_MILLIS_PROP,
        LDQJdbcAuthnConstants.DEFAULT_RETRY_DELAY_MILLIS);
    private static final long MAX_DELAY_MS = Long.getLong(
        LDQJdbcAuthnConstants.HTTP_RETRY_MAX_DELAY_MILLIS_PROP,
        LDQJdbcAuthnConstants.DEFAULT_MAX_RETRY_DELAY_MILLIS);
    private static final double MULTIPLIER = Double.parseDouble(
        System.getProperty(LDQJdbcAuthnConstants.HTTP_RETRY_BACKOFF_MULTIPLIER_PROP,
            String.valueOf(LDQJdbcAuthnConstants.DEFAULT_BACKOFF_MULTIPLIER)));
    private static final OkHttpClient httpClient = OAuth2HttpClientFactory.createOAuthHttpClient();


    private OAuth2JwtTokenClient oauth2TokenClient;

    @BeforeAll
    public static void setupRetries() {
        // Enable retries for testing
        System.setProperty(LDQJdbcAuthnConstants.HTTP_RETRY_MAX_RETRIES_PROP, "2");
    }

    @BeforeEach
    public void setup() {
        this.oauth2TokenClient = new OAuth2JwtTokenClient(httpClient);
    }

    @AfterAll
    static void tearDown() {
        OAuth2TokenUtil.shutdownExecutorService(httpClient.dispatcher().executorService());
        httpClient.connectionPool().evictAll();
    }

    @Test
    public void testRequestAccessTokenWithValidArgumentsThrowsNetworkException() {
        // Test that the method accepts 2 arguments correctly.
        // Since we're using a non-existent URL, it should throw a network exception
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.oauth2TokenClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL));

        // Verify that the error message indicates a request failure
        assertTrue(exception.getMessage().contains(ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR));
    }

    @Test
    public void testRequestAccessTokenWithInvalidUrlThrowsException() {
        // Test that the method accepts 2 arguments correctly with invalid URL
        assertThrows(IllegalArgumentException.class,
            () -> this.oauth2TokenClient.requestToken(TEST_JWT_ASSERTION, INVALID_URL));
    }

    @Test
    public void testRequestAccessTokenWithNullJwtAssertionThrowsNullPointerException() {
        // Test null JWT assertion validation
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.oauth2TokenClient.requestToken(null, TEST_TOKEN_URL)
        );

        assertEquals(JWT_ASSERTION_CANNOT_BE_NULL_OR_EMPTY, exception.getMessage());
    }

    @Test
    public void testRequestAccessTokenWithNullTokenUrlThrowsNullPointerException() {
        // Test null token URL validation
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> this.oauth2TokenClient.requestToken(TEST_JWT_ASSERTION, null)
        );

        assertEquals(TOKEN_URL_CANNOT_BE_NULL_OR_EMPTY, exception.getMessage());
    }

    @Test
    public void testRequestAccessTokenSuccess()
        throws Exception {

        // Create a valid JWT token for testing
        final String validJwtToken = createValidJwtToken();

        // Create a test client that overrides the requestTokenResponseNode method
        final OAuth2JwtTokenClient testClientWithValidJwt = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl) {
                final ObjectNode response = LDQJdbcAuthnConstants.OBJECT_MAPPER.createObjectNode();
                response.put("access_token", validJwtToken);
                return response;
            }
        };

        // Call the method - this should now succeed and return a BearerAccessToken
        final BearerAccessToken result = testClientWithValidJwt.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL)
            .getAccessToken();

        // Verify the result
        assertNotNull(result, "Result should not be null");
        assertEquals(validJwtToken, result.getToken());
        assertEquals(TEST_TENANT, result.getTenant());
        assertEquals(TEST_SUBJECT, result.getSubject());
        assertEquals(TEST_CLIENT_ID, result.getClientId());
        assertNotNull(result.getIdToken(), "ID token should not be null");
        assertNotNull(result.getExpiryTime(), "Expiry time should not be null");
        assertEquals(BearerAccessToken.TYPE_BEARER, result.getType());
    }

    /**
     * Creates a valid JWT token for testing purposes using the Nimbus JWT library.
     * This creates a properly signed JWT that will pass SignedJWT.parse() validation.
     */
    private String createValidJwtToken()
        throws Exception {
        // Create JWT header with KeyID
        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
            .keyID(TEST_ID_TOKEN)
            .build();

        // Create JWT claims set with test data
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(TEST_SUBJECT)
            .expirationTime(new java.util.Date(TEST_EXPIRY_TIME))
            .claim(JWTClaimNames.TENANT, TEST_TENANT)
            .claim(JWTClaimNames.CLIENT_ID, TEST_CLIENT_ID)
            .build();

        // Create signed JWT
        final SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        final MACSigner signer = new MACSigner(SECRET);
        signedJWT.sign(signer);

        // Return the serialized JWT
        return signedJWT.serialize();
    }

    /**
     * Executes a request with manual retry logic, simulating the retry interceptor behavior.
     * This method handles the retry loop and delay logic repeated across multiple tests.
     *
     * @param testClient         The OAuth2JwtTokenClient instance to use for the request
     * @param isRetryableChecker A function that determines if an exception is retryable.
     *                           Takes the exception and retry count, returns true if retryable.
     * @return The BearerAccessToken if successful
     * @throws Exception if the request fails after all retries
     */
    private BearerAccessToken executeWithManualRetry(
                                                     final OAuth2JwtTokenClient testClient,
                                                     final BiFunction<Throwable, Integer, Boolean> isRetryableChecker) {
        BearerAccessToken result = null;
        int retryCount = 0;

        while (retryCount <= MAX_RETRIES && result == null) {
            try {
                result = testClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL).getAccessToken();
            }
            catch (final LDQJdbcDriverRuntimeException e) {
                final Throwable cause = e.getCause();
                final boolean isRetryable = isRetryableChecker.apply(cause, retryCount);

                if (retryCount < MAX_RETRIES && isRetryable) {
                    retryCount++;
                    try {
                        Thread.sleep(BASE_DELAY_MS);
                    }
                    catch (final InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Test interrupted", ie);
                    }
                }
                else {
                    throw e;
                }
            }
        }

        return result;
    }

    @Test
    public void testRetryOn429()
        throws Exception {
        final AtomicInteger attemptCount = new AtomicInteger(0);
        final String validJwtToken = createValidJwtToken();

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                final int attempt = attemptCount.incrementAndGet();
                if (attempt <= NUM_TEST_RETRIES) {
                    throw new IOException("HTTP 429 - Too Many Requests");
                }
                final ObjectNode response = LDQJdbcAuthnConstants.OBJECT_MAPPER.createObjectNode();
                response.put("access_token", validJwtToken);
                return response;
            }
        };

        final BearerAccessToken result = executeWithManualRetry(testClient, (cause, retryCount) -> {
            return cause != null &&
                cause.getMessage() != null &&
                (cause.getMessage().contains("HTTP 429") ||
                    cause.getMessage().contains("Too Many Requests"));
        });

        assertNotNull(result, "Result should not be null after retries");
        assertEquals(3, attemptCount.get(), "Should have made 3 attempts (initial + 2 retries)");
        assertEquals(validJwtToken, result.getToken());
    }

    @Test
    public void testRetryOn500()
        throws Exception {
        final AtomicInteger attemptCount = new AtomicInteger(0);
        final String validJwtToken = createValidJwtToken();

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                final int attempt = attemptCount.incrementAndGet();
                if (attempt <= NUM_TEST_RETRIES) {
                    throw new IOException("HTTP 500 - Internal Server Error");
                }
                final ObjectNode response = LDQJdbcAuthnConstants.OBJECT_MAPPER.createObjectNode();
                response.put("access_token", validJwtToken);
                return response;
            }
        };

        final BearerAccessToken result = executeWithManualRetry(testClient, (cause, retryCount) -> {
            return cause != null &&
                cause.getMessage() != null &&
                (cause.getMessage().contains("HTTP 5") ||
                    cause.getMessage().contains("Internal Server Error"));
        });

        assertNotNull(result, "Result should not be null after retries");
        assertEquals(3, attemptCount.get(), "Should have made 3 attempts (initial + 2 retries)");
        assertEquals(validJwtToken, result.getToken());
    }

    @Test
    public void testRetryOnNetworkException()
        throws Exception {
        final AtomicInteger attemptCount = new AtomicInteger(0);
        final String validJwtToken = createValidJwtToken();

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                final int attempt = attemptCount.incrementAndGet();
                // Simulate network errors for the first attempt, then success
                if (attempt == 1) {
                    throw new IOException("Connection timeout");
                }
                final ObjectNode response = LDQJdbcAuthnConstants.OBJECT_MAPPER.createObjectNode();
                response.put("access_token", validJwtToken);
                return response;
            }
        };

        final BearerAccessToken result = executeWithManualRetry(testClient, (cause, retryCount) -> {
            return cause != null &&
                cause.getMessage() != null &&
                (cause.getMessage().contains("connection") ||
                    cause.getMessage().contains("timeout") ||
                    cause.getMessage().contains("network"));
        });

        assertNotNull(result, "Result should not be null after retry");
        assertEquals(2, attemptCount.get(), "Should have made 2 attempts (initial + retry)");
        assertEquals(validJwtToken, result.getToken());
    }

    /**
     * Test retry interceptor behavior: No retry on HTTP 400 (Bad Request).
     * Client errors should not trigger retries.
     */
    @Test
    public void testRetryNoRetryOn400BadRequest() {
        final AtomicInteger attemptCount = new AtomicInteger(0);

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                attemptCount.incrementAndGet();
                // Simulate 400 Bad Request - should not retry
                throw new IOException("HTTP 400 - Bad Request");
            }
        };

        assertThrows(LDQJdbcDriverRuntimeException.class, () -> {
            testClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL).getAccessToken();
        });

        assertEquals(1, attemptCount.get(), "Should have made only 1 attempt (no retries for 400)");
    }

    /**
     * Test retry interceptor behavior: No retry on HTTP 401 (Unauthorized).
     * Authentication errors should not trigger retries.
     */
    @Test
    public void testRetryNoRetryOn401Unauthorized() {
        final AtomicInteger attemptCount = new AtomicInteger(0);

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                attemptCount.incrementAndGet();
                throw new IOException("HTTP 401 - Unauthorized");
            }
        };

        assertThrows(LDQJdbcDriverRuntimeException.class, () -> {
            testClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL).getAccessToken();
        });

        assertEquals(1, attemptCount.get(), "Should have made only 1 attempt (no retries for 401)");
    }

    @Test
    public void testMaxRetriesExceededFailsAfterMaxRetries() {
        final AtomicInteger attemptCount = new AtomicInteger(0);

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                attemptCount.incrementAndGet();
                throw new IOException("HTTP 429 - Too Many Requests");
            }
        };

        final LDQJdbcDriverRuntimeException exception = assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> {
                testClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL).getAccessToken();
            });

        assertTrue(exception.getMessage() != null && exception.getMessage().contains("network error"),
            "Exception should indicate network error");

        assertNotNull(exception.getCause(), "Exception should have a cause");
        assertTrue(exception.getCause() instanceof IOException, "Cause should be IOException");
        assertTrue(exception.getCause().getMessage() != null &&
            exception.getCause().getMessage().contains("HTTP 429"),
            "Cause message should contain HTTP 429");

        assertEquals(1, attemptCount.get(),
            "Should have made 1 attempt when IOException is thrown before HTTP request is made");
    }

    /**
     * Test retry interceptor behavior: Successful response on the first attempt.
     * Should not retry when a request succeeds immediately.
     */
    @Test
    public void testRetrySuccessfulResponse()
        throws Exception {
        final AtomicInteger attemptCount = new AtomicInteger(0);
        final String validJwtToken = createValidJwtToken();

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl) {
                attemptCount.incrementAndGet();
                // Success immediately - no retries needed
                final ObjectNode response = LDQJdbcAuthnConstants.OBJECT_MAPPER.createObjectNode();
                response.put("access_token", validJwtToken);
                return response;
            }
        };

        final BearerAccessToken result = testClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL).getAccessToken();

        assertNotNull(result, "Result should not be null");
        assertEquals(1, attemptCount.get(), "Should have made only 1 attempt (no retries needed)");
        assertEquals(validJwtToken, result.getToken());
    }

    @Test
    public void testRetryExponentialBackoffDelaysIncrease()
        throws Exception {
        final AtomicInteger attemptCount = new AtomicInteger(0);
        final String validJwtToken = createValidJwtToken();

        final OAuth2JwtTokenClient testClient = new OAuth2JwtTokenClient(httpClient) {
            @Override
            protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
                throws IOException {
                final int attempt = attemptCount.incrementAndGet();

                if (attempt <= NUM_TEST_RETRIES) {
                    throw new IOException("HTTP 429 - Too Many Requests");
                }
                final ObjectNode response = LDQJdbcAuthnConstants.OBJECT_MAPPER.createObjectNode();
                response.put("access_token", validJwtToken);
                return response;
            }
        };

        BearerAccessToken result = null;
        int retryCount = 0;
        final long startTime = System.currentTimeMillis();
        final int arraySize = Math.max(1, NUM_TEST_RETRIES);
        final AtomicLong[] delays = new AtomicLong[arraySize];
        for (int i = 0; i < arraySize; i++) {
            delays[i] = new AtomicLong(0);
        }

        while (retryCount <= MAX_RETRIES && result == null) {
            try {
                result = testClient.requestToken(TEST_JWT_ASSERTION, TEST_TOKEN_URL).getAccessToken();
            }
            catch (final LDQJdbcDriverRuntimeException e) {
                final Throwable cause = e.getCause();
                final boolean isRetryable = cause != null &&
                    cause.getMessage() != null &&
                    (cause.getMessage().contains("HTTP 429") ||
                        cause.getMessage().contains("HTTP 5") ||
                        cause.getMessage().contains("Too Many Requests"));

                if (retryCount < MAX_RETRIES && isRetryable) {
                    final long delayStart = System.currentTimeMillis();
                    retryCount++;
                    try {
                        final long delay = (long) (BASE_DELAY_MS *
                            Math.pow(MULTIPLIER, retryCount - 1));
                        Thread.sleep(delay);
                        final long actualDelay = System.currentTimeMillis() - delayStart;
                        if (retryCount <= NUM_TEST_RETRIES) {
                            delays[retryCount - 1].set(actualDelay);
                        }
                    }
                    catch (final InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Test interrupted", ie);
                    }
                }
                else {
                    throw e;
                }
            }
        }

        final long duration = System.currentTimeMillis() - startTime;

        assertNotNull(result, "Result should not be null after retries");
        assertEquals(3, attemptCount.get(), "Should have made 3 attempts");

        if (delays[0].get() > 0) {
            assertTrue(delays[0].get() >= BASE_DELAY_MS - 500,
                String.format("First retry delay should be ~%d ms, but got %d ms",
                    BASE_DELAY_MS, delays[0].get()));
        }
        if (delays[1].get() > 0) {
            final long actualSecondDelay = delays[1].get();
            final long expectedSecondDelay = (long) (BASE_DELAY_MS *
                MULTIPLIER);
            assertTrue(actualSecondDelay >= expectedSecondDelay - 500,
                String.format("Second retry delay should be ~%d ms, but got %d ms",
                    expectedSecondDelay, actualSecondDelay));
            final long expectedSecondDelaySquared = expectedSecondDelay * expectedSecondDelay;
            assertTrue(expectedSecondDelaySquared > 0,
                String.format("Expected second delay squared should be positive: %d", expectedSecondDelaySquared));
            assertTrue(actualSecondDelay > delays[0].get(),
                String.format("Second delay (%d ms) should be greater than first delay (%d ms)",
                    actualSecondDelay, delays[0].get()));
        }

        assertTrue(duration >= 2000,
            String.format("Expected delay of at least 2000 ms for exponential backoff, but got %d ms", duration));
    }

    @Test
    void shouldRetrySpecifiedNumberOfTimesAndThrowIfFailsTest()
        throws IOException {

        final OAuth2RetryInterceptor interceptor = OAuth2RetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();
        Mockito.when(chain.request()).thenReturn(request);

        Mockito.when(chain.proceed(request)).thenThrow(new IOException("Network error"));

        final IOException ex = assertThrows(IOException.class, () -> interceptor.intercept(chain));
        assertTrue(ex.getMessage().contains("Network error"));
    }

    @Test
    void shouldSucceedWithoutRetryIfNoExceptionTest()
        throws IOException {

        final OAuth2RetryInterceptor interceptor = OAuth2RetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();
        final Response response = Mockito.mock(Response.class);

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(request)).thenReturn(response);

        final Response result = interceptor.intercept(chain);

        assertEquals(response, result);

        // Should call only once since it succeeded
        Mockito.verify(chain, Mockito.times(1)).proceed(request);
    }
}
