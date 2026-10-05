/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.AUTHORIZATION_HEADER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.BEARER_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_GATEWAY_PATH_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_EARLY_REFRESH_SKEW_MIN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.EARLY_REFRESH_SKEW_MIN_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.X_TENANT_HEADER;
import static com.workday.ldq.jdbc.impl.oauth.TokenAuthInterceptor.extractTenantFromToken;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.trino.jdbc.$internal.client.ProtocolHeaders;
import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.MediaType;
import io.trino.jdbc.$internal.okhttp3.Protocol;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;
import io.trino.jdbc.$internal.okhttp3.ResponseBody;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;
import com.workday.ldq.jdbc.impl.property.DriverProperty;

/**
 * Unit tests for TokenAuthInterceptor token management behaviors.
 *
 */
public class TokenAuthInterceptorTest {

    private static final String URL = "http://localhost/test";
    private static final Function<Request, Response> RESPONSE_FUNCTION_SUCCESS = req -> newResponse(req, HTTP_OK, "OK");
    private static final Function<Request, Response> RESPONSE_FUNCTION_UNAUTHORIZED = req -> newResponse(req,
        HTTP_UNAUTHORIZED, "Unauthorized");
    private static final int CONCURRENT_CALL_LIMIT = 10;

    @Test
    void oneClientOneIsuCreatesNewToken()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String newlyIssuedToken = "new-token-issued";

        final TokenManager mockTokenManager = mock(TokenManager.class);
        final BearerAccessToken accessToken = token(newlyIssuedToken, cfg.getClientId(), Duration.ofSeconds(300));
        final TokenResponse tokenResponse = new TokenResponse(accessToken, null);
        when(mockTokenManager.acquireToken()).thenReturn(tokenResponse);

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);
        // Create ArgumentCaptor to capture the Request when chain.proceed() is called
        final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            final String tenantId = "tenant-id";
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn(tenantId);

            try (Response resp = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp.code());
            }

            // Get the captured request and verify the header
            verify(chain, times(1)).proceed(requestCaptor.capture());
            final Request capturedRequest = requestCaptor.getValue();
            assertEquals(BEARER_PREFIX + newlyIssuedToken, capturedRequest.header(AUTHORIZATION_HEADER));
            assertEquals(tenantId, capturedRequest.header(X_TENANT_HEADER));
            assertEquals(String.format("%s=%s", LDQJdbcAuthnConstants.ACCESS_TOKEN_KEY, newlyIssuedToken),
                capturedRequest.header(
                    ProtocolHeaders.TRINO_HEADERS.requestExtraCredential()));

            verify(mockTokenManager, times(1)).acquireToken();
        }
    }

    @Test
    void oneClientOneIsuReusesToken()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String accessTokenIssued = "token-reuse";

        final TokenManager mockTokenManager = mock(TokenManager.class);
        final BearerAccessToken accessToken = token(accessTokenIssued, cfg.getClientId(), Duration.ofSeconds(600));
        final TokenResponse tokenResponse = new TokenResponse(accessToken, null);
        when(mockTokenManager.acquireToken()).thenReturn(tokenResponse);

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);
        final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            final String testTenantId = "tenant-id";
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn(testTenantId);
            try (Response resp1 = interceptor.intercept(chain);
                 Response resp2 = interceptor.intercept(chain);
                 Response resp3 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp1.code());
                assertEquals(HTTP_OK, resp2.code());
                assertEquals(HTTP_OK, resp3.code());
            }

            verify(chain, times(3)).proceed(requestCaptor.capture());
            verify(mockTokenManager, times(1)).acquireToken(); // Should only call once

            final List<Request> capturedRequest = requestCaptor.getAllValues();
            for (final Request req : capturedRequest) {
                assertEquals(BEARER_PREFIX + accessTokenIssued, req.header(AUTHORIZATION_HEADER));
                assertEquals(testTenantId, req.header(X_TENANT_HEADER));
                assertEquals(String.format("%s=%s", LDQJdbcAuthnConstants.ACCESS_TOKEN_KEY, accessTokenIssued), req
                    .header(
                        ProtocolHeaders.TRINO_HEADERS.requestExtraCredential()));
            }
        }
    }

    @Test
    void oneClientOneIsuRefreshesTokenWhenNearExpiry()
        throws Exception {
        System.setProperty(EARLY_REFRESH_SKEW_MIN_PROP, Long.toString(DEFAULT_EARLY_REFRESH_SKEW_MIN));
        try {
            // Set a large skew so that a short-lived token is immediately considered near-expiry
            final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
            final String initialToken = "token-short";
            final String refreshedToken = "token-refreshed";

            final TokenManager mockTokenManager = mock(TokenManager.class);

            // First call returns short-lived token
            final BearerAccessToken shortToken = token(initialToken, cfg.getClientId(), Duration.ofSeconds(5));
            final TokenResponse initialResponse = new TokenResponse(shortToken, null);

            // Second call returns refreshed token
            final BearerAccessToken longToken = token(refreshedToken, cfg.getClientId(), Duration.ofSeconds(600));
            final TokenResponse refreshedResponse = new TokenResponse(longToken, null);

            when(mockTokenManager.acquireToken())
                .thenReturn(initialResponse)
                .thenReturn(refreshedResponse);

            final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);

            final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);
            final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);

            try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
                org.mockito.Mockito.CALLS_REAL_METHODS)) {
                mockedStatic.when(() -> extractTenantFromToken(anyString()))
                    .thenReturn("mocked-tenant-id");
                try (Response resp1 = interceptor.intercept(chain);
                     Response resp2 = interceptor.intercept(chain)) {
                    assertEquals(HTTP_OK, resp1.code());
                    assertEquals(HTTP_OK, resp2.code());
                }
                verify(chain, times(2)).proceed(requestCaptor.capture());
                verify(mockTokenManager, times(2)).acquireToken(); // Initial + refresh

                final List<Request> capturedRequest = requestCaptor.getAllValues();
                assertEquals(BEARER_PREFIX + initialToken, capturedRequest.get(0).header(AUTHORIZATION_HEADER));
                assertEquals(BEARER_PREFIX + refreshedToken, capturedRequest.get(1).header(AUTHORIZATION_HEADER));
            }
        }
        finally {
            System.clearProperty(EARLY_REFRESH_SKEW_MIN_PROP);
        }
    }

    @Test
    void twoDifferentClientsDoNotShareToken()
        throws Exception {
        final OAuth2Config cfgA = new OAuth2Config(newProps("clientA", "isu1"));
        final OAuth2Config cfgB = new OAuth2Config(newProps("clientB", "isu2"));
        final String clientAToken = "token-clientA";
        final String clientBToken = "token-clientB";

        final TokenManager mockTokenManagerA = mock(TokenManager.class);
        final BearerAccessToken accessTokenA = token(clientAToken, cfgA.getClientId(), Duration.ofSeconds(600));
        final TokenResponse tokenResponseA = new TokenResponse(accessTokenA, null);
        when(mockTokenManagerA.acquireToken()).thenReturn(tokenResponseA);

        final TokenManager mockTokenManagerB = mock(TokenManager.class);
        final BearerAccessToken accessTokenB = token(clientBToken, cfgB.getClientId(), Duration.ofSeconds(600));
        final TokenResponse tokenResponseB = new TokenResponse(accessTokenB, null);
        when(mockTokenManagerB.acquireToken()).thenReturn(tokenResponseB);

        final TokenAuthInterceptor interceptorA = new TokenAuthInterceptor(mockTokenManagerA);
        final TokenAuthInterceptor interceptorB = new TokenAuthInterceptor(mockTokenManagerB);

        final Interceptor.Chain chain1 = createMockChain(RESPONSE_FUNCTION_SUCCESS);
        final Interceptor.Chain chain2 = createMockChain(RESPONSE_FUNCTION_SUCCESS);

        final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            final String tenantIdOne = "tenant-id-1";
            final String tenantIdTwo = "tenant-id-2";
            mockedStatic.when(() -> extractTenantFromToken(clientAToken)).thenReturn(tenantIdOne);
            mockedStatic.when(() -> extractTenantFromToken(clientBToken)).thenReturn(tenantIdTwo);
            try (Response resp1 = interceptorA.intercept(chain1);
                 Response resp2 = interceptorB.intercept(chain2)) {
                assertEquals(HTTP_OK, resp1.code());
                assertEquals(HTTP_OK, resp2.code());
            }

            verify(chain1, times(1)).proceed(requestCaptor.capture());
            verify(chain2, times(1)).proceed(requestCaptor.capture());

            assertEquals(BEARER_PREFIX + clientAToken,
                requestCaptor.getAllValues().get(0).header(AUTHORIZATION_HEADER));
            assertEquals(tenantIdOne, requestCaptor.getAllValues().get(0).header(X_TENANT_HEADER));
            assertEquals(BEARER_PREFIX + clientBToken,
                requestCaptor.getAllValues().get(1).header(AUTHORIZATION_HEADER));
            assertEquals(tenantIdTwo, requestCaptor.getAllValues().get(1).header(X_TENANT_HEADER));

            verify(mockTokenManagerA, times(1)).acquireToken();
            verify(mockTokenManagerB, times(1)).acquireToken();
        }
    }

    @Test
    void unauthorized401TriggersSingleRefreshAndRetry()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String initialToken = "token-old";
        final String refreshedToken = "new-token-issued";

        final TokenManager mockTokenManager = mock(TokenManager.class);

        // First call returns initial token
        final BearerAccessToken initialAccessToken = token(initialToken, cfg.getClientId(), Duration.ofSeconds(60));
        final TokenResponse initialResponse = new TokenResponse(initialAccessToken, null);

        // Second call returns refreshed token
        final BearerAccessToken refreshedAccessToken = token(refreshedToken, cfg.getClientId(), Duration.ofSeconds(
            600));
        final TokenResponse refreshedResponse = new TokenResponse(refreshedAccessToken, null);

        when(mockTokenManager.acquireToken())
            .thenReturn(initialResponse)
            .thenReturn(refreshedResponse);

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = mock(Interceptor.Chain.class);
        when(chain.request()).thenReturn(newRequest());
        when(chain.proceed(any(Request.class)))
            .thenAnswer(invocation -> {
                final Request req = invocation.getArgument(0);
                return RESPONSE_FUNCTION_UNAUTHORIZED.apply(req);
            })
            .thenAnswer(invocation -> {
                final Request req = invocation.getArgument(0);
                return RESPONSE_FUNCTION_SUCCESS.apply(req);
            });
        final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn("mocked-tenant-id");
            try (Response resp = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp.code());
            }
            verify(chain, times(2)).proceed(requestCaptor.capture());
            verify(mockTokenManager, times(2)).acquireToken(); // Initial + refresh after 401
            assertEquals(BEARER_PREFIX + initialToken,
                requestCaptor.getAllValues().get(0).header(AUTHORIZATION_HEADER));
            assertEquals(BEARER_PREFIX + refreshedToken,
                requestCaptor.getAllValues().get(1).header(AUTHORIZATION_HEADER));
        }
    }

    /**
     * Concurrency test: Multiple threads accessing the same TokenAuthInterceptor instance
     * should only trigger a single token fetch, not one per thread.
     */
    @Test
    void concurrentAccessToTokenOnlyFetchesOnce()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String sharedToken = "shared-token";
        final AtomicInteger tokenFetchCount = new AtomicInteger();

        final TokenManager mockTokenManager = mock(TokenManager.class);
        when(mockTokenManager.acquireToken()).thenAnswer(invocation -> {
            // check the number of times the supplier is called for token. Should only be called once
            tokenFetchCount.incrementAndGet();
            simulateRandomTokenFetch();
            final BearerAccessToken accessToken = token(sharedToken, cfg.getClientId(), Duration.ofSeconds(600));
            return new TokenResponse(accessToken, null);
        });

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final List<String> tokensUsed = executeConcurrentInterceptorCalls(interceptor, CONCURRENT_CALL_LIMIT);

        // Verify all threads got the same token
        for (final String tokenUsed : tokensUsed) {
            assertEquals(sharedToken, tokenUsed, "All threads should use the same token");
        }

        // Important: Token should only be fetched ONCE despite 10 concurrent threads
        assertEquals(1, tokenFetchCount.get(),
            "Token supplier should only be called once despite concurrent access");
    }

    /**
     * Concurrency test: Multiple threads accessing an expired token should trigger
     * only a single refresh, not one refresh per thread.
     */
    @Test
    void concurrentAccessToExpiredTokenOnlyRefreshesOnce()
        throws Exception {
        System.setProperty(EARLY_REFRESH_SKEW_MIN_PROP, Long.toString(DEFAULT_EARLY_REFRESH_SKEW_MIN));
        try {
            final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
            final String initialToken = "initial-token";
            final String refreshedToken = "refreshed-token";
            final AtomicInteger tokenFetchCount = new AtomicInteger();

            final TokenManager mockTokenManager = mock(TokenManager.class);
            when(mockTokenManager.acquireToken()).thenAnswer(invocation -> {
                final int callNumber = tokenFetchCount.getAndIncrement();
                simulateRandomTokenFetch();

                if (callNumber == 0) {
                    // First call: return expired token (expires in 5 seconds, but skew is 3 minutes)
                    final BearerAccessToken accessToken = token(initialToken, cfg.getClientId(), Duration.ofSeconds(5));
                    return new TokenResponse(accessToken, null);
                }
                else if (callNumber == 1) {
                    // Second call: return refreshed token
                    final BearerAccessToken accessToken = token(refreshedToken, cfg.getClientId(), Duration.ofSeconds(
                        600));
                    return new TokenResponse(accessToken, null);
                }
                // Additional calls: return refreshed token with unique name, none of these should be used
                final BearerAccessToken accessToken = token(refreshedToken + callNumber, cfg.getClientId(), Duration
                    .ofSeconds(600));
                return new TokenResponse(accessToken, null);
            });

            final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);

            // First call to populate the cache with expired token
            executeSingleInterceptorCallWithSuccessResponse(interceptor);

            // Now token is cached but expired. Multiple threads should trigger only ONE refresh.
            // this should surface any concurrency issues in the token refresh logic
            final List<String> tokensUsed = executeConcurrentInterceptorCalls(interceptor, CONCURRENT_CALL_LIMIT);

            // Verify all threads got the refreshed token
            for (final String tokenUsed : tokensUsed) {
                assertEquals(refreshedToken, tokenUsed, "All threads should use the refreshed token");
            }

            // Important: Token should be fetched exactly TWICE (initial + one refresh)
            // NOT (CONCURRENT_CALL_LIMIT + 1) refreshes from concurrent threads
            assertEquals(2, tokenFetchCount.get(),
                "Token supplier should be called exactly twice: initial fetch + one refresh");
        }
        finally {
            System.clearProperty(EARLY_REFRESH_SKEW_MIN_PROP);
        }
    }

    @Test
    void getModifiedRequestReturnsSameRequestWhenPrefixPresent() {
        final Request request = new Request.Builder()
            .url("http://localhost" + LDQ_GATEWAY_PATH_PREFIX + "/query")
            .get()
            .build();
        final Request result = TokenAuthInterceptor.getModifiedRequest(request);
        assertSame(request, result);
    }

    @Test
    void getModifiedRequestPrependsGatewayPathPrefixWhenAbsent() {
        final Request request = new Request.Builder().url("http://localhost/query").get().build();
        final Request result = TokenAuthInterceptor.getModifiedRequest(request);
        assertEquals(LDQ_GATEWAY_PATH_PREFIX + "/query", result.url().encodedPath());
    }

    private static Function<OAuth2Config, BearerAccessToken> tokenSupplier(final AtomicInteger calls,
                                                                           final String accessToken,
                                                                           final Duration tokenExpiry) {
        return auth2Config -> {
            calls.incrementAndGet();
            return token(accessToken, auth2Config.getClientId(), tokenExpiry);
        };
    }

    private static Properties newProps(final String clientId, final String isu) {
        final Properties prop = new Properties();
        prop.setProperty(DriverProperty.WD_AUTH_MODEL.getKey(), AuthModel.JWT_BEARER.name());
        prop.setProperty(DriverProperty.WD_CLIENT_ID.getKey(), clientId);
        prop.setProperty(DriverProperty.WD_ISU.getKey(), isu);
        prop.setProperty(DriverProperty.WD_TOKEN_ENDPOINT.getKey(), "https://example/token");
        prop.setProperty(DriverProperty.WD_SSL_PRIVATE_KEY.getKey(), "-----BEGIN PRIVATE KEY-----\n" +
            "MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCjPdW1xNqSZVAm\n");
        return prop;
    }

    private static BearerAccessToken token(final String token, final String clientId, final Duration expiration) {
        return BearerAccessToken.builder()
            .token(token)
            .expiryTime(Instant.now().plus(expiration).toEpochMilli())
            .clientId(clientId)
            .build();
    }

    private static Request newRequest() {
        return new Request.Builder().url(URL).get().build();
    }

    private static Response newResponse(final Request req, final int code, final String message) {
        final ResponseBody body = ResponseBody.create("", MediaType.parse("text/plain"));
        return new Response.Builder()
            .code(code)
            .message(message)
            .request(req)
            .protocol(Protocol.HTTP_1_1)
            .body(body)
            .build();
    }

    /**
     * Simulates a slow token fetch with variable delay to increase the chance of race conditions in concurrent tests.
     * Uses random sleep between 10-50ms to create realistic timing variations.
     */
    private static void simulateRandomTokenFetch() {
        try {
            // Random delay between 10-50ms to increase race condition probability
            final long delayMs = 10 + (long) (Math.random() * 40);
            Thread.sleep(delayMs);
        }
        catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Interceptor.Chain createMockChain(final Function<Request, Response> responseFunctionSuccess)
        throws IOException {
        final Interceptor.Chain chain = mock(Interceptor.Chain.class);
        when(chain.request()).thenReturn(newRequest());
        when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
            final Request req = invocation.getArgument(0);
            return responseFunctionSuccess.apply(req);
        });

        return chain;
    }

    /**
     * Executes a single interceptor call and verifies it succeeds.
     */
    private static void executeSingleInterceptorCallWithSuccessResponse(final TokenAuthInterceptor interceptor)
        throws Exception {
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn("mocked-tenant-id");
            try (Response resp = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp.code());
            }
        }
    }

    /**
     * Executes concurrent interceptor calls from multiple threads and returns the tokens used.
     * All threads start simultaneously to maximize contention.
     *
     * @param interceptor the interceptor to test
     * @param threadCount number of concurrent threads
     * @return list of tokens extracted from Authorization headers
     */
    private static List<String> executeConcurrentInterceptorCalls(final TokenAuthInterceptor interceptor,
                                                                  final int threadCount)
        throws Exception {
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch doneLatch = new CountDownLatch(threadCount);
        final List<Future<String>> futures = new ArrayList<>();

        try {
            // Submit tasks that all start at the same time
            for (int i = 0; i < threadCount; i++) {
                final Future<String> future = executor.submit(() -> {
                    try {
                        // Wait for all threads to be ready
                        startLatch.await();

                        // Each thread creates its own mock chain
                        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);

                        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
                            org.mockito.Mockito.CALLS_REAL_METHODS)) {
                            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                                .thenReturn("mocked-tenant-id");
                            // Call interceptor
                            try (Response resp = interceptor.intercept(chain)) {
                                assertEquals(HTTP_OK, resp.code());
                                // Extract token from Authorization header
                                final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
                                verify(chain, times(1)).proceed(requestCaptor.capture());
                                final String authHeader = requestCaptor.getValue().header(AUTHORIZATION_HEADER);
                                return authHeader != null ? authHeader.replace(BEARER_PREFIX, "") : null;
                            }
                        }
                    }
                    catch (final Exception e) {
                        throw new RuntimeException("Thread failed", e);
                    }
                    finally {
                        doneLatch.countDown();
                    }
                });
                futures.add(future);
            }

            // Start all threads simultaneously
            startLatch.countDown();

            // Wait for all threads to complete (with timeout)
            final boolean completed = doneLatch.await(CONCURRENT_CALL_LIMIT, TimeUnit.SECONDS);
            assertTrue(completed, "All threads should complete within timeout");

            // Collect all tokens used
            final List<String> tokensUsed = new ArrayList<>();
            for (final Future<String> future : futures) {
                tokensUsed.add(future.get());
            }
            return tokensUsed;
        }
        finally {
            executor.shutdown();
            if (!executor.awaitTermination(DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS, TimeUnit.MILLISECONDS)) {
                executor.shutdownNow();
            }
            assertTrue(executor.awaitTermination(DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS, TimeUnit.MILLISECONDS),
                "Executor should terminate within timeout");
        }
    }

    /**
     * Simulates the core scenario: an access token is obtained, it expires, and the interceptor
     * automatically uses the cached refresh token to obtain a new access token without requiring
     * a full re-authentication.
     * <p>
     * Uses a large early-refresh skew so the short-lived initial token is immediately considered
     * near-expiry on the second call, eliminating any real time wait.
     */
    @Test
    void expiredAccessTokenUsesRefreshTokenToGetNewToken()
        throws Exception {
        System.setProperty(EARLY_REFRESH_SKEW_MIN_PROP, "60"); // 60-minute skew forces any short-lived token near-expiry
        try {
            final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
            final String initialToken = "initial-access-token";
            final String refreshedToken = "refreshed-access-token";
            final String refreshToken = "refresh-token-12345";

            final TokenManager mockTokenManager = mock(TokenManager.class);

            // Initial token expires in 5 seconds — immediately near-expiry under 60-min skew
            final BearerAccessToken shortLivedToken = token(initialToken, cfg.getClientId(), Duration.ofSeconds(5));
            final TokenResponse initialResponse = new TokenResponse(shortLivedToken, refreshToken);

            // Token returned after using the refresh token
            final BearerAccessToken longLivedToken = token(refreshedToken, cfg.getClientId(), Duration.ofHours(1));
            final TokenResponse refreshedResponse = new TokenResponse(longLivedToken, "new-refresh-token");

            when(mockTokenManager.acquireToken()).thenReturn(initialResponse);
            when(mockTokenManager.getTokenUsingRefreshToken(refreshToken)).thenReturn(refreshedResponse);

            final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
            final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);
            final ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);

            try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
                org.mockito.Mockito.CALLS_REAL_METHODS)) {
                mockedStatic.when(() -> extractTenantFromToken(anyString()))
                    .thenReturn("mocked-tenant-id");

                // First call: acquires initial (short-lived) token
                try (Response resp1 = interceptor.intercept(chain)) {
                    assertEquals(HTTP_OK, resp1.code());
                }

                // Second call: initial token is near-expiry, so refresh token is used automatically
                try (Response resp2 = interceptor.intercept(chain)) {
                    assertEquals(HTTP_OK, resp2.code());
                }

                verify(chain, times(2)).proceed(requestCaptor.capture());
                verify(mockTokenManager, times(1)).acquireToken();
                verify(mockTokenManager, times(1)).getTokenUsingRefreshToken(refreshToken);

                final List<Request> capturedRequests = requestCaptor.getAllValues();
                assertEquals(BEARER_PREFIX + initialToken, capturedRequests.get(0).header(AUTHORIZATION_HEADER),
                    "First request should use the initial access token");
                assertEquals(BEARER_PREFIX + refreshedToken, capturedRequests.get(1).header(AUTHORIZATION_HEADER),
                    "Second request should use the refreshed access token obtained via refresh token");
            }
        }
        finally {
            System.clearProperty(EARLY_REFRESH_SKEW_MIN_PROP);
        }
    }

    // ========================================
    // Tests for refreshAndCacheToken() flow paths
    // ========================================

    @Test
    @DisplayName("refreshAndCacheToken - Path 1: No cached token, acquires new token")
    void testRefreshAndCacheToken_NoCachedToken_AcquiresNewToken()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String newToken = "new-access-token";
        final TokenManager mockTokenManager = mock(TokenManager.class);
        final BearerAccessToken accessToken = token(newToken, cfg.getClientId(), Duration.ofHours(1));
        final TokenResponse tokenResponse = new TokenResponse(accessToken, "refresh-token");

        when(mockTokenManager.acquireToken()).thenReturn(tokenResponse);

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn("mocked-tenant-id");

            try (Response resp = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp.code());
                verify(mockTokenManager, times(1)).acquireToken();
                verify(mockTokenManager, times(0)).getTokenUsingRefreshToken(anyString());
            }
        }
    }

    @Test
    @DisplayName("refreshAndCacheToken - Path 2: Cached token valid, reuses token")
    void testRefreshAndCacheToken_CachedTokenValid_ReusesToken()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String validToken = "valid-access-token";
        final TokenManager mockTokenManager = mock(TokenManager.class);
        final BearerAccessToken accessToken = token(validToken, cfg.getClientId(), Duration.ofHours(1));
        final TokenResponse tokenResponse = new TokenResponse(accessToken, "refresh-token");

        when(mockTokenManager.acquireToken()).thenReturn(tokenResponse);

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn("mocked-tenant-id");

            // First call to cache the token
            try (Response resp1 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp1.code());
            }

            // Second call should reuse cached token
            try (Response resp2 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp2.code());
                verify(mockTokenManager, times(1)).acquireToken(); // Only called once
                verify(mockTokenManager, times(0)).getTokenUsingRefreshToken(anyString());
            }
        }
    }

    @Test
    @DisplayName("refreshAndCacheToken - Path 3: Cached token expired with refresh token, uses refresh token")
    void testRefreshAndCacheToken_ExpiredTokenWithRefreshToken_UsesRefreshToken()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String expiredToken = "expired-access-token";
        final String refreshedToken = "refreshed-access-token";
        final String refreshToken = "refresh-token";

        final TokenManager mockTokenManager = mock(TokenManager.class);

        // Initial token (expired)
        final BearerAccessToken expiredAccessToken = token(expiredToken, cfg.getClientId(), Duration.ofSeconds(1));
        final TokenResponse initialResponse = new TokenResponse(expiredAccessToken, refreshToken);

        // Refreshed token
        final BearerAccessToken refreshedAccessToken = token(refreshedToken, cfg.getClientId(), Duration.ofHours(1));
        final TokenResponse refreshedResponse = new TokenResponse(refreshedAccessToken, "new-refresh-token");

        when(mockTokenManager.acquireToken()).thenReturn(initialResponse);
        when(mockTokenManager.getTokenUsingRefreshToken(anyString()))
            .thenReturn(refreshedResponse);

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn("mocked-tenant-id");

            // First call to cache the expired token
            try (Response resp1 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp1.code());
            }

            // Wait for token to expire
            Thread.sleep(2000);

            // Second call should use refresh token
            try (Response resp2 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp2.code());
                verify(mockTokenManager, times(1)).acquireToken();
                verify(mockTokenManager, times(1)).getTokenUsingRefreshToken(anyString());
            }
        }
    }

    @Test
    @DisplayName("refreshAndCacheToken - Path 4: Refresh token fails, falls back to acquireToken")
    void testRefreshAndCacheToken_RefreshTokenFails_FallsBackToAcquireToken()
        throws Exception {
        final OAuth2Config cfg = new OAuth2Config(newProps("clientA", "isu1"));
        final String expiredToken = "expired-access-token";
        final String newToken = "new-access-token";
        final String refreshToken = "refresh-token";

        final TokenManager mockTokenManager = mock(TokenManager.class);

        // Initial token (expired)
        final BearerAccessToken expiredAccessToken = token(expiredToken, cfg.getClientId(), Duration.ofSeconds(1));
        final TokenResponse initialResponse = new TokenResponse(expiredAccessToken, refreshToken);

        // New token after fallback
        final BearerAccessToken newAccessToken = token(newToken, cfg.getClientId(), Duration.ofHours(1));
        final TokenResponse newResponse = new TokenResponse(newAccessToken, "new-refresh-token");

        when(mockTokenManager.acquireToken())
            .thenReturn(initialResponse)  // First call
            .thenReturn(newResponse);      // Fallback call

        // Refresh token fails
        when(mockTokenManager.getTokenUsingRefreshToken(anyString()))
            .thenThrow(new LDQJdbcDriverRuntimeException("Refresh token expired"));

        final TokenAuthInterceptor interceptor = new TokenAuthInterceptor(mockTokenManager);
        final Interceptor.Chain chain = createMockChain(RESPONSE_FUNCTION_SUCCESS);

        try (MockedStatic<TokenAuthInterceptor> mockedStatic = mockStatic(TokenAuthInterceptor.class,
            org.mockito.Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> extractTenantFromToken(anyString()))
                .thenReturn("mocked-tenant-id");

            // First call to cache the expired token
            try (Response resp1 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp1.code());
            }

            // Wait for token to expire
            Thread.sleep(2000);

            //  Second call should try refresh token, fail, then fall back to acquireToken
            try (Response resp2 = interceptor.intercept(chain)) {
                assertEquals(HTTP_OK, resp2.code());
                verify(mockTokenManager, times(2)).acquireToken(); // Initial + fallback
                verify(mockTokenManager, times(1)).getTokenUsingRefreshToken(anyString());
            }
        }
    }
}
