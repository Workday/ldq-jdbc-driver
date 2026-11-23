/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package com.workday.ldq.jdbc.api;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.AUTHORIZATION_HEADER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.BEARER_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_GATEWAY_PATH_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TENANT_CLAIM_NAME;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.impl.oauth.OAuth2Config;
import com.workday.ldq.jdbc.impl.oauth.TokenAuthInterceptor;
import com.workday.ldq.jdbc.impl.oauth.TokenManager;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Verifies the OkHttp client built by {@link LDQJdbcDriver#wrapClient} against a real HTTP server,
 * so that OkHttp's interceptor-chain rules (which a mocked {@code Chain} does not enforce) are exercised.
 */
@Execution(ExecutionMode.CONCURRENT)
public class LDQJdbcDriverHttpClientTest {

    private static final String SECRET = "test-secret-key-for-jwt-signing-32-bytes-long"; // gitleaks:allow
    private static final String TENANT = "test-tenant";

    private MockWebServer server;
    private TokenManager tokenManager;
    private LDQJdbcDriver driver;

    @BeforeEach
    void setUp()
        throws Exception {
        this.server = new MockWebServer();
        this.server.start();
        this.tokenManager = mock(TokenManager.class);
        this.driver = new LDQJdbcDriver();
        setThreadContext(this.driver, this.tokenManager);
    }

    @AfterEach
    void tearDown()
        throws Exception {
        try {
            if (this.driver != null) {
                cleanThreadContext(this.driver);
            }
        }
        finally {
            if (this.server != null) {
                this.server.close();
            }
        }
    }

    @Test
    @DisplayName("401 response is refreshed and retried through the real OkHttp chain")
    void unauthorizedResponseIsRetriedWithRefreshedToken()
        throws Exception {
        // A token that is already near expiry is never reused, so each acquireToken() call yields a new one
        final String initialToken = jwt(Instant.now().plusSeconds(10));
        final String refreshedToken = jwt(Instant.now().plusSeconds(3600));
        when(this.tokenManager.acquireToken(any()))
            .thenReturn(new TokenResponse(accessToken(initialToken, Instant.now().plusSeconds(10)), null))
            .thenReturn(new TokenResponse(accessToken(refreshedToken, Instant.now().plusSeconds(3600)), null));

        this.server.enqueue(new MockResponse.Builder().code(HTTP_UNAUTHORIZED).build());
        this.server.enqueue(new MockResponse.Builder().code(HTTP_OK).build());

        final OkHttpClient client = (OkHttpClient) this.driver.wrapClient(new OkHttpClient());
        final Request request = new Request.Builder()
            .url(this.server.url("/v1/statement").toString())
            .build();

        try (Response response = client.newCall(request).execute()) {
            assertEquals(HTTP_OK, response.code());
        }

        verify(this.tokenManager, times(2)).acquireToken(any());

        final RecordedRequest first = this.server.takeRequest(5, TimeUnit.SECONDS);
        final RecordedRequest second = this.server.takeRequest(5, TimeUnit.SECONDS);

        assertNotNull(first, "First request should have reached MockWebServer");
        assertNotNull(second, "Retry request should have reached MockWebServer");

        assertEquals(BEARER_PREFIX + initialToken, first.getHeaders().get(AUTHORIZATION_HEADER));
        assertEquals(LDQ_GATEWAY_PATH_PREFIX + "/v1/statement", first.getUrl().encodedPath());

        assertEquals(BEARER_PREFIX + refreshedToken, second.getHeaders().get(AUTHORIZATION_HEADER));
        assertEquals(LDQ_GATEWAY_PATH_PREFIX + "/v1/statement", second.getUrl().encodedPath());
    }

    @Test
    @DisplayName("TokenAuthInterceptor is registered as an application interceptor, not a network interceptor")
    void tokenInterceptorIsNotANetworkInterceptor() {
        // Must be an application interceptor: it calls chain.proceed() again on a 401, which OkHttp
        // forbids for network interceptors ("must call proceed() exactly once").
        final OkHttpClient client = (OkHttpClient) this.driver.wrapClient(new OkHttpClient());

        assertTrue(client.interceptors().stream().anyMatch(TokenAuthInterceptor.class::isInstance));
        assertTrue(client.networkInterceptors().stream().noneMatch(TokenAuthInterceptor.class::isInstance));
    }

    // HELPERS

    private static void setThreadContext(@Nonnull final LDQJdbcDriver driver,
                                         @Nonnull final TokenManager tokenManager)
        throws Exception {
        final Class<?> contextClass = Class.forName(LDQJdbcDriver.class.getName() + "$ThreadContext");
        final Constructor<?> constructor = contextClass.getDeclaredConstructor(TokenManager.class, OAuth2Config.class,
            boolean.class);
        constructor.setAccessible(true);
        final Object context = constructor.newInstance(tokenManager, mock(OAuth2Config.class), false);

        final Field field = LDQJdbcDriver.class.getDeclaredField("threadContext");
        field.setAccessible(true);
        ((ThreadLocal<Object>) field.get(driver)).set(context);
    }

    private static void cleanThreadContext(final LDQJdbcDriver driver)
        throws Exception {
        final Field field = LDQJdbcDriver.class.getDeclaredField("threadContext");
        field.setAccessible(true);
        ((ThreadLocal<?>) field.get(driver)).remove();
    }

    private static BearerAccessToken accessToken(@Nonnull final String token, @Nonnull final Instant expiry) {
        return BearerAccessToken.builder()
            .token(token)
            .expiryTime(expiry.toEpochMilli())
            .clientId("client")
            .build();
    }

    private static String jwt(@Nonnull final Instant expiry)
        throws Exception {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("subject")
            .expirationTime(Date.from(expiry))
            .jwtID(UUID.randomUUID().toString())
            .claim(TENANT_CLAIM_NAME, TENANT)
            .build();
        final SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(SECRET));
        return jwt.serialize();
    }
}
