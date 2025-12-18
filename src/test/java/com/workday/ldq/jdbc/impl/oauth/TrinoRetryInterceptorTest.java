/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.BAD_GATEWAY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GATEWAY_TIMEOUT;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.SERVICE_UNAVAILABLE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TOO_MANY_REQUESTS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.trino.jdbc.$internal.okhttp3.FormBody;
import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;

import java.io.IOException;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

/**
 * Unit tests for {@link TrinoRetryInterceptor}.
 *
 */
class TrinoRetryInterceptorTest {

    private static final String TEST_ENDPOINT = "https://test.example.com";
    private static final long BASE_DELAY_MS = 1L;
    private static final long MAX_DELAY_MS = 5L;
    private static final int MAX_RETRIES = 3;
    private static final double MULTIPLIER = 2.0;

    @Test
    void shouldRecoverFromSslHandshakeExceptionOnReconnect()
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();
        final Response response = Mockito.mock(Response.class);

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(request))
            .thenThrow(new SSLHandshakeException("Remote host terminated the handshake"))
            .thenReturn(response);

        final Response result = interceptor.intercept(chain);

        assertEquals(response, result);
        Mockito.verify(chain, Mockito.times(2)).proceed(request);
    }

    @Test
    void shouldNotRetrySslHandshakeExceptionCausedByCertificateException()
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();
        final SSLHandshakeException untrustedCertException = new SSLHandshakeException("PKIX path validation failed");
        untrustedCertException.initCause(new CertificateException("Untrusted certificate"));

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(request)).thenThrow(untrustedCertException);

        final IOException thrown = assertThrows(IOException.class, () -> interceptor.intercept(chain));

        assertTrue(thrown instanceof SSLHandshakeException);
        Mockito.verify(chain, Mockito.times(1)).proceed(request);
    }

    @Test
    void shouldThrowAfterExhaustingRetriesOnRepeatedSslHandshakeException()
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(request))
            .thenThrow(new SSLHandshakeException("Remote host terminated the handshake"));

        assertThrows(IOException.class, () -> interceptor.intercept(chain));

        Mockito.verify(chain, Mockito.times(MAX_RETRIES + 1)).proceed(request);
    }

    @Test
    void shouldRecoverFromConnectExceptionOnReconnect()
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();
        final Response response = Mockito.mock(Response.class);

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(request))
            .thenThrow(new ConnectException("Connection refused"))
            .thenReturn(response);

        final Response result = interceptor.intercept(chain);

        assertEquals(response, result);
        Mockito.verify(chain, Mockito.times(2)).proceed(request);
    }

    @Test
    void shouldRecoverFromUnknownHostExceptionOnReconnect()
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).build();
        final Response response = Mockito.mock(Response.class);

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(request))
            .thenThrow(new UnknownHostException("test.example.com"))
            .thenReturn(response);

        final Response result = interceptor.intercept(chain);

        assertEquals(response, result);
        Mockito.verify(chain, Mockito.times(2)).proceed(request);
    }

    @ParameterizedTest
    @ValueSource(ints = {SERVICE_UNAVAILABLE, TOO_MANY_REQUESTS, GATEWAY_TIMEOUT})
    void shouldRetryOnTransientErrorResponseForGetRequest(final int statusCode)
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder().url(TEST_ENDPOINT).get().build();
        final Response failedResponse = Mockito.mock(Response.class);
        final Response successResponse = Mockito.mock(Response.class);

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(failedResponse.isSuccessful()).thenReturn(false);
        Mockito.when(failedResponse.code()).thenReturn(statusCode);
        Mockito.when(successResponse.isSuccessful()).thenReturn(true);
        Mockito.when(chain.proceed(request))
            .thenReturn(failedResponse)
            .thenReturn(successResponse);

        final Response result = interceptor.intercept(chain);

        assertEquals(successResponse, result);
        Mockito.verify(chain, Mockito.times(2)).proceed(request);
    }

    @ParameterizedTest
    @ValueSource(ints = {BAD_GATEWAY, SERVICE_UNAVAILABLE, TOO_MANY_REQUESTS, GATEWAY_TIMEOUT})
    void shouldNotRetryOnTransientErrorResponseForPostRequest(final int statusCode)
        throws IOException {
        final TrinoRetryInterceptor interceptor = TrinoRetryInterceptor.of(
            BASE_DELAY_MS, MAX_DELAY_MS, MAX_RETRIES, MULTIPLIER);

        final Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        final Request request = new Request.Builder()
            .url(TEST_ENDPOINT)
            .post(new FormBody.Builder().build())
            .build();
        final Response failedResponse = Mockito.mock(Response.class);

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(failedResponse.isSuccessful()).thenReturn(false);
        Mockito.when(failedResponse.code()).thenReturn(statusCode);
        Mockito.when(chain.proceed(request)).thenReturn(failedResponse);

        final Response result = interceptor.intercept(chain);

        assertEquals(failedResponse, result);
        Mockito.verify(chain, Mockito.times(1)).proceed(request);
    }
}
