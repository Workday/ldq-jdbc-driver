/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GATEWAY_TIMEOUT;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_METHOD_POST;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.SERVICE_UNAVAILABLE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TOO_MANY_REQUESTS;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.Request;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

import javax.net.ssl.SSLHandshakeException;

/**
 * OkHttp retry interceptor for Trino JDBC requests with exponential backoff.
 * <p>
 * Retried for specific exceptions that occur before any part of the HTTP request is sent, and so resending is
 * always safe. Do not add any other exceptions unless it is evaluated to be safe.
 * <ul>
 * <li>SSL handshake failures ({@link SSLHandshakeException})</li>
 * <li>Connection failures ({@link ConnectException})</li>
 * <li>DNS resolution failures ({@link UnknownHostException})</li>
 * </ul>
 * <p>
 * Retried only for non {@code POST} requests (e.g., polling {@code nextUri}); never for a statement-submission
 * {@code POST}: a 429/503/504 response can arrive after the server already received and started acting
 * on the request (e.g., a proxy timing out while the coordinator is still executing a submitted
 * statement), so resending a {@code POST} request on one of these could duplicate a non-idempotent
 * writing.
 * <ul>
 * <li>HTTP 429 (Too Many Requests)</li>
 * <li>HTTP 503 (Service Unavailable)</li>
 * <li>HTTP 504 (Gateway Timeout)</li>
 * </ul>
 * <p>
 * Uses exponential backoff with jitter.
 *
 */
public final class TrinoRetryInterceptor
    extends AbstractRetryInterceptor {

    private static final Logger LOG = Logger.getLogger(TrinoRetryInterceptor.class.getName());

    private TrinoRetryInterceptor(final long baseDelayMs,
                                  final long maxDelayMs,
                                  final int maxRetries,
                                  final double multiplier) {
        super(baseDelayMs, maxDelayMs, maxRetries, multiplier);
    }

    private TrinoRetryInterceptor() {
        super();
    }

    /**
     * Creates a new TrinoRetryInterceptor with the specified configuration.
     *
     * @param baseDelayMs the base delay in milliseconds for the first retry
     * @param maxDelayMs  the maximum allowed delay in milliseconds
     * @param maxRetries  the maximum number of retry attempts
     * @param multiplier  the exponential multiplier applied per attempt
     * @return a new TrinoRetryInterceptor instance
     */
    public static TrinoRetryInterceptor of(final long baseDelayMs,
                                           final long maxDelayMs,
                                           final int maxRetries,
                                           final double multiplier) {
        return new TrinoRetryInterceptor(baseDelayMs, maxDelayMs, maxRetries, multiplier);
    }

    /**
     * Creates a new TrinoRetryInterceptor with the default configuration.
     *
     * @return a new TrinoRetryInterceptor instance
     */
    public static TrinoRetryInterceptor get() {
        return new TrinoRetryInterceptor();
    }

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    protected boolean shouldRetry(final int statusCode, final Request request) {
        // Currently, LDQ supports only SELECT queries, so resending a POST method could be safe.
        // However, excluding POST requests for safety.
        // Non-POST requests (e.g., polling nextUri) carry no such risk.
        if (HTTP_METHOD_POST.equalsIgnoreCase(request.method())) {
            return false;
        }

        // Retry only on specific server errors and rate limiting
        return statusCode == TOO_MANY_REQUESTS ||
            statusCode == SERVICE_UNAVAILABLE ||
            statusCode == GATEWAY_TIMEOUT;
    }

    @Override
    protected boolean isRetryableException(final @Nonnull IOException e) {
        // Retry on SSL handshake failures but not if the cause is CertificateException
        if (e instanceof SSLHandshakeException) {
            Throwable exceptionCause = e.getCause();
            while (exceptionCause != null) {
                if (exceptionCause instanceof CertificateException) {
                    return false;
                }
                exceptionCause = exceptionCause.getCause();
            }
            return true;
        }
        // Retry on connection-establishment failures. Neither of these can occur after any HTTP bytes
        // have been sent, so retrying is always safe, even for non-idempotent requests.
        // Not checking nested cause as OkHttp throws these exceptions.
        // Also, we do not want to retry as they could have been retried earlier.
        return e instanceof ConnectException ||
            e instanceof UnknownHostException ||
            e instanceof NoRouteToHostException;
    }

}
