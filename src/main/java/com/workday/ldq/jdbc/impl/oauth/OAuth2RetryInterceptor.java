/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

import javax.net.ssl.SSLHandshakeException;

/**
 * OkHttp retry interceptor for OAuth token requests with exponential backoff and jitter.
 * Uses exponential backoff with 50%-100% jitter to avoid thundering herd problems.
 * Delay calculation: {@code baseDelayMs * multiplier^attempt * jitter}, capped at {@code maxDelayMs}.
 *
 */
class OAuth2RetryInterceptor
    extends AbstractRetryInterceptor {

    private static final Logger LOG = Logger.getLogger(OAuth2RetryInterceptor.class.getName());

    private OAuth2RetryInterceptor(final long baseDelayMs,
                                   final long maxDelayMs,
                                   final int maxRetries,
                                   final double multiplier) {
        super(baseDelayMs, maxDelayMs, maxRetries, multiplier);
    }

    private OAuth2RetryInterceptor() {
        super();
    }

    /**
     * Creates a new OAuth2RetryInterceptor with the specified configuration.
     *
     * @param baseDelayMs the base delay in milliseconds for the first retry
     * @param maxDelayMs  the maximum allowed delay in milliseconds
     * @param maxRetries  the maximum number of retry attempts
     * @param multiplier  the exponential multiplier applied per attempt
     * @return a new OAuth2RetryInterceptor instance
     */
    public static OAuth2RetryInterceptor of(final long baseDelayMs,
                                            final long maxDelayMs,
                                            final int maxRetries,
                                            final double multiplier) {
        return new OAuth2RetryInterceptor(baseDelayMs, maxDelayMs, maxRetries, multiplier);
    }

    /**
     * Creates a new OAuth2RetryInterceptor with the default configuration.
     *
     * @return a new OAuth2RetryInterceptor instance
     */
    public static OAuth2RetryInterceptor get() {
        return new OAuth2RetryInterceptor();
    }

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    /**
     * Determines if an IOException or its nested causes represents a transient error worth retrying.
     * Safe to check nested as these are directly thrown by Auth endpoint
     *
     * @param e the IOException to evaluate
     * @return true if exception indicates transient failure else false
     */
    @Override
    protected boolean isRetryableException(final @Nonnull IOException e) {
        Throwable current = e;
        boolean retryable = false;

        while (current != null) {
            // 1. HARD STOP: Certificate issues are permanent; never retry.
            if (current instanceof CertificateException) {
                return false;
            }

            // 2. RETRY CANDIDATES: Flag transient network and SSL handshake failures.
            // Note: SocketException automatically includes ConnectException & NoRouteToHostException
            if (current instanceof SocketException ||
                current instanceof SocketTimeoutException ||
                current instanceof SSLHandshakeException) {
                retryable = true;
            }

            current = current.getCause();
        }
        return retryable;
    }

}
