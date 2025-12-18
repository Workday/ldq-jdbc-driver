/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.BAD_GATEWAY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_BACKOFF_MULTIPLIER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_MAX_RETRIES;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_MAX_RETRY_DELAY_MILLIS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_RETRY_DELAY_MILLIS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GATEWAY_TIMEOUT;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_RETRY_BACKOFF_MULTIPLIER_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_RETRY_DELAY_MILLIS_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_RETRY_MAX_DELAY_MILLIS_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_RETRY_MAX_RETRIES_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.SERVICE_UNAVAILABLE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TOO_MANY_REQUESTS;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * Abstract base class for OkHttp retry interceptors with exponential backoff.
 * <p>
 * Provides common retry loop logic and backoff calculation. Subclasses define:
 * <ul>
 * <li>{@link #shouldRetry(int, Request)} - Which HTTP status codes (and, if relevant, request methods)
 * trigger retries</li>
 * <li>{@link #isRetryableException(IOException)} - Which exceptions are transient</li>
 * <li>{@link #getLogger()} - Logger instance for the subclass</li>
 * </ul>
 * <p>
 * The retry loop attempts requests up to {@code maxRetries plus 1} times (initial attempt plus retries).
 * Between attempts, the interceptor sleeps with exponential backoff calculated by
 * {@link #calculateBackoffDelay(int)}.
 *
 */
abstract class AbstractRetryInterceptor
    implements Interceptor {

    private static final int MAX_RETRIES = Integer.getInteger(
        HTTP_RETRY_MAX_RETRIES_PROP, DEFAULT_MAX_RETRIES);
    private static final long RETRY_DELAY_MILLIS = Long.getLong(
        HTTP_RETRY_DELAY_MILLIS_PROP, DEFAULT_RETRY_DELAY_MILLIS);
    private static final double BACKOFF_MULTIPLIER = Double.parseDouble(
        System.getProperty(HTTP_RETRY_BACKOFF_MULTIPLIER_PROP,
            String.valueOf(DEFAULT_BACKOFF_MULTIPLIER)));
    private static final long MAX_RETRY_DELAY_MILLIS = Long.getLong(
        HTTP_RETRY_MAX_DELAY_MILLIS_PROP, DEFAULT_MAX_RETRY_DELAY_MILLIS);

    protected final long baseDelayMs;
    protected final long maxDelayMs;
    protected final int maxRetries;
    protected final double multiplier;

    protected AbstractRetryInterceptor(final long baseDelayMs,
                                       final long maxDelayMs,
                                       final int maxRetries,
                                       final double multiplier) {
        this.baseDelayMs = baseDelayMs;
        this.maxDelayMs = maxDelayMs;
        this.maxRetries = maxRetries;
        this.multiplier = multiplier;
    }

    protected AbstractRetryInterceptor() {
        this.baseDelayMs = RETRY_DELAY_MILLIS;
        this.maxDelayMs = MAX_RETRY_DELAY_MILLIS;
        this.maxRetries = MAX_RETRIES;
        this.multiplier = BACKOFF_MULTIPLIER;
    }

    /**
     * Returns the logger instance for this interceptor.
     * Subclasses must provide their own logger.
     *
     * @return the logger instance
     */
    protected abstract Logger getLogger();

    /**
     * Determines whether a non-successful response should trigger a resend of the given request based on the status
     * code and request method.
     * @param statusCode the HTTP status code returned
     * @param request the request that produced the response (Potentially for filtering based on request method)
     * @return true if the request should be resent d
     */
    protected boolean shouldRetry(final int statusCode, final Request request) {
        return statusCode == TOO_MANY_REQUESTS ||
            statusCode == BAD_GATEWAY ||
            statusCode == SERVICE_UNAVAILABLE ||
            statusCode == GATEWAY_TIMEOUT;
    }

    /**
     * Determines if an IOException represents a transient error worth retrying.
     *
     * @param e the IOException to evaluate
     * @return true if the exception indicates a transient failure
     */
    protected abstract boolean isRetryableException(@Nonnull IOException e);

    @Override
    public Response intercept(final Chain chain)
        throws IOException {
        final Request request = chain.request();

        for (int attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                final Response response = chain.proceed(request);
                if (response.isSuccessful()) {
                    return response;
                }

                if (attempt != this.maxRetries && shouldRetry(response.code(), request)) {
                    getLogger().warning("Retry attempt [" + (attempt + 1) + "/" + this.maxRetries +
                        "]: Received HTTP status [" + response.code() + "]. Retrying...");
                    response.close();
                    sleepWithBackoff(attempt);
                    continue;
                }
                return response;
            }
            catch (final IOException e) {
                if (!isRetryableException(e)) {
                    throw e;
                }
                if (attempt == this.maxRetries) {
                    throw new IOException("Failed to execute request after [" + this.maxRetries +
                        "] attempts - Failed with error: " + e.getMessage(), e);
                }
                sleepWithBackoff(attempt);
            }
        }

        throw new IOException("Failed to execute request after [" + this.maxRetries + "] attempts");
    }

    /**
     * Sleeps with exponential backoff. Subclasses can override to customize behavior.
     *
     * @param attempt the current attempt number (0-based)
     * @throws IOException if the sleep is interrupted
     */
    protected void sleepWithBackoff(final int attempt)
        throws IOException {
        final long delayMs = calculateBackoffDelay(attempt);
        getLogger().info("Retry attempt [" + (attempt + 1) + "]: sleeping for [" + delayMs + "] ms");
        sleep(delayMs);
    }

    /**
     * Calculates the backoff delay. Subclasses can override to add jitter.
     * Default implementation: {@code min(baseDelayMs * multiplier^attempt, maxDelayMs)}.
     *
     * @param attempt the current attempt number (0-based)
     * @return the delay in milliseconds
     */
    @VisibleForTesting
    protected long calculateBackoffDelay(final int attempt) {
        final double jitter = 0.5 + Math.random() * 0.5;
        return (long) Math.min(this.baseDelayMs * Math.pow(this.multiplier, attempt) * jitter, this.maxDelayMs);
    }

    /**
     * Sleeps the current thread. Subclasses can override error handling.
     *
     * @param delayMs the duration to sleep in milliseconds
     * @throws IOException if the sleep is interrupted
     */
    @VisibleForTesting
    protected void sleep(final long delayMs)
        throws IOException {
        try {
            Thread.sleep(delayMs);
        }
        catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Retry interrupted", e);
        }
    }
}
