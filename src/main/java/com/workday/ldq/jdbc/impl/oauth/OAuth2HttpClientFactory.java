/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_CONNECTION_POOL_KEEP_ALIVE_SECONDS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_CONNECTION_POOL_MAX_IDLE_CONNECTIONS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_HTTP_CONNECT_TIMEOUT_MILLIS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_HTTP_READ_TIMEOUT_MILLIS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_HTTP_REQUEST_TIMEOUT_MILLIS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_INITIALIZE_HTTP_CLIENT;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_CONNECTION_POOL_KEEP_ALIVE_SECONDS_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_CONNECTION_POOL_MAX_IDLE_CONNECTIONS_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OAUTH_HTTP_CONNECT_TIMEOUT_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OAUTH_HTTP_READ_TIMEOUT_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OAUTH_HTTP_REQUEST_TIMEOUT_PROP;

import io.trino.jdbc.$internal.okhttp3.ConnectionPool;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;

import java.util.concurrent.TimeUnit;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Factory for creating configured OkHttpClient instances for OAuth operations.
 * <p>
 * Provides consistent HTTP client configuration across all OAuth clients with:
 * <ul>
 * <li>Configurable timeouts (connect, read, write)</li>
 * <li>Connection retry on failure</li>
 * <li>Exponential backoff retry interceptor</li>
 * </ul>
 * <p>
 * Configuration is controlled via system properties:
 * <ul>
 * <li>{@code wd.oauth.http-connect-timeout} - Connection timeout in milliseconds</li>
 * <li>{@code wd.oauth.http-read-timeout} - Read timeout in milliseconds</li>
 * <li>{@code wd.oauth.http-request-timeout} - Request timeout in milliseconds</li>
 * <li>{@code wd.http.retry.max-retries} - Maximum number of retry attempts</li>
 * <li>{@code wd.http.retry.delay-millis} - Base delay between retries</li>
 * <li>{@code wd.http.retry.max-delay-millis} - Maximum delay between retries</li>
 * <li>{@code wd.http.retry.backoff-multiplier} - Exponential backoff multiplier</li>
 * </ul>
 *
 */
public final class OAuth2HttpClientFactory {

    // HTTP timeout configuration
    private static final int CONNECT_TIMEOUT = Integer.getInteger(
        OAUTH_HTTP_CONNECT_TIMEOUT_PROP, DEFAULT_HTTP_CONNECT_TIMEOUT_MILLIS);
    private static final int READ_TIMEOUT = Integer.getInteger(
        OAUTH_HTTP_READ_TIMEOUT_PROP, DEFAULT_HTTP_READ_TIMEOUT_MILLIS);
    private static final int REQUEST_TIMEOUT = Integer.getInteger(
        OAUTH_HTTP_REQUEST_TIMEOUT_PROP, DEFAULT_HTTP_REQUEST_TIMEOUT_MILLIS);
    private static final long CONNECTION_POOL_KEEP_ALIVE_SECONDS = Long.getLong(
        HTTP_CONNECTION_POOL_KEEP_ALIVE_SECONDS_PROP, DEFAULT_CONNECTION_POOL_KEEP_ALIVE_SECONDS);
    private static final int CONNECTION_POOL_MAX_IDLE_CONNECTIONS = Integer.getInteger(
        HTTP_CONNECTION_POOL_MAX_IDLE_CONNECTIONS_PROP, DEFAULT_CONNECTION_POOL_MAX_IDLE_CONNECTIONS);

    private OAuth2HttpClientFactory() {
        // Utility class - prevent instantiation
    }

    /**
     * Creates OkHttpClient with standard OAuth configuration.
     * Do not store any auth-specific state information in this HTTP client.
     * <p>
     * The client is configured with:
     * <ul>
     * <li>Timeouts for connect, read, and write operations</li>
     * <li>Automatic retry on connection failures</li>
     * <li>Exponential backoff retry interceptor for transient errors (429, 5xx)</li>
     * </ul>
     *
     * @return configured OkHttpClient instance
     * @throws LDQJdbcDriverRuntimeException if client creation fails
     */
    public static OkHttpClient createOAuthHttpClient()
        throws LDQJdbcDriverRuntimeException {
        try {
            return new OkHttpClient.Builder()
                .connectionPool(
                    new ConnectionPool(
                        CONNECTION_POOL_MAX_IDLE_CONNECTIONS,
                        CONNECTION_POOL_KEEP_ALIVE_SECONDS,
                        TimeUnit.SECONDS))
                .connectTimeout(CONNECT_TIMEOUT, TimeUnit.MILLISECONDS)
                .readTimeout(READ_TIMEOUT, TimeUnit.MILLISECONDS)
                .writeTimeout(REQUEST_TIMEOUT, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(true)
                .addInterceptor(OAuth2RetryInterceptor.get())
                .build();
        }
        catch (final Exception e) {
            throw new LDQJdbcDriverRuntimeException(FAILED_TO_INITIALIZE_HTTP_CLIENT, e);
        }
    }
}
