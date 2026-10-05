/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.api;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_JDBC_DRIVER_NAME;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_CONNECTION_POOL_KEEP_ALIVE_SECONDS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_CONNECTION_POOL_MAX_IDLE_CONNECTIONS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_CONNECTION_POOL_KEEP_ALIVE_SECONDS_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_CONNECTION_POOL_MAX_IDLE_CONNECTIONS_PROP;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.JDBC_TRINO_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.JDBC_WORKDAY_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.VERSION_PATTERN;
import static com.workday.ldq.jdbc.impl.oauth.AuthModel.getRequiredByAuthModels;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTH_MODEL;
import static io.trino.jdbc.$internal.guava.base.MoreObjects.firstNonNull;
import static io.trino.jdbc.$internal.guava.base.Verify.verify;
import static java.lang.Integer.parseInt;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.Call;
import io.trino.jdbc.$internal.okhttp3.ConnectionPool;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;
import io.trino.jdbc.NonRegisteringTrinoDriver;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.LDQJdbcConnection;
import com.workday.ldq.jdbc.impl.oauth.AuthModel;
import com.workday.ldq.jdbc.impl.oauth.OAuth2Config;
import com.workday.ldq.jdbc.impl.oauth.OAuth2HttpClientFactory;
import com.workday.ldq.jdbc.impl.oauth.OAuth2TokenUtil;
import com.workday.ldq.jdbc.impl.oauth.TokenAuthInterceptor;
import com.workday.ldq.jdbc.impl.oauth.TokenManager;
import com.workday.ldq.jdbc.impl.oauth.TrinoRetryInterceptor;
import com.workday.ldq.jdbc.impl.property.DriverProperty;
import com.workday.ldq.jdbc.impl.property.DriverPropertyUtil;

/**
 * Custom Trino JDBC Driver with OAuth 2.0 authentication support.
 * <p>
 * This driver extends the standard Trino JDBC driver to add OAuth 2.0 authentication
 * with support for multiple authentication models {@link AuthModel}.
 *
 */
public final class LDQJdbcDriver
    extends NonRegisteringTrinoDriver {

    public static final String DRIVER_VERSION = loadDriverVersion();
    public static final int MAJOR_VERSION;
    public static final int MINOR_VERSION;

    public static final String LDQ_JDBC_DRIVER_USER_AGENT_INFO =
        String.format("%s/%s", LDQ_JDBC_DRIVER_NAME, DRIVER_VERSION);
    private static final Matcher matcher = VERSION_PATTERN.matcher(DRIVER_VERSION);

    // Single instance of HttpClient used to communicate with Auth Server.
    // Reduces overhead of creating new connections by reusing HttpClient. Since HttpClient does not store any state
    // information, this is safe.
    private final OkHttpClient httpClient = OAuth2HttpClientFactory.createOAuthHttpClient();
    private final ThreadLocal<ThreadContext> threadContext = new ThreadLocal<>();

    // Connection pool configuration for the Trino query client. Keep-alive is kept intentionally short so
    // that OkHttp never hands out a connection an intermediary proxy (e.g., Galahad, session duration 90s)
    // has already closed - pooled connections are proactively retired instead of failing to reuse.
    private static final long CONNECTION_POOL_KEEP_ALIVE_SECONDS = Long.getLong(
        HTTP_CONNECTION_POOL_KEEP_ALIVE_SECONDS_PROP, DEFAULT_CONNECTION_POOL_KEEP_ALIVE_SECONDS);
    private static final int CONNECTION_POOL_MAX_IDLE_CONNECTIONS = Integer.getInteger(
        HTTP_CONNECTION_POOL_MAX_IDLE_CONNECTIONS_PROP, DEFAULT_CONNECTION_POOL_MAX_IDLE_CONNECTIONS);
    // One pool per driver instance, reused across every Connection's clients, mirroring the pool
    // in delegate NonRegisteringTrinoDriver.
    private final ConnectionPool connectionPool = new ConnectionPool(
        CONNECTION_POOL_MAX_IDLE_CONNECTIONS, CONNECTION_POOL_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS);

    static {
        try {
            verify(matcher.find(), "Driver version is invalid: %s", DRIVER_VERSION);
            MAJOR_VERSION = parseInt(matcher.group(1));
            MINOR_VERSION = parseInt(firstNonNull(matcher.group(3), "0"));
            DriverManager.registerDriver(new LDQJdbcDriver());
        }
        catch (final Exception e) {
            throw new LDQJdbcDriverRuntimeException(
                String.format("Failed to register %s", LDQJdbcDriver.class.getName()), e);
        }
    }

    /**
     * Public no-arg constructor required for JDBC driver discovery via ServiceLoader.
     * JDBC clients use ServiceLoader to instantiate drivers.
     */
    public LDQJdbcDriver() {
        super();
    }

    @Override
    public Connection connect(final String url, final Properties info)
        throws SQLException {

        if (!acceptsURL(url)) {
            return null;
        }

        DriverPropertyUtil.checkRequiredProperties(info);
        final OAuth2Config config = new OAuth2Config(info);

        // Create the appropriate TokenManager based on the authentication model
        final TokenManager tokenManager = TokenManager.create(config, this.httpClient);

        // Store TokenManager and OAuth2Config in thread locals to be used in {@link #wrapClient} method
        // which is always called on the same thread before the connection is created.
        this.threadContext.set(new ThreadContext(tokenManager, config));
        boolean connectionSuccess = false;
        try {
            final Properties driverProperties = DriverPropertyUtil.setTrinoDriverProperties(info);
            // Use the delegate driver to establish the connection
            final Connection trinoConnection = super.connect(convertToTrinoUrl(url), driverProperties);
            if (trinoConnection == null) {
                return null;
            }
            connectionSuccess = true;
            // Wrap the Trino connection to return custom LDQ JDBC metadata
            return new LDQJdbcConnection(trinoConnection, this.threadContext.get().tokenMgr);
        }
        finally {
            if (!connectionSuccess) {
                this.threadContext.get().close();
            }
            this.threadContext.remove();
        }
    }

    @Override
    public boolean acceptsURL(final String url) {
        final boolean acceptsWorkday = url != null && url.startsWith(JDBC_WORKDAY_PREFIX);
        final boolean acceptsTrino = url != null && url.startsWith(JDBC_TRINO_PREFIX);
        return acceptsWorkday || acceptsTrino;
    }

    /**
     * Converts jdbc:workday: URL to jdbc:trino: URL for the parent driver.
     * If the URL already starts with jdbc:trino:, it is returned unchanged.
     *
     * @param url the JDBC URL
     * @return the converted URL
     */
    @VisibleForTesting
    String convertToTrinoUrl(final String url) {
        if (url == null) {
            return null;
        }
        if (url.startsWith(JDBC_WORKDAY_PREFIX)) {
            return url.replace(JDBC_WORKDAY_PREFIX, JDBC_TRINO_PREFIX);
        }
        return url;
    }

    @Override
    public int getMajorVersion() {
        return MAJOR_VERSION;
    }

    @Override
    public int getMinorVersion() {
        return MINOR_VERSION;
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(final String url, final Properties info) {
        return Arrays.stream(DriverProperty.values())
            .map(prop -> buildPropertyInfo(prop, info))
            .toArray(DriverPropertyInfo[]::new);
    }

    private static DriverPropertyInfo buildPropertyInfo(final DriverProperty property, final Properties info) {
        final String currentValue = info != null ? info.getProperty(property.getKey()) : null;
        final DriverPropertyInfo propertyInfo = new DriverPropertyInfo(property.getKey(), currentValue);

        if (property.getKey().equals(WD_AUTH_MODEL.getKey())) {
            propertyInfo.choices = Arrays.stream(AuthModel.values())
                .map(AuthModel::name)
                .toArray(String[]::new);
        }

        final String[] requiredByModels = getRequiredByAuthModels(property);
        propertyInfo.required = requiredByModels.length > 0;
        final String requiredTag = propertyInfo.required ? "[REQUIRED for " + String.join(", ", requiredByModels) + "] "
            : "[OPTIONAL]";
        propertyInfo.description = determineCategory(property) + requiredTag + property.getDescription();
        // For Boolean properties, provide choices for better UX in tools like DBeaver
        if (Boolean.class.equals(property.getType())) {
            propertyInfo.choices = new String[]{"true", "false"};
        }

        return propertyInfo;
    }

    private static String determineCategory(final DriverProperty prop) {
        if (prop.isUsedForOAuth() && prop.isUsedForTrino()) {
            return "[OAuth+Trino] ";
        }
        else if (prop.isUsedForOAuth()) {
            return "[OAuth] ";
        }
        else {
            return "[Trino] ";
        }
    }

    @Override
    public void close()
        throws IOException {
        try {
            super.close();
        }
        finally {
            OAuth2TokenUtil.shutdownExecutorService(this.httpClient.dispatcher().executorService());
            this.httpClient.connectionPool().evictAll();
            this.connectionPool.evictAll();
        }
    }

    @Override
    protected Call.Factory wrapClient(final OkHttpClient client) {
        final ThreadContext threadContext = this.threadContext.get();
        return client.newBuilder()
            .connectionPool(this.connectionPool)
            .addNetworkInterceptor(new TokenAuthInterceptor(threadContext.tokenMgr))
            .addInterceptor(TrinoRetryInterceptor.get())
            .build();
    }

    /**
     * Load driver version from multiple sources in order of preference:
     * JAR manifest Implementation-Version (works only in JAR)
     * else fallback to "0.0.0"
     */
    private static String loadDriverVersion() {
        final String manifestVersion = LDQJdbcDriver.class.getPackage().getImplementationVersion();
        if (manifestVersion != null) {
            return manifestVersion;
        }

        // Fallback version (mostly for tests, when JAR is not built)
        return "0.0.0";
    }

    private static class ThreadContext
        implements AutoCloseable {

        final TokenManager tokenMgr;
        final OAuth2Config oauthConfig;

        ThreadContext(final @Nonnull TokenManager tokenManager, final @Nonnull OAuth2Config oauth2Config) {
            this.tokenMgr = tokenManager;
            this.oauthConfig = oauth2Config;
        }

        @Override
        public void close() {
            this.tokenMgr.close();
        }
    }

}
