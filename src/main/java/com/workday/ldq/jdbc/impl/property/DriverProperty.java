/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.property;

import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;
import static io.trino.jdbc.$internal.client.uri.PropertyName.SESSION_PROPERTIES;
import static io.trino.jdbc.$internal.client.uri.PropertyName.TIMEOUT;

import io.trino.jdbc.$internal.client.uri.PropertyName;

import com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants;

/**
 * Unified property definitions for both OAuth and Trino driver.
 * Single source of truth for all driver properties
 * Each property knows:
 * - Its external name (LDQ JDBC driver property name)
 * - Its Trino property name (if applicable)
 * - Where it's used (OAuth, Trino)
 * - Its default value (if any), mostly used for non-client specific properties to drive behavior.
 * - Its type and parser function for type-safe access
 *
 */
public enum DriverProperty {

    // OAUTH-ONLY PROPERTIES

    /**
     * OAuth 2.0 token endpoint URL.
     */
    WD_TOKEN_ENDPOINT(
        LDQJdbcAuthnConstants.WD_TOKEN_ENDPOINT_KEY,
        LDQJdbcAuthnConstants.WD_TOKEN_ENDPOINT_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    /**
     * OAuth 2.0 client ID, ID of the client registered with Workday.
     */
    WD_CLIENT_ID(
        LDQJdbcAuthnConstants.WD_CLIENT_ID_KEY,
        LDQJdbcAuthnConstants.WD_CLIENT_ID_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    /**
     * OAuth Authorization endpoint URL.
     */
    WD_AUTHORIZATION_ENDPOINT(
        LDQJdbcAuthnConstants.WD_AUTHORIZATION_ENDPOINT_KEY,
        LDQJdbcAuthnConstants.WD_AUTHORIZATION_ENDPOINT_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    /**
     * OAuth Authorization redirect URL.
     */
    WD_AUTHORIZATION_REDIRECT_URL(
        LDQJdbcAuthnConstants.WD_AUTHORIZATION_REDIRECT_URL_KEY,
        LDQJdbcAuthnConstants.WD_AUTHORIZATION_REDIRECT_URL_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),
    /**
     * OAuth 2.0 client secret. Provided when the client is registered with Workday.
     */
    WD_CLIENT_SECRET(
        LDQJdbcAuthnConstants.WD_CLIENT_SECRET_KEY,
        LDQJdbcAuthnConstants.WD_CLIENT_SECRET_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    /**
     * Workday Integration System User (ISU).
     * Used as the subject claim in JWT.
     */
    WD_ISU(
        LDQJdbcAuthnConstants.WD_ISU_KEY,
        LDQJdbcAuthnConstants.WD_ISU_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    WD_SSL_PRIVATE_KEY(
        LDQJdbcAuthnConstants.WD_SSL_PRIVATE_KEY,
        LDQJdbcAuthnConstants.WD_SSL_PRIVATE_KEY_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    WD_SSL_PRIVATE_KEY_PATH(
        LDQJdbcAuthnConstants.WD_SSL_PRIVATE_KEY_FILE_PATH,
        LDQJdbcAuthnConstants.WD_SSL_PRIVATE_KEY_FILE_PATH_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    WD_AUTH_MODEL(
        LDQJdbcAuthnConstants.WD_AUTH_MODEL_KEY,
        LDQJdbcAuthnConstants.WD_AUTH_MODEL_DESCRIPTION,
        PropertyUsage.OAUTH,
        "JWT_BEARER",
        null,
        String.class
    ),

    /**
     * Pre-issued access token, used directly without a token exchange.
     */
    WD_ACCESS_TOKEN(
        LDQJdbcAuthnConstants.WD_ACCESS_TOKEN_KEY,
        LDQJdbcAuthnConstants.WD_ACCESS_TOKEN_DESCRIPTION,
        PropertyUsage.OAUTH,
        null,
        null,
        String.class
    ),

    // TRINO-ONLY PROPERTIES

    WD_HTTPCLIENT_TIMEOUT(
        LDQJdbcAuthnConstants.WD_HTTP_TIMEOUT,
        LDQJdbcAuthnConstants.WD_HTTP_TIMEOUT_DESCRIPTION,
        PropertyUsage.TRINO,
        null,
        TIMEOUT,
        String.class
    ),

    /**
     * Trino session properties.
     * Format: key1: value1, key2: value2
     * Note: keeping it for testing, will be removed once its populated downstream in co-ordinator.
     */
    WD_SESSION_PROPERTIES(
        LDQJdbcAuthnConstants.WD_SESSION_PROPERTIES_KEY,
        LDQJdbcAuthnConstants.WD_SESSION_PROPERTIES_DESCRIPTION,
        PropertyUsage.TRINO,
        null,
        SESSION_PROPERTIES,
        String.class
    );

    private final String key;
    private final String description;
    private final PropertyUsage usage;
    private final String defaultValue;
    private final PropertyName trinoPropertyName;
    private final Class<?> type;

    <T> DriverProperty(final String key,
                       final String description,
                       final PropertyUsage usage,
                       final String defaultValue,
                       final PropertyName trinoPropertyName,
                       final Class<T> type) {
        this.key = key;
        this.description = description;
        this.usage = usage;
        this.defaultValue = defaultValue;
        this.trinoPropertyName = trinoPropertyName;
        this.type = type;
    }

    public String getKey() {
        return this.key;
    }

    public String getDescription() {
        return this.description;
    }

    public String getDefaultValue() {
        return this.defaultValue;
    }

    public PropertyName getTrinoPropertyName() {
        return this.trinoPropertyName;
    }

    public Class<?> getType() {
        return this.type;
    }

    public boolean isUsedForOAuth() {
        return this.usage == PropertyUsage.OAUTH;
    }

    public boolean isUsedForTrino() {
        return this.usage == PropertyUsage.TRINO;
    }

    /**
     * Get the raw string value without parsing.
     * Useful for Trino properties that expect strings.
     *
     * @param value The string value
     * @return The trimmed string value or default value
     */
    public String getDefaultIfNeeded(final String value) {
        if (IS_NOT_EMPTY.negate().test(value)) {
            return this.defaultValue;
        }
        return value.trim();
    }

    /**
     * Property usage indicator.
     */
    public enum PropertyUsage {
        OAUTH,
        TRINO
    }

    @Override
    public String toString() {
        return this.key + " (" + this.description + ")";
    }
}
