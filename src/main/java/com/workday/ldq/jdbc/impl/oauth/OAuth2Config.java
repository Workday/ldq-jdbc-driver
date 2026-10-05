/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_ENDPOINT;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_REDIRECT_URL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTH_MODEL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_SECRET;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ISU;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.Properties;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.property.DriverProperty;
import com.workday.ldq.jdbc.impl.property.DriverPropertyUtil;

/**
 * Immutable OAuth2 configuration using enum-based property storage with type-safe parsing.
 * IMPORTANT: Caller must validate properties first using DriverPropertyUtil.checkRequiredProperties().
 *
 */
public final class OAuth2Config {

    public static final String AUTH_MODEL_REQUIRED_MESSAGE =
        "Authentication model is required and cannot be null or empty";
    private final Map<DriverProperty, String> values = new EnumMap<>(DriverProperty.class);

    public OAuth2Config(@Nonnull final Properties properties) {
        extractOAuthProps(properties);
    }

    /**
     * Extract all OAuth properties from Properties.
     * Uses type-safe parsing from DriverProperty enum.
     * Assumption is that DriverPropertyUtil.checkRequiredProperties has already been called.
     */
    private void extractOAuthProps(final Properties properties) {
        DriverPropertyUtil.applyDefaults(properties);
        final String authModelValue = properties.getProperty(WD_AUTH_MODEL.getKey());

        if (IS_NOT_EMPTY.negate().test(authModelValue)) {
            throw new LDQJdbcDriverRuntimeException(AUTH_MODEL_REQUIRED_MESSAGE);
        }

        Arrays.stream(DriverProperty.values())
            .filter(DriverProperty::isUsedForOAuth)
            .forEach(prop -> {
                final String rawValue = properties.getProperty(prop.getKey());
                if (DriverPropertyUtil.IS_NOT_EMPTY.test(rawValue)) {
                    this.values.put(prop, rawValue.trim());
                }
            });
    }

    public String getTokenEndpoint() {
        return get(WD_TOKEN_ENDPOINT);
    }

    public String getAuthorizationEndpoint() {
        return get(WD_AUTHORIZATION_ENDPOINT);
    }

    public String getAuthorizationRedirectUrl() {
        return get(WD_AUTHORIZATION_REDIRECT_URL);
    }

    public String getClientSecret() {
        return get(WD_CLIENT_SECRET);
    }

    public String getClientId() {
        return get(WD_CLIENT_ID);
    }

    public String getIsu() {
        return get(WD_ISU);
    }

    public String getPrivateKey() {
        return get(WD_SSL_PRIVATE_KEY);
    }

    public String getAccessToken() {
        return get(WD_ACCESS_TOKEN);
    }

    public AuthModel getAuthModel() {
        final String value = get(WD_AUTH_MODEL);
        return AuthModel.fromString(value);
    }

    private String get(final DriverProperty property) {
        return this.values.get(property);
    }

}
