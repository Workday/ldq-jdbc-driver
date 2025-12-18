/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GRANT_TYPE_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OAUTH_2_JWT_GRANT_TYPE;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_ENDPOINT;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_REDIRECT_URL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_SECRET;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ISU;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import java.util.Arrays;
import java.util.Set;

import com.workday.ldq.jdbc.impl.property.DriverProperty;

/**
 * Supported authentication models for the LDQ JDBC driver.
 * <p>This enum defines the different OAuth 2.0 authentication flows supported by the driver.
 * Each model corresponds to a specific OAuth 2.0 grant type and authentication mechanism.
 * <p>Each model declares its required properties, making validation model-aware and eliminating
 * the need for scattered conditional logic.
 *
 */
public enum AuthModel {

    /**
     * JWT Bearer authentication using private key signing.
     * <p>This is the default authentication model. It uses the OAuth 2.0 JWT Bearer grant type
     * (RFC 7523) where the client creates a signed JWT assertion using a private key and
     * exchanges it for an access token.
     */
    JWT_BEARER(
        OAUTH_2_JWT_GRANT_TYPE,
        Set.of(
            WD_TOKEN_ENDPOINT,
            WD_CLIENT_ID,
            WD_ISU,
            WD_SSL_PRIVATE_KEY)
    ),

    /**
     * Authorization Code authentication.
     * <p>This uses the OAuth 2.0 Authorization Code grant type (RFC 6749) where the client
     * redirects the user to the authorization endpoint, the user authenticates and
     * consents, and the client exchanges the authorization code for an access token.
     */
    AUTHORIZATION_CODE(
        GRANT_TYPE_AUTHORIZATION_CODE,
        Set.of(
            WD_TOKEN_ENDPOINT,
            WD_CLIENT_ID,
            WD_AUTHORIZATION_ENDPOINT,
            WD_AUTHORIZATION_REDIRECT_URL,
            WD_CLIENT_SECRET)
    ),

    /**
     * Authorization Code with PKCE (Proof Key for Code Exchange).
     * <p>Uses the OAuth 2.0 Authorization Code grant type with PKCE extension (RFC 7636)
     * for enhanced security. This is typically used for interactive authentication flows.
     */
    AUTHORIZATION_CODE_PKCE(
        GRANT_TYPE_AUTHORIZATION_CODE,
        Set.of(
            WD_TOKEN_ENDPOINT,
            WD_CLIENT_ID,
            WD_AUTHORIZATION_ENDPOINT,
            WD_AUTHORIZATION_REDIRECT_URL)
    ),

    /**
     * Direct Access Token authentication.
     * <p>Used when the caller already possesses a valid access token and wants to use it
     * directly, without performing any token exchange.
     */
    ACCESS_TOKEN(
        GRANT_TYPE_ACCESS_TOKEN,
        Set.of(WD_ACCESS_TOKEN)
    );

    private final String grantType;
    private final Set<DriverProperty> requiredProperties;

    AuthModel(final String grantType, final Set<DriverProperty> requiredProperties) {
        this.grantType = grantType;
        this.requiredProperties = requiredProperties;
    }

    /**
     * Get the OAuth 2.0 grant type string for this authentication model.
     *
     * @return The grant type string used in OAuth token requests
     */
    public String getGrantType() {
        return this.grantType;
    }

    /**
     * Get the set of required properties for this authentication model.
     *
     * @return Immutable set of required driver properties
     */
    public Set<DriverProperty> getRequiredProperties() {
        return this.requiredProperties;
    }

    /**
     * Parse an authentication model from a string value.
     *
     * @param value The string value (case-insensitive)
     * @return The corresponding AuthModel, or JWT_BEARER if null/empty
     * @throws IllegalArgumentException if the value doesn't match any known model
     */
    public static AuthModel fromString(final String value) {
        if (IS_NOT_EMPTY.negate().test(value)) {
            return JWT_BEARER;  // Default
        }

        final String normalized = value.trim().toUpperCase();
        try {
            return AuthModel.valueOf(normalized);
        }
        catch (final IllegalArgumentException e) {
            throw new IllegalArgumentException(
                String.format("Unknown authentication model: %s. Supported values: %s", normalized, Arrays.toString(
                    values())));
        }
    }

    /**
     * Check if this authentication model requires a private key.
     *
     * @return true if a private key is required, false otherwise
     */
    public boolean requiresPrivateKey() {
        return this.requiredProperties.contains(WD_SSL_PRIVATE_KEY);
    }

    /**
     * Check if this authentication model requires PKCE.
     *
     * @return true if PKCE is required, false otherwise
     */
    public boolean requiresPKCE() {
        return this == AUTHORIZATION_CODE_PKCE;
    }

    /**
     * Get the list of authentication models that require this property.
     *
     * @param prop The property to check
     *
     * @return Array of AuthModel names that require this property, or empty array if not required by any
     */
    public static String[] getRequiredByAuthModels(final DriverProperty prop) {
        return Arrays.stream(values())
            .filter(model -> model.getRequiredProperties().contains(prop))
            .map(AuthModel::name)
            .toArray(String[]::new);
    }
}
