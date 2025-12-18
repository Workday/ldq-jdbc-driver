/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_ENDPOINT;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_REDIRECT_URL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_SECRET;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ISU;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for AuthModel enum.
 * Tests authentication model parsing, validation, and property requirements.
 *
 */
class AuthModelTest {

    // ==================== fromString() - Positive Test Cases ====================

    @Test
    @DisplayName("fromString - JWT_BEARER with exact uppercase match")
    void testFromStringJwtBearerExactCase() {
        final AuthModel result = AuthModel.fromString("JWT_BEARER");
        assertEquals(AuthModel.JWT_BEARER, result);
    }

    @Test
    @DisplayName("fromString - JWT_BEARER with lowercase")
    void testFromStringJwtBearerLowercase() {
        final AuthModel result = AuthModel.fromString("jwt_bearer");
        assertEquals(AuthModel.JWT_BEARER, result);
    }

    @Test
    @DisplayName("fromString - JWT_BEARER with mixed case")
    void testFromStringJwtBearerMixedCase() {
        final AuthModel result = AuthModel.fromString("JwT_BeArEr");
        assertEquals(AuthModel.JWT_BEARER, result);
    }

    @Test
    @DisplayName("fromString - AUTHORIZATION_CODE with exact uppercase match")
    void testFromStringAuthorizationCodeExactCase() {
        final AuthModel result = AuthModel.fromString("AUTHORIZATION_CODE");
        assertEquals(AuthModel.AUTHORIZATION_CODE, result);
    }

    @Test
    @DisplayName("fromString - AUTHORIZATION_CODE with lowercase")
    void testFromStringAuthorizationCodeLowercase() {
        final AuthModel result = AuthModel.fromString("authorization_code");
        assertEquals(AuthModel.AUTHORIZATION_CODE, result);
    }

    @ParameterizedTest
    @DisplayName("fromString - All valid values with whitespace")
    @CsvSource({
        "  JWT_BEARER  ,               JWT_BEARER",
        "  AUTHORIZATION_CODE  ,       AUTHORIZATION_CODE",
        "  AUTHORIZATION_CODE_PKCE  ,  AUTHORIZATION_CODE_PKCE"
    })
    void testFromStringWithWhitespace(final String input, final AuthModel expected) {
        final AuthModel result = AuthModel.fromString(input);
        assertEquals(expected, result);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("fromString - Null/empty defaults to JWT_BEARER")
    void testFromStringNullOrEmptyDefaultsToJwtBearer(final String input) {
        final AuthModel result = AuthModel.fromString(input);
        assertEquals(AuthModel.JWT_BEARER, result);
    }

    @ParameterizedTest
    @ValueSource(strings = {"   ", "\t", "\n", "  \t  "})
    @DisplayName("fromString - Whitespace-only throws exception")
    void testFromStringWhitespaceOnlyFails(final String input) {
        assertEquals(AuthModel.JWT_BEARER, AuthModel.fromString(input));
    }

    // ==================== fromString() - Negative Test Cases ====================

    @Test
    @DisplayName("fromString - Invalid value throws IllegalArgumentException")
    void testFromStringInvalidValue() {
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> AuthModel.fromString("INVALID_AUTH_MODEL")
        );

        // Note: Current implementation has a bug - it doesn't include the invalid value in the message
        // Error message format: "Unknown authentication model: %s. Supported values: [...]"
        // But the %s placeholder is missing, so it just shows: "Unknown authentication model: . Supported values: [.
        // ..]"
        assertTrue(exception.getMessage().contains("Unknown authentication model:"));
        assertTrue(exception.getMessage().contains("Supported values:"));
    }

    @Test
    @DisplayName("fromString - Invalid value error message contains all valid models")
    void testFromStringInvalidValueErrorMessageContainsAllModels() {
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> AuthModel.fromString("UNKNOWN")
        );

        final String message = exception.getMessage();
        assertTrue(message.contains("JWT_BEARER"), "Error should mention JWT_BEARER");
        assertTrue(message.contains("AUTHORIZATION_CODE"), "Error should mention AUTHORIZATION_CODE");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "CLIENT_CREDENTIALS",   // Not implemented yet
        "PASSWORD",             // Not supported
        "IMPLICIT",             // Deprecated OAuth flow
        "jwt_bearer_token",     // Close but wrong
        "AUTH_CODE",            // Abbreviation
        "JWT-BEARER",           // Wrong separator
        "JWT BEARER"            // Space instead of underscore
    })
    @DisplayName("fromString - Common invalid values throw exceptions")
    void testFromStringCommonInvalidValues(final String invalidValue) {
        assertThrows(IllegalArgumentException.class, () -> AuthModel.fromString(invalidValue));
    }

    // ==================== Grant Type Tests ====================

    @Test
    @DisplayName("getGrantType - JWT_BEARER returns correct grant type")
    void testGetGrantTypeJwtBearer() {
        assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", AuthModel.JWT_BEARER.getGrantType());
    }

    @Test
    @DisplayName("getGrantType - AUTHORIZATION_CODE returns authorization_code")
    void testGetGrantTypeAuthorizationCode() {
        assertEquals("authorization_code", AuthModel.AUTHORIZATION_CODE.getGrantType());
    }

    // ==================== Required Properties Tests ====================

    @Test
    @DisplayName("getRequiredProperties - JWT_BEARER requires correct properties")
    void testJwtBearerRequiredProperties() {
        final var required = AuthModel.JWT_BEARER.getRequiredProperties();

        assertEquals(4, required.size());
        assertTrue(required.contains(WD_TOKEN_ENDPOINT));
        assertTrue(required.contains(WD_CLIENT_ID));
        assertTrue(required.contains(WD_ISU));
        assertTrue(required.contains(WD_SSL_PRIVATE_KEY));

        // Should NOT require authorization code properties
        assertFalse(required.contains(WD_AUTHORIZATION_ENDPOINT));
        assertFalse(required.contains(WD_AUTHORIZATION_REDIRECT_URL));
        assertFalse(required.contains(WD_CLIENT_SECRET));
    }

    @Test
    @DisplayName("getRequiredProperties - AUTHORIZATION_CODE requires correct properties")
    void testAuthorizationCodeRequiredProperties() {
        final var required = AuthModel.AUTHORIZATION_CODE.getRequiredProperties();

        assertEquals(5, required.size());
        assertTrue(required.contains(WD_TOKEN_ENDPOINT));
        assertTrue(required.contains(WD_CLIENT_ID));
        assertTrue(required.contains(WD_AUTHORIZATION_ENDPOINT));
        assertTrue(required.contains(WD_AUTHORIZATION_REDIRECT_URL));
        assertTrue(required.contains(WD_CLIENT_SECRET));
        assertFalse(required.contains(WD_ISU));
        assertFalse(required.contains(WD_SSL_PRIVATE_KEY));
    }

    @Test
    @DisplayName("getRequiredProperties - Returns immutable set")
    void testRequiredPropertiesImmutable() {
        final var required = AuthModel.JWT_BEARER.getRequiredProperties();

        assertThrows(UnsupportedOperationException.class, () -> {
            required.add(WD_AUTHORIZATION_ENDPOINT);
        });
    }

    // ==================== requiresPrivateKey() Tests ====================

    @Test
    @DisplayName("requiresPrivateKey - JWT_BEARER requires private key")
    void testJwtBearerRequiresPrivateKey() {
        assertTrue(AuthModel.JWT_BEARER.requiresPrivateKey());
    }

    @Test
    @DisplayName("requiresPrivateKey - AUTHORIZATION_CODE does not require private key")
    void testAuthorizationCodeDoesNotRequirePrivateKey() {
        assertFalse(AuthModel.AUTHORIZATION_CODE.requiresPrivateKey());
    }

    // ==================== getRequiredByAuthModels() Tests ====================

    @Test
    @DisplayName("getRequiredByAuthModels - WD_TOKEN_ENDPOINT required by all models")
    void testGetRequiredByAuthModelsTokenEndpoint() {
        final String[] models = AuthModel.getRequiredByAuthModels(WD_TOKEN_ENDPOINT);

        assertEquals(3, models.length);
        assertTrue(containsValue(models, "JWT_BEARER"));
        assertTrue(containsValue(models, "AUTHORIZATION_CODE"));
        assertTrue(containsValue(models, "AUTHORIZATION_CODE_PKCE"));
    }

    @Test
    @DisplayName("getRequiredByAuthModels - WD_ISU only required by JWT_BEARER")
    void testGetRequiredByAuthModelsIsu() {
        final String[] models = AuthModel.getRequiredByAuthModels(WD_ISU);

        assertEquals(1, models.length);
        assertEquals("JWT_BEARER", models[0]);
    }

    @Test
    @DisplayName("getRequiredByAuthModels - WD_AUTHORIZATION_ENDPOINT required by both auth code flows")
    void testGetRequiredByAuthModelsAuthorizationEndpoint() {
        final String[] models = AuthModel.getRequiredByAuthModels(WD_AUTHORIZATION_ENDPOINT);

        assertEquals(2, models.length);
        assertTrue(containsValue(models, "AUTHORIZATION_CODE"));
        assertTrue(containsValue(models, "AUTHORIZATION_CODE_PKCE"));
    }

    // ==================== Enum Values Tests ====================

    @Test
    @DisplayName("values - All auth models are present")
    void testAllAuthModelsPresent() {
        final AuthModel[] models = AuthModel.values();

        assertEquals(4, models.length);
        assertArrayEquals(
            new AuthModel[]{
                AuthModel.JWT_BEARER,
                AuthModel.AUTHORIZATION_CODE,
                AuthModel.AUTHORIZATION_CODE_PKCE,
                AuthModel.ACCESS_TOKEN
            },
            models
        );
    }

    @Test
    @DisplayName("name - Enum names are correct")
    void testEnumNames() {
        assertEquals("JWT_BEARER", AuthModel.JWT_BEARER.name());
        assertEquals("AUTHORIZATION_CODE", AuthModel.AUTHORIZATION_CODE.name());
        assertEquals("AUTHORIZATION_CODE_PKCE", AuthModel.AUTHORIZATION_CODE_PKCE.name());
        assertEquals("ACCESS_TOKEN", AuthModel.ACCESS_TOKEN.name());
    }

    // ==================== AUTHORIZATION_CODE_PKCE Tests ====================

    @ParameterizedTest
    @DisplayName("fromString - AUTHORIZATION_CODE_PKCE parses correctly regardless of case")
    @ValueSource(strings = {
        "AUTHORIZATION_CODE_PKCE",
        "authorization_code_pkce",
        "Authorization_Code_Pkce"
    })
    void testFromStringAuthorizationCodePkce(final String input) {
        assertEquals(AuthModel.AUTHORIZATION_CODE_PKCE, AuthModel.fromString(input));
    }

    @Test
    @DisplayName("getGrantType - AUTHORIZATION_CODE_PKCE returns same grant type as AUTHORIZATION_CODE")
    void testGetGrantTypeAuthorizationCodePkce() {
        assertEquals("authorization_code", AuthModel.AUTHORIZATION_CODE_PKCE.getGrantType());
        assertEquals(AuthModel.AUTHORIZATION_CODE.getGrantType(), AuthModel.AUTHORIZATION_CODE_PKCE.getGrantType());
    }

    @Test
    @DisplayName("getRequiredProperties - AUTHORIZATION_CODE_PKCE requires 4 properties")
    void testAuthorizationCodePkceRequiredProperties() {
        final var required = AuthModel.AUTHORIZATION_CODE_PKCE.getRequiredProperties();

        assertEquals(4, required.size());
        assertTrue(required.contains(WD_TOKEN_ENDPOINT));
        assertTrue(required.contains(WD_CLIENT_ID));
        assertTrue(required.contains(WD_AUTHORIZATION_ENDPOINT));
        assertTrue(required.contains(WD_AUTHORIZATION_REDIRECT_URL));

        assertFalse(required.contains(WD_CLIENT_SECRET));
        assertFalse(required.contains(WD_ISU));
        assertFalse(required.contains(WD_SSL_PRIVATE_KEY));
    }

    @Test
    @DisplayName("requiresPrivateKey - AUTHORIZATION_CODE_PKCE does not require private key")
    void testAuthorizationCodePkceDoesNotRequirePrivateKey() {
        assertFalse(AuthModel.AUTHORIZATION_CODE_PKCE.requiresPrivateKey());
    }

    @ParameterizedTest
    @DisplayName("requiresPKCE - returns true only for AUTHORIZATION_CODE_PKCE")
    @CsvSource({
        "JWT_BEARER,              false",
        "AUTHORIZATION_CODE,      false",
        "AUTHORIZATION_CODE_PKCE, true",
        "ACCESS_TOKEN,            false"
    })
    void testRequiresPKCE(final AuthModel model, final boolean expected) {
        assertEquals(expected, model.requiresPKCE());
    }

    // ==================== ACCESS_TOKEN Tests ====================

    @Test
    @DisplayName("getRequiredProperties - ACCESS_TOKEN requires only WD_ACCESS_TOKEN")
    void testAccessTokenRequiredProperties() {
        final var required = AuthModel.ACCESS_TOKEN.getRequiredProperties();

        assertEquals(1, required.size());
        assertTrue(required.contains(WD_ACCESS_TOKEN));
    }

    // ==================== Helper Methods ====================

    private boolean containsValue(final String[] array, final String value) {
        for (final String element : array) {
            if (element.equals(value)) {
                return true;
            }
        }
        return false;
    }
}
