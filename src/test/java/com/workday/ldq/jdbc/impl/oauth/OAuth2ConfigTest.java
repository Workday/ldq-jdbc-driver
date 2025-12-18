/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTH_MODEL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ISU;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_LDQ_USE_CASE;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.workday.ldq.jdbc.impl.property.LdqUseCase;

/**
 * Unit tests for OAuth2Config class.
 * Tests property extraction, validation, and getter methods.
 *
 */
public class OAuth2ConfigTest {

    // Test URLs
    private static final String TEST_TOKEN_ENDPOINT = "https://test.example.com/oauth/token";

    // Test values
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_ISU = "test-isu";
    private static final String TEST_PRIVATE_KEY = "test-private-key";


    // Whitespace values for trimming tests
    private static final String WHITESPACE_TOKEN_ENDPOINT = "  https://test.example.com/oauth/token  ";
    private static final String WHITESPACE_CLIENT_ID = "  test-client-id  ";

    private Properties properties;

    @BeforeEach
    public void setup() {
        this.properties = new Properties();
    }

    @Test
    public void testConstructor_WithAllOAuthProperties_ShouldCreateConfig() {
        // Given: All OAuth properties set
        setupAllOAuthProperties();

        // When: Creating OAuth2Config
        final OAuth2Config config = new OAuth2Config(this.properties);

        // Then: All properties should be accessible
        assertEquals(TEST_TOKEN_ENDPOINT, config.getTokenEndpoint());
        assertEquals(TEST_CLIENT_ID, config.getClientId());
        assertEquals(TEST_ISU, config.getIsu());
        assertEquals(TEST_PRIVATE_KEY, config.getPrivateKey());
    }

    @Test
    public void testConstructor_WithNullProperties_ShouldThrowException() {
        assertThrows(NullPointerException.class, () -> new OAuth2Config(null));
    }

    @Test
    public void testConstructor_MissingPrivateKey_ShouldNotThrowException() {
        // Private key is optional - validation happens later in DriverPropertyUtil.checkRequiredProperties()
        setupAllOAuthProperties();
        this.properties.remove(WD_SSL_PRIVATE_KEY.getKey());

        // Should not throw - private key is not marked as required in DriverProperty
        final OAuth2Config config = new OAuth2Config(this.properties);
        // Private key should be null or default value
        assertEquals(null, config.getPrivateKey());
    }

    @Test
    public void testConstructor_WithWhitespaceValues_ShouldTrimValues() {
        setupAllOAuthProperties();
        // Given: Properties with whitespace
        this.properties.setProperty(WD_TOKEN_ENDPOINT.getKey(), WHITESPACE_TOKEN_ENDPOINT);
        this.properties.setProperty(WD_CLIENT_ID.getKey(), WHITESPACE_CLIENT_ID);

        // When: Creating OAuth2Config
        final OAuth2Config config = new OAuth2Config(this.properties);

        // Then: Values should be trimmed
        assertEquals(TEST_TOKEN_ENDPOINT, config.getTokenEndpoint());
        assertEquals(TEST_CLIENT_ID, config.getClientId());
    }

    @Test
    public void testGetLdqUseCase_WithDefaultValue_ShouldReturnLdq() {
        setupAllOAuthProperties();
        // Don't set WD_LDQ_USE_CASE - should use default
        final OAuth2Config config = new OAuth2Config(this.properties);
        // Asserting default value
        assertEquals(LdqUseCase.LDQ, config.getLdqUseCase());
    }

    @Test
    public void testGetLdqUseCase_WithEtlValue_ShouldReturnEtl() {
        setupAllOAuthProperties();
        this.properties.setProperty(WD_LDQ_USE_CASE.getKey(), "ETL");
        final OAuth2Config config = new OAuth2Config(this.properties);

        assertEquals(LdqUseCase.ETL, config.getLdqUseCase());
    }

    @Test
    public void testGetLdqUseCase_WithAgenticValue_ShouldReturnAgentic() {
        setupAllOAuthProperties();
        this.properties.setProperty(WD_LDQ_USE_CASE.getKey(), "agentic");
        final OAuth2Config config = new OAuth2Config(this.properties);

        assertEquals(LdqUseCase.AGENTIC, config.getLdqUseCase());
    }

    @Test
    public void testGetLdqUseCase_WithInvalidValue_ShouldThrowException() {
        setupAllOAuthProperties();
        this.properties.setProperty(WD_LDQ_USE_CASE.getKey(), "invalid");

        final OAuth2Config oAuth2Config = new OAuth2Config(this.properties);
        assertThrows(IllegalArgumentException.class, () -> oAuth2Config.getLdqUseCase());
    }

    /**
     * Helper method to set up all OAuth properties for testing.
     */
    private void setupAllOAuthProperties() {
        this.properties.setProperty(WD_TOKEN_ENDPOINT.getKey(), TEST_TOKEN_ENDPOINT);
        this.properties.setProperty(WD_CLIENT_ID.getKey(), TEST_CLIENT_ID);
        this.properties.setProperty(WD_ISU.getKey(), TEST_ISU);
        this.properties.setProperty(WD_SSL_PRIVATE_KEY.getKey(), TEST_PRIVATE_KEY);
        this.properties.setProperty(WD_AUTH_MODEL.getKey(), AuthModel.JWT_BEARER.name());
    }
}
