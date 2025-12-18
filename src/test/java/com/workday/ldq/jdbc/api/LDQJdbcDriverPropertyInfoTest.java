/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.api;

import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ISU;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.workday.ldq.jdbc.impl.property.DriverProperty;

/**
 * Tests for {@link LDQJdbcDriver#getPropertyInfo(String, Properties)} method.
 * Verifies that JDBC clients like DBeaver can discover driver properties correctly.
 *
 */
class LDQJdbcDriverPropertyInfoTest {

    private LDQJdbcDriver driver;
    private static final String JDBC_URL = "jdbc:workday://localhost:8080";

    @BeforeEach
    void setUp() {
        this.driver = new LDQJdbcDriver();
    }

    /**
     * Test that getPropertyInfo returns all driver properties.
     * Note: Returns DriverProperty.values().length + 2 (for user and password dummy properties)
     */
    @Test
    void testGetPropertyInfoReturnsAllProperties()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        assertNotNull(propertyInfos);
        assertEquals(DriverProperty.values().length, propertyInfos.length,
            "Should return info for all driver properties plus user/password");
    }

    /**
     * Test that property names are correct (not formatted strings).
     * DBeaver expects property keys like "wd.tokenEndpoint", not "wd.tokenEndpoint (description)".
     */
    @Test
    void testPropertyNamesAreKeys()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        for (final DriverPropertyInfo info : propertyInfos) {
            assertNotNull(info.name, "Property name should not be null");
            assertTrue(info.name.startsWith("wd."), "Property name should start with 'wd.'");
            assertFalse(info.name.contains("("), "Property name should not contain description");
        }
    }

    /**
     * Test that required properties are marked correctly.
     */
    @Test
    void testRequiredPropertiesMarked()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        // Find specific required properties
        final DriverPropertyInfo tokenEndpoint = findProperty(propertyInfos, WD_TOKEN_ENDPOINT.getKey());
        final DriverPropertyInfo clientId = findProperty(propertyInfos, WD_CLIENT_ID.getKey());
        final DriverPropertyInfo isu = findProperty(propertyInfos, WD_ISU.getKey());
        final DriverPropertyInfo privateKey = findProperty(propertyInfos, WD_SSL_PRIVATE_KEY.getKey());

        assertNotNull(tokenEndpoint);
        assertTrue(tokenEndpoint.required, "wd.authn.accessTokenEndpoint should be required");

        assertNotNull(clientId);
        assertTrue(clientId.required, "wd.authn.clientId should be required");

        assertNotNull(isu);
        assertTrue(isu.required, "wd.authn.isu should be required");

        assertNotNull(privateKey);
        assertTrue(privateKey.required, "wd.authn.privateKey should be required");
    }

    /**
     * Test that property descriptions are set.
     */
    @Test
    void testPropertyDescriptionsSet()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        for (final DriverPropertyInfo info : propertyInfos) {
            assertNotNull(info.description, "Property description should not be null for: " + info.name);
            assertFalse(info.description.isEmpty(), "Property description should not be empty for: " + info.name);
        }
    }

    /**
     * Test that current values are populated from provided properties.
     */
    @Test
    void testCurrentValuesPopulated()
        throws SQLException {
        final Properties props = new Properties();
        props.setProperty(WD_TOKEN_ENDPOINT.getKey(), "https://example.com/token");
        props.setProperty(WD_CLIENT_ID.getKey(), "test-client-id");

        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, props);

        final DriverPropertyInfo tokenEndpoint = findProperty(propertyInfos, WD_TOKEN_ENDPOINT.getKey());
        final DriverPropertyInfo clientId = findProperty(propertyInfos, WD_CLIENT_ID.getKey());

        assertNotNull(tokenEndpoint);
        assertEquals("https://example.com/token", tokenEndpoint.value);

        assertNotNull(clientId);
        assertEquals("test-client-id", clientId.value);
    }

    /**
     * Test that properties without values have null value.
     */
    @Test
    void testEmptyPropertiesHaveNullValue()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        final DriverPropertyInfo tokenEndpoint = findProperty(propertyInfos, WD_TOKEN_ENDPOINT.getKey());
        assertNotNull(tokenEndpoint);
        assertNull(tokenEndpoint.value, "Property without value should have null value");
    }

    /**
     * Test that getPropertyInfo works with null properties.
     */
    @Test
    void testGetPropertyInfoWithNullProperties()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, null);

        assertNotNull(propertyInfos);
        assertEquals(DriverProperty.values().length, propertyInfos.length);

        // All values should be null except user (which has default "oauth") and password (which has default "")
        for (int i = 0; i < DriverProperty.values().length; i++) {
            assertNull(propertyInfos[i].value, "Property value should be null when no properties provided");
        }
    }

    /**
     * Test that all property keys are unique.
     */
    @Test
    void testAllPropertyKeysAreUnique()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        final long uniqueCount = Arrays.stream(propertyInfos)
            .map(info -> info.name)
            .distinct()
            .count();

        assertEquals(propertyInfos.length, uniqueCount, "All property keys should be unique");
    }

    /**
     * Test that specific properties exist with correct metadata.
     */
    @Test
    void testSpecificPropertiesMetadata()
        throws SQLException {
        final DriverPropertyInfo[] propertyInfos = this.driver.getPropertyInfo(JDBC_URL, new Properties());

        // Test WD_TOKEN_ENDPOINT
        final DriverPropertyInfo tokenEndpoint = findProperty(propertyInfos, WD_TOKEN_ENDPOINT.getKey());
        assertNotNull(tokenEndpoint);
        assertEquals(WD_TOKEN_ENDPOINT.getKey(), tokenEndpoint.name);
        assertTrue(tokenEndpoint.required);
        assertTrue(tokenEndpoint.description.contains("OAuth 2.0"));
    }

    /**
     * Helper method to find a property by name.
     */
    private DriverPropertyInfo findProperty(final DriverPropertyInfo[] propertyInfos, final String name) {
        return Arrays.stream(propertyInfos)
            .filter(info -> info.name.equals(name))
            .findFirst()
            .orElse(null);
    }
}
