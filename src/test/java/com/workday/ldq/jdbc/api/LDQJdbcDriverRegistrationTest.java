/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.api;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_JDBC_DRIVER_NAME;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_PRODUCT_NAME;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.workday.ldq.jdbc.impl.LDQJdbcConnection;
import com.workday.ldq.jdbc.impl.oauth.TokenManager;

/**
 * Tests for {@link LDQJdbcDriver} registration and discovery.
 * Verifies that the driver can be discovered by JDBC clients like DBeaver.
 *
 */
@ExtendWith(MockitoExtension.class)
class LDQJdbcDriverRegistrationTest {

    private static final String JDBC_URL = "jdbc:workday://localhost:8080";

    /**
     * Test that the driver is registered with DriverManager.
     */
    @Test
    void testDriverIsRegistered() {
        boolean found = false;
        final Enumeration<Driver> drivers = DriverManager.getDrivers();

        while (drivers.hasMoreElements()) {
            final Driver driver = drivers.nextElement();
            if (driver instanceof LDQJdbcDriver) {
                found = true;
                break;
            }
        }

        assertTrue(found, "LDQJdbcDriver should be registered with DriverManager");
    }

    /**
     * Test that DriverManager can find the driver for our URL.
     */
    @Test
    void testDriverManagerFindsDriver()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);
        assertNotNull(driver, "DriverManager should find driver for jdbc:workday: URL");
        assertInstanceOf(LDQJdbcDriver.class, driver, "Driver should be instance of LDQJdbcDriver");
    }

    /**
     * Test that the driver accepts our URL pattern.
     */
    @Test
    void testDriverAcceptsUrl()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);
        assertTrue(driver.acceptsURL(JDBC_URL), "Driver should accept jdbc:workday: URLs");
        assertTrue(driver.acceptsURL("jdbc:workday://example.com:443"), "Driver should accept jdbc:workday: URLs");
    }

    /**
     * Test that the driver rejects non-workday URLs.
     */
    @Test
    void testDriverRejectsOtherUrls()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);
        assertFalse(driver.acceptsURL("jdbc:postgresql://localhost:5432"), "Driver should reject non-workday URLs");
        assertFalse(driver.acceptsURL("jdbc:mysql://localhost:3306"), "Driver should reject non-workday URLs");
        assertFalse(driver.acceptsURL(null), "Driver should reject null URLs");
    }

    /**
     * Test that getPropertyInfo can be called via DriverManager.
     * This is how DBeaver discovers properties.
     */
    @Test
    void testGetPropertyInfoViaDriverManager()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);
        final DriverPropertyInfo[] propertyInfos = driver.getPropertyInfo(JDBC_URL, new Properties());

        assertNotNull(propertyInfos, "Property info should not be null");
        assertTrue(propertyInfos.length > 0, "Should return at least one property");

        // Verify property structure
        for (final DriverPropertyInfo info : propertyInfos) {
            assertNotNull(info.name, "Property name should not be null");
            assertNotNull(info.description, "Property description should not be null");
            assertTrue(info.name.startsWith("wd."), "Property name should start with 'wd.'");
        }
    }

    /**
     * Test that getPropertyInfo returns properties with current values.
     */
    @Test
    void testGetPropertyInfoWithValues()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);

        final Properties props = new Properties();
        props.setProperty(WD_TOKEN_ENDPOINT.getKey(), "https://example.com/token");
        props.setProperty(WD_CLIENT_ID.getKey(), "test-client");

        final DriverPropertyInfo[] propertyInfos = driver.getPropertyInfo(JDBC_URL, props);

        assertNotNull(propertyInfos);

        // Find and verify the properties we set
        boolean foundTokenEndpoint = false;
        boolean foundClientId = false;

        for (final DriverPropertyInfo info : propertyInfos) {
            if (WD_TOKEN_ENDPOINT.getKey().equals(info.name)) {
                assertEquals("https://example.com/token", info.value);
                foundTokenEndpoint = true;
            }
            else if (WD_CLIENT_ID.getKey().equals(info.name)) {
                assertEquals("test-client", info.value);
                foundClientId = true;
            }
        }

        assertTrue(foundTokenEndpoint, "Should find wd.tokenEndpoint property");
        assertTrue(foundClientId, "Should find wd.clientId property");
    }

    /**
     * Test driver version information.
     * Version is now loaded from a build-time generated driver-version.properties file,
     * which contains the version from build.gradle.kts
     */
    @Test
    void testDriverVersion()
        throws Exception {
        final Driver driver = DriverManager.getDriver(JDBC_URL);

        final int expectedMajor = 0;
        final int expectedMinor = 0;

        // Version from build.gradle.kts
        assertEquals(expectedMajor, driver.getMajorVersion(),
            "Major version should match with version in build.gradle.kts");
        assertEquals(expectedMinor, driver.getMinorVersion(),
            "Minor version should match with version in build.gradle.kts");
    }

    /**
     * Test that driver JDBC compliance status can be queried.
     */
    @Test
    void testDriverJdbcCompliant()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);

        // Just verify we can call the method - a Trino driver may not be fully JDBC compliant
        // This is expected and documented behavior
        driver.jdbcCompliant();
    }

    /**
     * Test that Connection.getMetaData() returns custom LDQ JDBC metadata.
     * This test uses a mock connection to verify the metadata wrapper behavior
     * without requiring a live Trino server.
     */
    @Test
    void testConnectionMetaDataReturnsCustomDriverInfo()
        throws SQLException {
        // Create a mock Trino connection with mock metadata
        final Connection mockTrinoConnection = mock(Connection.class);
        final TokenManager mockTokenManager = mock(TokenManager.class);
        final DatabaseMetaData mockTrinoMetadata = mock(DatabaseMetaData.class);

        // Configure mock Trino metadata to return Trino driver info
        when(mockTrinoConnection.getMetaData()).thenReturn(mockTrinoMetadata);

        //LDQJdbcConnection
        final Connection wrappedConnection = new LDQJdbcConnection(mockTrinoConnection, mockTokenManager);
        final DatabaseMetaData metadata = wrappedConnection.getMetaData();

        // Verify custom LDQ JDBC metadata is returned
        assertNotNull(metadata, "Metadata should not be null");
        assertEquals(LDQ_JDBC_DRIVER_NAME, metadata.getDriverName(),
            "Driver name should be LDQ JDBC driver name");
        assertEquals(LDQJdbcDriver.DRIVER_VERSION, metadata.getDriverVersion(),
            "Driver version should be LDQ JDBC driver version");
        assertEquals(LDQJdbcDriver.MAJOR_VERSION, metadata.getDriverMajorVersion(),
            "Major version should be LDQ JDBC driver major version");
        assertEquals(LDQJdbcDriver.MINOR_VERSION, metadata.getDriverMinorVersion(),
            "Minor version should be LDQ JDBC driver minor version");

        // Verify connection reference points to wrapped connection (not the delegate)
        assertEquals(wrappedConnection, metadata.getConnection(),
            "Metadata should return wrapped connection, not delegate");
    }

    /**
     * Test that LDQJdbcDatabaseMetaData delegates non-driver methods to Trino metadata.
     * This verifies that only driver-specific methods are overridden, while all other
     * DatabaseMetaData methods are properly delegated to the underlying Trino metadata.
     */
    @Test
    void testDatabaseMetaDataDelegation()
        throws SQLException {
        // Create a mock Trino connection with mock metadata
        final Connection mockTrinoConnection = mock(Connection.class);
        final TokenManager mockTokenManager = mock(TokenManager.class);
        final DatabaseMetaData mockTrinoMetadata = mock(DatabaseMetaData.class);

        when(mockTrinoConnection.getMetaData()).thenReturn(mockTrinoMetadata);

        // Configure mock to return Trino-specific values for non-driver methods
        when(mockTrinoMetadata.supportsTransactions()).thenReturn(true);

        final Connection ldqJdbcConnection = new LDQJdbcConnection(mockTrinoConnection, mockTokenManager);
        final DatabaseMetaData metadata = ldqJdbcConnection.getMetaData();

        // Verify non-driver methods are delegated to Trino metadata
        assertTrue(metadata.supportsTransactions(),
            "Transaction support should be delegated to Trino metadata");

        // But driver methods should return LDQ JDBC values
        assertEquals(LDQ_JDBC_DRIVER_NAME, metadata.getDriverName(),
            "Driver name should be LDQ JDBC driver name");
        assertEquals(LDQ_PRODUCT_NAME, metadata.getDatabaseProductName(),
            "Database product name should be LDQ product name");
    }
}
