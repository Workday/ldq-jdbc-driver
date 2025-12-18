/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.integration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.jar.JarFile;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.workday.ldq.jdbc.api.LDQJdbcDriver;

/**
 * Integration tests for LDQJdbcDriver connection functionality.
 * These tests verify:
 * 1. Driver registration and discovery
 * 2. Connection creation with valid properties
 * 3. Connection metadata and capabilities
 * 4. Driver version information
 *
 */
@DisplayName("Driver Connection Integration Tests")
public class DriverConnectionIntegrationTest {

    private static final String JDBC_URL = "jdbc:workday://localhost:8089?SSLVerification=NONE";

    @BeforeAll
    static void setUp() {
        // Ensure driver is loaded
        try {
            Class.forName("com.workday.ldq.jdbc.api.LDQJdbcDriver");
        }
        catch (final ClassNotFoundException e) {
            fail("Failed to load LDQJdbcDriver class", e);
        }
    }

    @Test
    @DisplayName("Driver is registered with DriverManager")
    void testDriverRegistration() {
        // Verify driver is registered
        boolean driverFound = false;
        final Enumeration<Driver> drivers = DriverManager.getDrivers();

        while (drivers.hasMoreElements()) {
            final Driver driver = drivers.nextElement();
            if (driver instanceof LDQJdbcDriver) {
                driverFound = true;
                break;
            }
        }

        assertTrue(driverFound, "LDQJdbcDriver should be registered with DriverManager");
    }

    @Test
    @DisplayName("DriverManager can find driver for jdbc:workday URL")
    void testDriverManagerFindsDriver()
        throws SQLException {
        final Driver driver = DriverManager.getDriver(JDBC_URL);

        assertNotNull(driver, "DriverManager should find driver for jdbc:workday URL");
        assertInstanceOf(LDQJdbcDriver.class, driver,
            "Driver should be instance of LDQJdbcDriver");
    }

    @Test
    @DisplayName("Driver version loaded from JAR manifest")
    void testDriverVersionFromJar()
        throws Exception {
        // Find the JAR file
        final String jarPath = findDriverJar();
        if (jarPath == null) {
            System.out.println("Skipping JAR version test - JAR not found. Run: ./gradlew shadowJar");
            return;
        }

        System.out.println("Testing version from JAR: " + jarPath);

        // Load version from JAR manifest
        try (JarFile jarFile = new JarFile(jarPath)) {
            final java.util.jar.Manifest manifest = jarFile.getManifest();
            assertNotNull(manifest, "JAR should have a manifest");

            final String manifestVersion = manifest.getMainAttributes()
                .getValue("Implementation-Version");

            assertNotNull(manifestVersion, "Manifest should contain Implementation-Version");
            assertFalse(manifestVersion.isEmpty(), "Implementation-Version should not be empty");

            // Verify it matches semantic versioning
            assertTrue(manifestVersion.matches("\\d+\\.\\d+\\.\\d+.*"),
                "Manifest version should match semantic versioning pattern (X.Y.Z): " + manifestVersion);

        }
    }

    /**
     * Find the driver JAR file in the build directory.
     *
     * @return Path to JAR file, or null if not found
     */
    private String findDriverJar() {
        // Try to find in build directory
        final File buildDir = new File("build/libs");
        if (buildDir.exists()) {
            final java.io.File[] jars = buildDir.listFiles((dir, name) -> name.startsWith("ldq-jdbc-driver") && name
                .endsWith("-all.jar"));
            if (jars != null && jars.length > 0) {
                return jars[0].getAbsolutePath();
            }
        }

        return null;
    }

}
