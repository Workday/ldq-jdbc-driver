/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.api;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.JDBC_TRINO_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.JDBC_WORKDAY_PREFIX;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Unit tests for LDQJdbcDriver.
 * Tests the convertToTrinoUrl method and other driver functionality.
 *
 */
public class LDQJdbcDriverTest {

    public static final String VALID_TEST_LDQ_URL = JDBC_WORKDAY_PREFIX + "//localhost:8443/catalog/schema";
    public static final String JDBC_TRINO_URL_TEST = JDBC_TRINO_PREFIX + "//localhost:8443/catalog/schema";

    private Driver driver;
    private Method convertToTrinoUrlMethod;

    @BeforeEach
    public void setUp()
        throws Exception {
        // Use reflection to access the private constructor
        this.driver = DriverManager.getDriver(VALID_TEST_LDQ_URL);

        // Use reflection to access the private convertToTrinoUrl method
        this.convertToTrinoUrlMethod = LDQJdbcDriver.class.getDeclaredMethod("convertToTrinoUrl", String.class);
        this.convertToTrinoUrlMethod.setAccessible(true);
    }

    @ParameterizedTest(name = "[{index}] {2}")
    @MethodSource("convertToTrinoUrlTestCases")
    public void testConvertToTrinoUrl(final String inputUrl, final String expectedOutput, final String description)
        throws Exception {
        final String result = (String) this.convertToTrinoUrlMethod.invoke(this.driver, inputUrl);

        if (expectedOutput == null) {
            assertNull(result, description);
        }
        else {
            assertEquals(expectedOutput, result, description);
        }
    }

    @ParameterizedTest(name = "[{index}] {2}")
    @MethodSource("acceptsURLTestCases")
    public void testAcceptsURL(final String inputUrl, final boolean expectedResult, final String description)
        throws SQLException {
        final boolean result = this.driver.acceptsURL(inputUrl);
        assertEquals(expectedResult, result, description);
    }

    @Test
    public void testNullProps() {
        // Test that null properties are handled correctly
        assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> {
                try (Connection connection = this.driver.connect(VALID_TEST_LDQ_URL, null)) {
                    // Should not reach here
                    fail("Should have thrown LDQJdbcDriverRuntimeException");
                }
            });
    }

    @Test
    public void testEmptyProps() {
        // Test that empty properties are handled correctly
        assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> {
                try (Connection connection = this.driver.connect(VALID_TEST_LDQ_URL, new Properties())) {
                    // Should not reach here
                    fail("Should have thrown LDQJdbcDriverRuntimeException");
                }
            });
    }

    /**
     * Provides test data for convertToTrinoUrl parameterized tests.
     * Format: inputUrl, expectedOutput, testDescription
     */
    static Stream<Arguments> convertToTrinoUrlTestCases() {
        return Stream.of(
            // Basic conversion
            Arguments.of(
                VALID_TEST_LDQ_URL,
                JDBC_TRINO_URL_TEST,
                "Workday URL should be converted to Trino URL"),
            // Trino URL unchanged
            Arguments.of(
                JDBC_TRINO_URL_TEST,
                JDBC_TRINO_URL_TEST,
                "Trino URL should be returned unchanged"),
            // Null URL
            Arguments.of(
                null,
                null,
                "Null URL should return null"),
            // Empty URL
            Arguments.of(
                "",
                "",
                "Empty URL should be returned unchanged"),
            // Non-Workday URL
            Arguments.of(
                "jdbc:mysql://localhost:3306/database",
                "jdbc:mysql://localhost:3306/database",
                "Non-workday URL should be returned unchanged"),
            // URL with query parameters
            Arguments.of(
                VALID_TEST_LDQ_URL + "?user=test&password=secret",
                JDBC_TRINO_URL_TEST + "?user=test&password=secret",
                "Workday URL with query params should be converted correctly"),
            // URL with fragment
            Arguments.of(
                VALID_TEST_LDQ_URL + "#fragment",
                JDBC_TRINO_URL_TEST + "#fragment",
                "Workday URL with fragment should be converted correctly"),
            // Complex URL
            Arguments.of(
                JDBC_WORKDAY_PREFIX + "//workday.example.com:8443/my-catalog/my-schema/table?param=value",
                JDBC_TRINO_PREFIX + "//workday.example.com:8443/my-catalog/my-schema/table?param=value",
                "Complex Workday URL should be converted correctly"
            )
        );
    }

    /**
     * Provides test data for acceptsURL parameterized tests.
     * Format: inputUrl, expectedResult, testDescription
     */
    static Stream<Arguments> acceptsURLTestCases() {
        return Stream.of(
            // Valid URLs that should be accepted (true)
            Arguments.of(
                VALID_TEST_LDQ_URL,
                true,
                "Valid Workday URL should be accepted"),
            Arguments.of(
                VALID_TEST_LDQ_URL + "?user=test&password=secret",
                true,
                "Workday URL with query parameters should be accepted"),
            Arguments.of(
                VALID_TEST_LDQ_URL + "#fragment",
                true,
                "Workday URL with fragment should be accepted"),
            Arguments.of(
                JDBC_WORKDAY_PREFIX + "//workday.example.com:8443/my-catalog/my-schema/table?param=value#fragment",
                true,
                "Complex Workday URL should be accepted"),
            Arguments.of(
                JDBC_TRINO_URL_TEST,
                true,
                "Trino URL should be accepted"),

            // Invalid URLs that should be rejected (false)
            Arguments.of(
                "jdbc:mysql://localhost:3306/database",
                false,
                "MySQL URL should not be accepted"),
            Arguments.of(
                "jdbc:postgresql://localhost:5432/database",
                false,
                "PostgreSQL URL should not be accepted"),
            Arguments.of(
                null,
                false,
                "Null URL should not be accepted"),
            Arguments.of(
                "",
                false,
                "Empty URL should not be accepted"),
            Arguments.of(
                "   ",
                false,
                "Whitespace URL should not be accepted"),
            Arguments.of(
                "jdbc:workday",
                false,
                "Partial Workday URL should not be accepted"),
            Arguments.of(
                "workday://localhost:8443/catalog/schema",
                false,
                "URL without jdbc: protocol should not be accepted"),
            Arguments.of(
                "jdbc:WORKDAY://localhost:8443/catalog/schema",
                false,
                "Case-sensitive Workday URL should not be accepted"),
            Arguments.of(
                "jdbc:workday ://localhost:8443/catalog/schema",
                false,
                "Workday URL with spaces should not be accepted"
            )
        );
    }
}
