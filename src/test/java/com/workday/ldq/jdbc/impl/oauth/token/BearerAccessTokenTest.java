/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Unit tests for BearerAccessToken.
 * Tests the BearerAccessToken class and its Builder pattern.
 *
 */
public class BearerAccessTokenTest {

    private static final String TEST_TOKEN =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
            ".eyJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjE2MzQ1Njc4MDAsInRlbmFudCI6InRlc3QtdGVuYW50IiwiY2xpZW50X2lkIjoidGVzdC1jbGllbnQtaWQifQ.test-signature";
    private static final String TEST_TENANT = "test-tenant";
    private static final String TEST_SUBJECT = "test-user";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_ID_TOKEN = "test-id-token";
    private static final long TEST_EXPIRY_TIME = 1634567800000L; // Future timestamp

    @ParameterizedTest(name = "[{index}] {6}")
    @MethodSource("builderConstructionTestCases")
    void testBuilder_Construction(
                                  final String token,
                                  final Object expiryTime,
                                  final String idToken,
                                  final String tenant,
                                  final String subject,
                                  final String clientId,
                                  final String description) {

        // Build the token
        final BearerAccessToken.Builder builder = BearerAccessToken.builder()
            .token(token)
            .expiryTime(expiryTime)
            .clientId(clientId);

        if (idToken != null) {
            builder.idToken(idToken);
        }
        if (tenant != null) {
            builder.tenant(tenant);
        }
        if (subject != null) {
            builder.subject(subject);
        }

        final BearerAccessToken result = builder.build();

        // Assert common fields
        assertNotNull(result, "BearerAccessToken should not be null");
        assertEquals(token, result.getToken(), "Token should match");
        assertEquals(clientId, result.getClientId(), "Client ID should match");
        assertEquals(BearerAccessToken.TYPE_BEARER, result.getType(), "Type should be BEARER");

        // Assert expiry time (handle both Date and Long)
        if (expiryTime instanceof Date) {
            assertEquals(expiryTime, result.getExpiryTime(), "Expiry time should match");
        }
        else if (expiryTime instanceof Long) {
            assertEquals(new Date((Long) expiryTime), result.getExpiryTime(), "Expiry time should match");
        }

        // Assert optional fields
        if (idToken != null) {
            assertEquals(idToken, result.getIdToken(), "ID token should match");
        }
        else {
            assertNull(result.getIdToken(), "ID token should be null");
        }

        if (tenant != null) {
            assertEquals(tenant, result.getTenant(), "Tenant should match");
        }
        else {
            assertNull(result.getTenant(), "Tenant should be null");
        }

        if (subject != null) {
            assertEquals(subject, result.getSubject(), "Subject should match");
        }
        else {
            assertNull(result.getSubject(), "Subject should be null");
        }
    }

    /**
     * Provides test data for builder construction tests.
     * Format: token, expiryTime, idToken, tenant, subject, clientId, testDescription
     */
    static Stream<Arguments> builderConstructionTestCases() {
        final Date expiryDate = new Date(TEST_EXPIRY_TIME);
        final Long expiryLong = TEST_EXPIRY_TIME;

        return Stream.of(
            // All fields populated
            Arguments.of(
                TEST_TOKEN,
                expiryDate,
                TEST_ID_TOKEN,
                TEST_TENANT,
                TEST_SUBJECT,
                TEST_CLIENT_ID,
                "Builder with all fields should create token correctly"
            ),

            // Minimal required fields only
            Arguments.of(
                TEST_TOKEN,
                expiryDate,
                null,
                null,
                null,
                TEST_CLIENT_ID,
                "Builder with minimal required fields should create token correctly"
            ),

            // With Long expiry time
            Arguments.of(
                TEST_TOKEN,
                expiryLong,
                null,
                null,
                null,
                TEST_CLIENT_ID,
                "Builder with Long expiry time should convert to Date"
            ),

            // Explicitly null optional fields
            Arguments.of(
                TEST_TOKEN,
                expiryDate,
                null,
                null,
                null,
                TEST_CLIENT_ID,
                "Builder with explicitly null optional fields should handle nulls correctly"
            ));
    }

    // ===== VALIDATION TESTS =====

    /**
     * Provides test data for validation exception tests.
     * Format: token, expiryTime, clientId, expectedExceptionType, expectedMessage, testDescription
     */
    static Stream<Arguments> validationExceptionTestCases() {
        final Date validExpiryTime = new Date(TEST_EXPIRY_TIME);
        final Date zeroExpiryTime = new Date(0);
        final Date negativeExpiryTime = new Date(-1);

        return Stream.of(
            // Token validation
            Arguments.of(
                null,
                validExpiryTime,
                TEST_CLIENT_ID,
                LDQJdbcDriverRuntimeException.class,
                "Token is required and cannot be null or empty",
                "Missing token should throw exception"
            ),
            Arguments.of(
                "",
                validExpiryTime,
                TEST_CLIENT_ID,
                LDQJdbcDriverRuntimeException.class,
                "Token is required and cannot be null or empty",
                "Empty token should throw exception"
            ),
            Arguments.of(
                "   ",
                validExpiryTime,
                TEST_CLIENT_ID,
                LDQJdbcDriverRuntimeException.class,
                "Token is required and cannot be null or empty",
                "Whitespace-only token should throw exception"
            ),

            // Expiry time validation
            Arguments.of(
                TEST_TOKEN,
                null,
                TEST_CLIENT_ID,
                LDQJdbcDriverRuntimeException.class,
                "Expiry time must be greater than 0",
                "Missing expiry time should throw exception"
            ),
            Arguments.of(
                TEST_TOKEN,
                zeroExpiryTime,
                TEST_CLIENT_ID,
                LDQJdbcDriverRuntimeException.class,
                "Expiry time must be greater than 0",
                "Zero expiry time should throw exception"
            ),
            Arguments.of(
                TEST_TOKEN,
                negativeExpiryTime,
                TEST_CLIENT_ID,
                LDQJdbcDriverRuntimeException.class,
                "Expiry time must be greater than 0",
                "Negative expiry time should throw exception"
            ),

            // Client ID validation
            Arguments.of(
                TEST_TOKEN,
                validExpiryTime,
                null,
                LDQJdbcDriverRuntimeException.class,
                "Client ID is required and cannot be null or empty",
                "Missing client ID should throw exception"
            ),
            Arguments.of(
                TEST_TOKEN,
                validExpiryTime,
                "",
                LDQJdbcDriverRuntimeException.class,
                "Client ID is required and cannot be null or empty",
                "Empty client ID should throw exception"
            ),
            Arguments.of(
                TEST_TOKEN,
                validExpiryTime,
                "   ",
                LDQJdbcDriverRuntimeException.class,
                "Client ID is required and cannot be null or empty",
                "Whitespace-only client ID should throw exception"
            )
        );
    }

    @ParameterizedTest(name = "[{index}] {5}")
    @MethodSource("validationExceptionTestCases")
    void testBuilder_ClaimValueValidationExceptions(
                                                    final String token,
                                                    final Date expiryTime,
                                                    final String clientId,
                                                    final Class<? extends Exception> expectedExceptionType,
                                                    final String expectedMessage,
                                                    final String description) {

        final Exception exception = assertThrows(
            expectedExceptionType,
            () -> {
                final BearerAccessToken.Builder builder = BearerAccessToken.builder();
                if (token != null) {
                    builder.token(token);
                }
                if (expiryTime != null) {
                    builder.expiryTime(expiryTime);
                }
                if (clientId != null) {
                    builder.clientId(clientId);
                }
                builder.build();
            },
            description
        );

        assertEquals(expectedMessage, exception.getMessage(), description);
    }

    // ===== EXPIRY TIME TYPE TESTS =====

    /**
     * Provides test data for expiry time type tests.
     * Format: expiryTimeValue, expectedDate, testDescription
     */
    static Stream<Arguments> expiryTimeTypeTestCases() {
        final Date expiryDate = new Date(TEST_EXPIRY_TIME);
        final Long expiryLong = TEST_EXPIRY_TIME;

        return Stream.of(
            Arguments.of(
                expiryDate,
                expiryDate,
                "Expiry time with Date should be accepted"
            ),
            Arguments.of(
                expiryLong,
                new Date(TEST_EXPIRY_TIME),
                "Expiry time with Long should be converted to Date"
            )
        );
    }

    @ParameterizedTest(name = "[{index}] {2}")
    @MethodSource("expiryTimeTypeTestCases")
    void testBuilder_ExpiryTimeTypes(
                                     final Object expiryTimeValue,
                                     final Date expectedDate,
                                     final String description) {

        final BearerAccessToken token = BearerAccessToken.builder()
            .token(TEST_TOKEN)
            .expiryTime(expiryTimeValue)
            .clientId(TEST_CLIENT_ID)
            .build();

        assertNotNull(token, "BearerAccessToken should not be null");
        assertEquals(expectedDate, token.getExpiryTime(), description);
    }

    /**
     * Provides test data for type validation exception tests.
     * Format: fieldName, invalidValue, expectedExceptionType, expectedMessageContains, testDescription
     */
    static Stream<Arguments> typeValidationExceptionTestCases() {
        return Stream.of(
            // Expiry time type validation
            Arguments.of(
                "expiryTime",
                "invalid",
                LDQJdbcDriverRuntimeException.class,
                "expiryTime must be Date or Long",
                "Invalid expiry time type should throw IllegalArgumentException"
            ),

            // Tenant type validation
            Arguments.of(
                "tenant",
                123,
                LDQJdbcDriverRuntimeException.class,
                "claim must be String",
                "Invalid tenant type should throw LDQJdbcDriverRuntimeException"
            )
        );
    }

    @ParameterizedTest(name = "[{index}] {4}")
    @MethodSource("typeValidationExceptionTestCases")
    void testBuilder_ClaimTypeValidationExceptions(
                                                   final String fieldName,
                                                   final Object invalidValue,
                                                   final Class<? extends Exception> expectedExceptionType,
                                                   final String expectedMessageContains,
                                                   final String description) {

        final Date validExpiryTime = new Date(TEST_EXPIRY_TIME);

        final Exception exception = assertThrows(
            expectedExceptionType,
            () -> {
                final BearerAccessToken.Builder builder = BearerAccessToken.builder()
                    .token(TEST_TOKEN)
                    .clientId(TEST_CLIENT_ID);

                // Set the field being tested
                switch (fieldName) {
                    case "expiryTime":
                        builder.expiryTime(invalidValue);
                        break;
                    case "tenant":
                        builder.expiryTime(validExpiryTime);
                        builder.tenant(invalidValue);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown field: " + fieldName);
                }

                builder.build();
            },
            description
        );

        assertTrue(exception.getMessage().contains(expectedMessageContains),
            "Exception message should contain: " + expectedMessageContains);
    }

}
