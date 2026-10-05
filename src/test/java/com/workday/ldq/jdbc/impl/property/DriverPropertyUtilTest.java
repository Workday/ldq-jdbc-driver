/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.property;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_READ_PRIVATE_KEY_FROM_FILE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PRIVATE_KEY_FILE_IS_TOO_LARGE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PRIVATE_KEY_FILE_NOT_FOUND;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.trino.jdbc.$internal.client.uri.PropertyName;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.workday.ldq.jdbc.api.LDQJdbcDriver;
import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.AuthModel;

/**
 * Unit tests for {@link DriverPropertyUtil} focusing on private key loading functionality.
 *
 */
public class DriverPropertyUtilTest {

    public static final String SPACE = " ";
    public static final String DUMMY_PRIVATE_KEY =
        "-----BEGIN PRIVATE KEY-----\ntest-key-content\n-----END PRIVATE KEY-----\n"; // gitleaks:allow
    @TempDir
    Path tempDir;

    private Properties props;

    @BeforeEach
    void setUp() {
        this.props = new Properties();
        this.props.setProperty(DriverProperty.WD_TOKEN_ENDPOINT.getKey(), "https://example.com/token");
        this.props.setProperty(DriverProperty.WD_CLIENT_ID.getKey(), "test-client-id");
        this.props.setProperty(DriverProperty.WD_ISU.getKey(), "test-isu");
    }

    @Test
    void testSetTrinoDriverPropertiesSetsApplicationNamePrefixToDriverUserAgentInfo() {
        final Properties trinoProps = DriverPropertyUtil.setTrinoDriverProperties(this.props);

        assertEquals(LDQJdbcDriver.LDQ_JDBC_DRIVER_USER_AGENT_INFO + ":",
            trinoProps.getProperty(PropertyName.APPLICATION_NAME_PREFIX.toString()));
    }

    @Test
    void testLoadPrivateKeyFileNotFound() {
        final String nonExistentFile = this.tempDir.resolve("does_not_exist.pem").toString();

        final NoSuchFileException exception = assertThrows(
            NoSuchFileException.class, () -> DriverPropertyUtil.loadPrivateKeyFromFile(nonExistentFile));
        assertTrue(exception.getMessage().contains(nonExistentFile));
    }

    @Test
    void testLoadPrivateKeyFileADirectory() {
        assertThrows(
            IOException.class, () -> DriverPropertyUtil.loadPrivateKeyFromFile(this.tempDir.toAbsolutePath()
                .toString()));
    }

    @Test
    void testLoadPrivateKeyFileADirectoryViaCheckRequired() {
        final String tempDirPath = this.tempDir.toAbsolutePath().toString();
        this.props.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), tempDirPath);
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.props));

        assertTrue(exception.getMessage().contains(FAILED_TO_READ_PRIVATE_KEY_FROM_FILE));
        assertTrue(exception.getMessage().contains(tempDirPath));
    }

    @Test
    void testLoadPrivateKeyFileNotFoundViaCheckRequired() {
        final String nonExistentFile = this.tempDir.resolve("does_not_exist.pem").toString();
        this.props.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), nonExistentFile);

        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.props));
        assertTrue(exception.getMessage().contains(PRIVATE_KEY_FILE_NOT_FOUND));
        assertTrue(exception.getMessage().contains(nonExistentFile));
    }

    @Test
    void testLoadingPrivateKeyLargeFileFails()
        throws IOException {
        final StringBuilder content = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            content.append("*******Line ").append(i).append("********\n");
        }
        final Path keyFile = createTempFile("large_key.pem", content.toString());
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.loadPrivateKeyFromFile(keyFile.toString()));

        assertTrue(exception.getMessage().contains(PRIVATE_KEY_FILE_IS_TOO_LARGE));
    }

    @Test
    void testNeitherKeyNorPathProvided() {
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.props));

        assertTrue(exception.getMessage().contains(WD_SSL_PRIVATE_KEY.getKey()));
    }

    @Test
    void testPathProvidedIsBlank() {
        this.props.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), SPACE);
        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.props));

        assertTrue(exception.getMessage().contains(WD_SSL_PRIVATE_KEY.getKey()));
    }

    @Test
    void testLoadPrivateKeyPreservesLineBreaks()
        throws IOException {
        final String keyContent = "Line 1\nLine 2\nLine 3\n";
        final Path keyFile = createTempFile("multiline.txt", keyContent);

        final String result = DriverPropertyUtil.loadPrivateKeyFromFile(keyFile.toString());

        assertEquals(keyContent, result);
        assertTrue(result.contains("\n"));
    }

    @Test
    @SuppressWarnings("checkstyle:WorkdayWindowsCR")
    void testLoadPrivateKeyWindowsLineEndings()
        throws IOException {
        // A file with Windows line endings (CRLF)
        // Note: Intentionally using \r\n to test Windows line ending preservation
        final String keyContent =
        // Dummy private key for testing
        "-----BEGIN PRIVATE KEY-----\r\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\r\n-----END PRIVATE KEY-----\r\n"; // gitleaks:allow
        final Path keyFile = createTempFile("windows_line_endings.pem", keyContent);

        final String result = DriverPropertyUtil.loadPrivateKeyFromFile(keyFile.toString());

        assertEquals(keyContent, result);
        assertTrue(result.contains("\r\n"));
    }

    @Test
    void testLoadPrivateKeyLoadsFromPath()
        throws IOException {
        // Dummy private key for testing
        final String keyContent = DUMMY_PRIVATE_KEY;
        final Path keyFile = createTempFile("path_key.pem", keyContent);
        this.props.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), keyFile.toString());
        DriverPropertyUtil.checkRequiredProperties(this.props);

        assertEquals(keyContent, this.props.getProperty(WD_SSL_PRIVATE_KEY.getKey()));
    }

    @Test
    void testLoadPrivateKeyLoadsFromPathAndWithBlankPrivateKey()
        throws IOException {
        final String keyContent = DUMMY_PRIVATE_KEY;
        final Path keyFile = createTempFile("path_key.pem", keyContent);
        this.props.setProperty(WD_SSL_PRIVATE_KEY.getKey(), SPACE);
        this.props.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), keyFile.toString());
        DriverPropertyUtil.checkRequiredProperties(this.props);

        assertEquals(keyContent, this.props.getProperty(WD_SSL_PRIVATE_KEY.getKey()));
    }

    @Test
    void testLoadPrivateKeyLoadsFromPathWithLeadingAndTrailingSpace()
        throws IOException {
        final String keyContent = DUMMY_PRIVATE_KEY; // gitleaks:allow
        final Path keyFile = createTempFile("path_key.pem", keyContent);
        this.props.setProperty(WD_SSL_PRIVATE_KEY.getKey(), SPACE);
        this.props.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), SPACE + keyFile.toString() + SPACE);
        DriverPropertyUtil.checkRequiredProperties(this.props);

        assertEquals(keyContent, this.props.getProperty(WD_SSL_PRIVATE_KEY.getKey()));
    }

    // Helper method to create temporary files
    private Path createTempFile(final String filename, final String content)
        throws IOException {
        final Path file = this.tempDir.resolve(filename);
        Files.writeString(file, content);
        return file;
    }

    // -------------------------------------------------------------------------
    // Per-AuthModel required-property dispatch
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(value = AuthModel.class, names = {"JWT_BEARER", "AUTHORIZATION_CODE", "ACCESS_TOKEN"})
    void testAllRequiredPropertiesPresentValidates(final AuthModel model) {
        final Properties props = validPropertiesFor(model);
        DriverPropertyUtil.checkRequiredProperties(props);
    }

    @ParameterizedTest
    @EnumSource(value = AuthModel.class, names = {"JWT_BEARER", "AUTHORIZATION_CODE", "ACCESS_TOKEN"})
    void testMissingAnyRequiredPropertyThrowsForModel(final AuthModel model) {
        for (final DriverProperty required : model.getRequiredProperties()) {
            final Properties props = validPropertiesFor(model);
            props.remove(required.getKey());

            final LDQJdbcDriverRuntimeException ex = assertThrows(
                LDQJdbcDriverRuntimeException.class,
                () -> DriverPropertyUtil.checkRequiredProperties(props),
                () -> "Expected validation failure when " + required.getKey()
                    + " is missing for AuthModel " + model);
            assertTrue(ex.getMessage().contains(required.getKey()),
                "Error must name the missing property key: " + ex.getMessage());
            assertTrue(ex.getMessage().contains(model.name()),
                "Error must name the AuthModel that drove the requirement: " + ex.getMessage());
        }
    }

    /**
     * Build a Properties bag with every required property for {@code model}
     * populated with a syntactically-valid stub value.
     */
    private static Properties validPropertiesFor(final AuthModel model) {
        final Properties props = new Properties();
        props.setProperty(DriverProperty.WD_AUTH_MODEL.getKey(), model.name());
        for (final DriverProperty required : model.getRequiredProperties()) {
            props.setProperty(required.getKey(), stubValueFor(required));
        }
        return props;
    }

    private static String stubValueFor(final DriverProperty prop) {
        switch (prop) {
            case WD_TOKEN_ENDPOINT:
                return "https://example.com/token";
            case WD_AUTHORIZATION_ENDPOINT:
                return "https://example.com/authorize";
            case WD_AUTHORIZATION_REDIRECT_URL:
                return "https://localhost:8888/callback";
            case WD_CLIENT_ID:
                return "test-client-id";
            case WD_CLIENT_SECRET:
                return "test-client-secret";
            case WD_ISU:
                return "test-isu";
            case WD_SSL_PRIVATE_KEY:
                return "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----";
            case WD_ACCESS_TOKEN:
                return "stub-access-token";
            default:
                return "test-value";
        }
    }

}
