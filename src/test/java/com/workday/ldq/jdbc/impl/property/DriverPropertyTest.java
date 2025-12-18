/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.property;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PRIVATE_KEY_FILE_PATH_NOT_ABSOLUTE;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_ENDPOINT;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTHORIZATION_REDIRECT_URL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_AUTH_MODEL;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_CLIENT_SECRET;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_ISU;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SESSION_PROPERTIES;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_SSL_PRIVATE_KEY_PATH;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_TOKEN_ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.trino.jdbc.$internal.client.uri.PropertyName;

import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.workday.ldq.jdbc.TestPrivateKeyPem;
import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Tests for {@link DriverProperty}
 *
 */

public class DriverPropertyTest {

    private static final String SESSION_PROPERTIES = "workday_core.tenant_alias:super";

    @TempDir
    Path tempDir;

    private Properties connectionProps;

    @BeforeEach
    public void setup() {
        this.connectionProps = testProperties();
    }

    @Test
    public void testRequiredPropertyMissing() {
        // make a required property empty String
        this.connectionProps.setProperty(WD_TOKEN_ENDPOINT.getKey(), "");
        final LDQJdbcDriverRuntimeException exception = assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.connectionProps));
        assertTrue(exception.getMessage().contains(WD_TOKEN_ENDPOINT.getKey()));
    }

    @Test
    public void testPrivateKeyAndPathMissing() {
        this.connectionProps.remove(WD_SSL_PRIVATE_KEY.getKey());
        final LDQJdbcDriverRuntimeException exception = assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.connectionProps));
        assertTrue(exception.getMessage().contains(WD_SSL_PRIVATE_KEY.getKey()));
    }

    @Test
    public void testPrivateKeyPath()
        throws Exception {
        this.connectionProps.remove(WD_SSL_PRIVATE_KEY.getKey());
        final Path keyFile = TestPrivateKeyPem.writePkcs8KeyFile(this.tempDir);
        this.connectionProps.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), keyFile.toAbsolutePath().toString());
        //Ensure that private key is not set
        assertFalse(this.connectionProps.containsKey(WD_SSL_PRIVATE_KEY.getKey()));
        DriverPropertyUtil.checkRequiredProperties(this.connectionProps);
        //Ensure that private key is set after loading from file
        assertTrue(this.connectionProps.containsKey(WD_SSL_PRIVATE_KEY.getKey()));
    }

    @Test
    public void testPrivateKeyPathIsNotAbsolute()
        throws Exception {
        this.connectionProps.remove(WD_SSL_PRIVATE_KEY.getKey());
        final Path keyFile = TestPrivateKeyPem.writePkcs8KeyFile(this.tempDir);
        this.connectionProps.setProperty(WD_SSL_PRIVATE_KEY_PATH.getKey(), keyFile.getFileName().toString());
        final LDQJdbcDriverRuntimeException exception = assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.connectionProps));

        assertTrue(exception.getMessage().contains(PRIVATE_KEY_FILE_PATH_NOT_ABSOLUTE));
    }

    @Test
    public void testRequiredPropertiesNull() {
        // remove a required property
        this.connectionProps.remove(WD_TOKEN_ENDPOINT.getKey());
        final LDQJdbcDriverRuntimeException exception = assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.connectionProps));
        // verify the missing property is mentioned in the exception
        assertTrue(exception.getMessage().contains(WD_TOKEN_ENDPOINT.getKey()));
    }

    @Test
    void testSetTrinoDriverPropertiesShouldTrimPropertyValues() {
        this.connectionProps.setProperty(WD_SESSION_PROPERTIES.getKey(), "  instrumentation:false  ");

        final Properties result = DriverPropertyUtil.setTrinoDriverProperties(this.connectionProps);
        assertEquals("instrumentation:false", result.getProperty(PropertyName.SESSION_PROPERTIES.toString()));
    }

    @Test
    void testRequiredPropertiesMissing() {
        // Properties missing
        final DriverProperty[] missingProperties = {WD_TOKEN_ENDPOINT};
        for (final DriverProperty prop : missingProperties) {
            this.connectionProps.remove(prop.getKey());
        }
        final LDQJdbcDriverRuntimeException exception = assertThrows(LDQJdbcDriverRuntimeException.class,
            () -> DriverPropertyUtil.checkRequiredProperties(this.connectionProps));
        for (final DriverProperty prop : missingProperties) {
            assertTrue(exception.getMessage().contains(prop.getKey()));
        }
    }

    private static Properties testProperties() {
        final Properties props = new Properties();

        // ========== OAuth 2.0 Configuration ==========
        props.setProperty(WD_CLIENT_ID.getKey(), "test-client-id");
        props.setProperty(WD_CLIENT_SECRET.getKey(), "test-client-secret");
        props.setProperty(WD_AUTHORIZATION_ENDPOINT.getKey(), "https://example.com/authorize");
        props.setProperty(WD_AUTHORIZATION_REDIRECT_URL.getKey(), "https://localhost:8888/callback");
        props.setProperty(WD_AUTH_MODEL.getKey(), "jwt_bearer");
        props.setProperty(WD_ISU.getKey(), "sfd-intuser-super");
        props.setProperty(WD_TOKEN_ENDPOINT.getKey(), "https://example.com/token");
        props.setProperty(WD_SSL_PRIVATE_KEY.getKey(), "---BEGIN PRIVATE KEY-----\n" +
            "MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQDca3ZqJ1uo1nLn\n ---END PRIVATE KEY-----");

        return props;
    }
}
