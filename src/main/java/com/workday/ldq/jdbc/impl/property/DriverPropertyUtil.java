/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.property;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_SSL;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.MAX_PRIVATE_KEY_FILE_SIZE_IN_BYTES;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PRIVATE_KEY_FILE_PATH_NOT_ABSOLUTE;
import static com.workday.ldq.jdbc.impl.oauth.OAuth2Config.AUTH_MODEL_REQUIRED_MESSAGE;
import static com.workday.ldq.jdbc.impl.property.DriverProperty.WD_LDQ_USE_CASE;

import io.trino.jdbc.$internal.client.uri.PropertyName;
import io.trino.jdbc.$internal.guava.base.Predicate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

import com.workday.ldq.jdbc.api.LDQJdbcDriver;
import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants;
import com.workday.ldq.jdbc.impl.oauth.AuthModel;

/**
 * Utility for extracting and mapping Trino driver properties.
 *
 */
public final class DriverPropertyUtil {

    public static final Predicate<String> IS_NOT_EMPTY = value -> value != null && !value.isBlank();

    private DriverPropertyUtil() {
        // Utility class
    }

    /**
     * Extract Trino driver properties
     * Uses type-safe parsing and validation from DriverProperty enum.
     *
     * @param driverProps Driver properties provided
     * @return Properties formatted for Trino driver
     */
    public static Properties setTrinoDriverProperties(final Properties driverProps) {
        final Properties trinoProps = new Properties();
        // Extract all Trino-related properties
        Arrays.stream(DriverProperty.values())
            .filter(DriverProperty::isUsedForTrino)
            .forEach(prop -> {
                final String rawValue = prop.getDefaultIfNeeded(driverProps.getProperty(prop.getKey()));
                if (DriverPropertyUtil.IS_NOT_EMPTY.test(rawValue)) {
                    trinoProps.setProperty(prop.getTrinoPropertyName().toString(), rawValue);
                }
            });
        // Set required Trino SSL properties, not exposed in DriverProperty
        trinoProps.setProperty(PropertyName.SSL.toString(), DEFAULT_SSL.toString());
        // Prefix the client-reported ApplicationName (if any) with the driver identity, so both surface
        // together in Trino's "source", which is what query event logs report. This also replaces the
        // "trino-jdbc" default Trino falls back to when no ApplicationName is set.
        trinoProps.setProperty(PropertyName.APPLICATION_NAME_PREFIX.toString(),
            LDQJdbcDriver.LDQ_JDBC_DRIVER_USER_AGENT_INFO + ":");
        return trinoProps;
    }

    /**
     * Validate that all required properties are present and perform additional security validations.
     * <p>Validation is model-aware: the set of required properties is determined by the configured
     * {@link AuthModel}, which defaults to {@link AuthModel#JWT_BEARER} if not specified.
     *
     * @param props Properties to validate - must not be null
     * @throws LDQJdbcDriverRuntimeException if required properties are missing or invalid
     */
    public static void checkRequiredProperties(final Properties props) {
        if (props == null) {
            throw new LDQJdbcDriverRuntimeException("No properties provided");
        }

        applyDefaults(props);

        final AuthModel authModel = resolveAuthModel(props);

        if (authModel == null) {
            throw new LDQJdbcDriverRuntimeException(AUTH_MODEL_REQUIRED_MESSAGE);
        }

        //validate ldq use case value provided
        final String ldqUseCaseValue = props.getProperty(WD_LDQ_USE_CASE.getKey());
        try {
            LdqUseCase.fromString(ldqUseCaseValue);
        }
        catch (final IllegalArgumentException e) {
            throw new LDQJdbcDriverRuntimeException(e.getMessage(), e);
        }

        if (authModel.requiresPrivateKey()) {
            loadPrivateKeyIfNeeded(props);
        }

        // Check for missing required properties based on the authentication model
        final List<String> missing = authModel.getRequiredProperties().stream()
            .map(DriverProperty::getKey)
            .filter(key -> !IS_NOT_EMPTY.test(props.getProperty(key)))
            .collect(Collectors.toList());

        if (!missing.isEmpty()) {
            throw new LDQJdbcDriverRuntimeException(String.format(
                "Required property(ies) missing for AuthModel %s: %s",
                authModel, String.join(", ", missing)));
        }

        if (authModel.getRequiredProperties().contains(DriverProperty.WD_TOKEN_ENDPOINT)) {
            validateTokenUrl(props.getProperty(DriverProperty.WD_TOKEN_ENDPOINT.getKey()));
        }
    }

    /**
     * Resolve the authentication model from properties, with proper error handling.
     *
     * @param props Properties containing the auth model configuration
     * @return The resolved AuthModel (defaults to JWT_BEARER if not specified)
     * @throws LDQJdbcDriverRuntimeException if an unknown model name is provided
     */
    public static AuthModel resolveAuthModel(final Properties props) {
        try {
            return AuthModel.fromString(props.getProperty(DriverProperty.WD_AUTH_MODEL.getKey()));
        }
        catch (final IllegalArgumentException e) {
            throw new LDQJdbcDriverRuntimeException(e.getMessage(), e);
        }
    }

    static void loadPrivateKeyIfNeeded(final Properties props) {
        final String privateKey = props.getProperty(DriverProperty.WD_SSL_PRIVATE_KEY.getKey());
        if (IS_NOT_EMPTY.test(privateKey)) {
            return;
        }

        final String privateKeyFilePath = props.getProperty(DriverProperty.WD_SSL_PRIVATE_KEY_PATH.getKey());
        if (IS_NOT_EMPTY.test(privateKeyFilePath)) {
            try {
                final String privateKeyFromFile = loadPrivateKeyFromFile(privateKeyFilePath.trim());
                props.setProperty(DriverProperty.WD_SSL_PRIVATE_KEY.getKey(), privateKeyFromFile);
            }
            catch (final NoSuchFileException e) {
                throw new LDQJdbcDriverRuntimeException(
                    String.format("%s : %s", LDQJdbcAuthnConstants.PRIVATE_KEY_FILE_NOT_FOUND, e.getMessage()), e);
            }
            catch (final IOException e) {
                throw new LDQJdbcDriverRuntimeException(
                    String.format("%s (%s): %s", LDQJdbcAuthnConstants.FAILED_TO_READ_PRIVATE_KEY_FROM_FILE,
                        e.getMessage(), privateKeyFilePath), e);
            }
        }
        else {
            // Neither private key nor private key path provided
            throw new LDQJdbcDriverRuntimeException(
                String.format("Either %s or %s must be provided when auth model is %s",
                    DriverProperty.WD_SSL_PRIVATE_KEY.getKey(),
                    DriverProperty.WD_SSL_PRIVATE_KEY_PATH.getKey(),
                    AuthModel.JWT_BEARER.name()));
        }
    }

    /**
     * Loads private key from a file.
     * It's important that newlines are preserved exactly as they appear in the file.
     * This method also enforces a reasonable file size limit to prevent loading large files by mistake.
     */
    static String loadPrivateKeyFromFile(final String filename)
        throws IOException {
        final Path path = Paths.get(filename);

        if (!path.isAbsolute()) {
            throw new LDQJdbcDriverRuntimeException(PRIVATE_KEY_FILE_PATH_NOT_ABSOLUTE + filename);
        }

        if (Files.size(path) > MAX_PRIVATE_KEY_FILE_SIZE_IN_BYTES) {
            throw new LDQJdbcDriverRuntimeException(LDQJdbcAuthnConstants.PRIVATE_KEY_FILE_IS_TOO_LARGE);
        }

        return Files.readString(path, StandardCharsets.UTF_8);
    }

    public static void applyDefaults(final Properties props) {
        Arrays.stream(DriverProperty.values())
            .filter(prop -> props.getProperty(prop.getKey()) == null) // Not already set
            .filter(prop -> prop.getDefaultValue() != null) // Has default value
            .forEach(prop -> props.setProperty(prop.getKey(), prop.getDefaultValue())); // Set default
    }

    /**
     * Validates that the OAuth token endpoint URL uses HTTPS protocol for security.
     * This is a critical security validation to prevent man-in-the-middle attacks
     * and ensure credentials are transmitted over encrypted connections.
     *
     * @param property
     * @throws LDQJdbcDriverRuntimeException if the token URL does not start with "https://"
     */
    private static void validateTokenUrl(final String property) {
        try {
            final URI tokenUri = new URI(property);
            if (!"https".equalsIgnoreCase(tokenUri.getScheme())) {
                throw new LDQJdbcDriverRuntimeException(
                    String.format("Token endpoint must use HTTPS protocol for security. Got: %s ...",
                        tokenUri.getScheme()));
            }
        }
        catch (final URISyntaxException e) {
            throw new LDQJdbcDriverRuntimeException(String.format("Invalid token endpoint URL: %s", property), e);
        }
    }

}
