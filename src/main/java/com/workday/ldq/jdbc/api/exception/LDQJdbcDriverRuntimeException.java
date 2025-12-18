/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.api.exception;

/**
 * Unchecked exception thrown by the Workday LDQ JDBC driver for unrecoverable configuration and
 * initialization errors.
 * This exception is thrown in the following (non-exhaustive) scenarios:
 * - Invalid driver configuration (missing required properties, invalid property values, etc.)
 * - Failed to parse private key for JWT signing
 * - Failed to initialize HTTP client for token requests
 * - Failed to obtain access token from OAuth server
 *
 */
public class LDQJdbcDriverRuntimeException
    extends RuntimeException {

    public LDQJdbcDriverRuntimeException(final String message) {
        super(message);
    }

    public LDQJdbcDriverRuntimeException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
