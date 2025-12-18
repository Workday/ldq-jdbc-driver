/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.LDQ_JDBC_DRIVER_NAME;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import com.workday.ldq.jdbc.api.LDQJdbcDriver;

/**
 * Wraps Trino {@link java.sql.DatabaseMetaData} to return Workday-branded driver information.
 * Delegates all methods to the underlying Trino metadata except for driver-specific methods
 * ({@link #getDriverName()}, {@link #getDriverVersion()}, {@link #getDriverMajorVersion()},
 * {@link #getDriverMinorVersion()}) and {@link #getDatabaseProductName()}, which return
 * LDQ JDBC values.
 *
 */
final class LDQJdbcDatabaseMetaData extends DelegatingDatabaseMetaData {

    /**
     * Creates a wrapper for the Trino DatabaseMetaData.
     *
     * @param metadata the Trino {@link DatabaseMetaData} to delegate all calls to
     * @param connection the wrapped {@link Connection} to return from {@link #getConnection()}
     */
    public LDQJdbcDatabaseMetaData(final DatabaseMetaData metadata, final Connection connection) {
        super(metadata, connection);
    }

    @Override
    public String getDriverName() throws SQLException {
        return LDQ_JDBC_DRIVER_NAME;
    }

    @Override
    public String getDriverVersion() throws SQLException {
        return LDQJdbcDriver.DRIVER_VERSION;
    }

    @Override
    public int getDriverMajorVersion() {
        return LDQJdbcDriver.MAJOR_VERSION;
    }

    @Override
    public int getDriverMinorVersion() {
        return LDQJdbcDriver.MINOR_VERSION;
    }

    @Override
    public String getDatabaseProductName() {
        return LDQJdbcAuthnConstants.LDQ_PRODUCT_NAME;
    }
}
