/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import com.workday.ldq.jdbc.impl.oauth.TokenManager;

/**
 * Wraps a Trino JDBC Connection {@link Connection}
 * Delegates all Connection methods to the underlying Trino connection, except for
 * {@link #getMetaData()} which returns custom LDQ JDBC driver information.
 * {@link #close()}
 *
 */
public final class LDQJdbcConnection extends DelegatingConnection {

    private final TokenManager tokenManager;

    /**
     * Creates a wrapper for the Trino Connection.
     *
     * @param delegateConnection the Trino {@link Connection} to delegate all calls to
     * @param tokenManager the token manager used to acquire tokens for this connection
     */
    public LDQJdbcConnection(final Connection delegateConnection, final TokenManager tokenManager) {
        super(delegateConnection);
        this.tokenManager = tokenManager;
    }

    @Override
    public DatabaseMetaData getMetaData()
        throws SQLException {
        final DatabaseMetaData trinoMetadata = this.delegate.getMetaData();
        return new LDQJdbcDatabaseMetaData(trinoMetadata, this);
    }

    @Override
    public void close()
        throws SQLException {
        try {
            super.close();
        }
        finally {
            this.tokenManager.close();
        }
    }
}
