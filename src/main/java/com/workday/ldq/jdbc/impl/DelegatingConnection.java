/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Base connection implementation of {@link Connection}, delegates all calls to the underlying implementation.
 * Subclasses can override specific methods to customize behavior.
 *
 */
abstract class DelegatingConnection
    implements Connection {

    protected final Connection delegate;

    protected DelegatingConnection(final Connection delegate) {
        this.delegate = delegate;
    }

    @Override
    public java.sql.Statement createStatement()
        throws SQLException {
        return this.delegate.createStatement();
    }

    @Override
    public java.sql.PreparedStatement prepareStatement(final String sql)
        throws SQLException {
        return this.delegate.prepareStatement(sql);
    }

    @Override
    public java.sql.CallableStatement prepareCall(final String sql)
        throws SQLException {
        return this.delegate.prepareCall(sql);
    }

    @Override
    public String nativeSQL(final String sql)
        throws SQLException {
        return this.delegate.nativeSQL(sql);
    }

    @Override
    public void setAutoCommit(final boolean autoCommit)
        throws SQLException {
        this.delegate.setAutoCommit(autoCommit);
    }

    @Override
    public boolean getAutoCommit()
        throws SQLException {
        return this.delegate.getAutoCommit();
    }

    @Override
    public void commit()
        throws SQLException {
        this.delegate.commit();
    }

    @Override
    public void rollback()
        throws SQLException {
        this.delegate.rollback();
    }

    @Override
    public void close()
        throws SQLException {
        this.delegate.close();
    }

    @Override
    public boolean isClosed()
        throws SQLException {
        return this.delegate.isClosed();
    }

    @Override
    public java.sql.DatabaseMetaData getMetaData()
        throws SQLException {
        return this.delegate.getMetaData();
    }

    @Override
    public void setReadOnly(final boolean readOnly)
        throws SQLException {
        this.delegate.setReadOnly(readOnly);
    }

    @Override
    public boolean isReadOnly()
        throws SQLException {
        return this.delegate.isReadOnly();
    }

    @Override
    public void setCatalog(final String catalog)
        throws SQLException {
        this.delegate.setCatalog(catalog);
    }

    @Override
    public String getCatalog()
        throws SQLException {
        return this.delegate.getCatalog();
    }

    @Override
    public void setTransactionIsolation(final int level)
        throws SQLException {
        this.delegate.setTransactionIsolation(level);
    }

    @Override
    public int getTransactionIsolation()
        throws SQLException {
        return this.delegate.getTransactionIsolation();
    }

    @Override
    public java.sql.SQLWarning getWarnings()
        throws SQLException {
        return this.delegate.getWarnings();
    }

    @Override
    public void clearWarnings()
        throws SQLException {
        this.delegate.clearWarnings();
    }

    @Override
    public java.sql.Statement createStatement(final int resultSetType, final int resultSetConcurrency)
        throws SQLException {
        return this.delegate.createStatement(resultSetType, resultSetConcurrency);
    }

    @Override
    public java.sql.PreparedStatement prepareStatement(final String sql,
                                                       final int resultSetType,
                                                       final int resultSetConcurrency)
        throws SQLException {
        return this.delegate.prepareStatement(sql, resultSetType, resultSetConcurrency);
    }

    @Override
    public java.sql.CallableStatement prepareCall(final String sql,
                                                  final int resultSetType,
                                                  final int resultSetConcurrency)
        throws SQLException {
        return this.delegate.prepareCall(sql, resultSetType, resultSetConcurrency);
    }

    @Override
    public java.util.Map<String, Class<?>> getTypeMap()
        throws SQLException {
        return this.delegate.getTypeMap();
    }

    @Override
    public void setTypeMap(final java.util.Map<String, Class<?>> map)
        throws SQLException {
        this.delegate.setTypeMap(map);
    }

    @Override
    public void setHoldability(final int holdability)
        throws SQLException {
        this.delegate.setHoldability(holdability);
    }

    @Override
    public int getHoldability()
        throws SQLException {
        return this.delegate.getHoldability();
    }

    @Override
    public java.sql.Savepoint setSavepoint()
        throws SQLException {
        return this.delegate.setSavepoint();
    }

    @Override
    public java.sql.Savepoint setSavepoint(final String name)
        throws SQLException {
        return this.delegate.setSavepoint(name);
    }

    @Override
    public void rollback(final java.sql.Savepoint savepoint)
        throws SQLException {
        this.delegate.rollback(savepoint);
    }

    @Override
    public void releaseSavepoint(final java.sql.Savepoint savepoint)
        throws SQLException {
        this.delegate.releaseSavepoint(savepoint);
    }

    @Override
    public java.sql.Statement createStatement(final int resultSetType,
                                              final int resultSetConcurrency,
                                              final int resultSetHoldability)
        throws SQLException {
        return this.delegate.createStatement(resultSetType, resultSetConcurrency, resultSetHoldability);
    }

    @Override
    public java.sql.PreparedStatement prepareStatement(final String sql,
                                                       final int resultSetType,
                                                       final int resultSetConcurrency,
                                                       final int resultSetHoldability)
        throws SQLException {
        return this.delegate.prepareStatement(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
    }

    @Override
    public java.sql.CallableStatement prepareCall(final String sql,
                                                  final int resultSetType,
                                                  final int resultSetConcurrency,
                                                  final int resultSetHoldability)
        throws SQLException {
        return this.delegate.prepareCall(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
    }

    @Override
    public java.sql.PreparedStatement prepareStatement(final String sql, final int autoGeneratedKeys)
        throws SQLException {
        return this.delegate.prepareStatement(sql, autoGeneratedKeys);
    }

    @Override
    public java.sql.PreparedStatement prepareStatement(final String sql, final int[] columnIndexes)
        throws SQLException {
        return this.delegate.prepareStatement(sql, columnIndexes);
    }

    @Override
    public java.sql.PreparedStatement prepareStatement(final String sql, final String[] columnNames)
        throws SQLException {
        return this.delegate.prepareStatement(sql, columnNames);
    }

    @Override
    public java.sql.Clob createClob()
        throws SQLException {
        return this.delegate.createClob();
    }

    @Override
    public java.sql.Blob createBlob()
        throws SQLException {
        return this.delegate.createBlob();
    }

    @Override
    public java.sql.NClob createNClob()
        throws SQLException {
        return this.delegate.createNClob();
    }

    @Override
    public java.sql.SQLXML createSQLXML()
        throws SQLException {
        return this.delegate.createSQLXML();
    }

    @Override
    public boolean isValid(final int timeout)
        throws SQLException {
        return this.delegate.isValid(timeout);
    }

    @Override
    public void setClientInfo(final String name, final String value)
        throws java.sql.SQLClientInfoException {
        this.delegate.setClientInfo(name, value);
    }

    @Override
    public void setClientInfo(final java.util.Properties properties)
        throws java.sql.SQLClientInfoException {
        this.delegate.setClientInfo(properties);
    }

    @Override
    public String getClientInfo(final String name)
        throws SQLException {
        return this.delegate.getClientInfo(name);
    }

    @Override
    public java.util.Properties getClientInfo()
        throws SQLException {
        return this.delegate.getClientInfo();
    }

    @Override
    public java.sql.Array createArrayOf(final String typeName, final Object[] elements)
        throws SQLException {
        return this.delegate.createArrayOf(typeName, elements);
    }

    @Override
    public java.sql.Struct createStruct(final String typeName, final Object[] attributes)
        throws SQLException {
        return this.delegate.createStruct(typeName, attributes);
    }

    @Override
    public void setSchema(final String schema)
        throws SQLException {
        this.delegate.setSchema(schema);
    }

    @Override
    public String getSchema()
        throws SQLException {
        return this.delegate.getSchema();
    }

    @Override
    public void abort(final java.util.concurrent.Executor executor)
        throws SQLException {
        this.delegate.abort(executor);
    }

    @Override
    public void setNetworkTimeout(final java.util.concurrent.Executor executor, final int milliseconds)
        throws SQLException {
        this.delegate.setNetworkTimeout(executor, milliseconds);
    }

    @Override
    public int getNetworkTimeout()
        throws SQLException {
        return this.delegate.getNetworkTimeout();
    }

    @Override
    public void beginRequest()
        throws SQLException {
        this.delegate.beginRequest();
    }

    @Override
    public void endRequest()
        throws SQLException {
        this.delegate.endRequest();
    }

    @Override
    public boolean setShardingKeyIfValid(final java.sql.ShardingKey shardingKey,
                                         final java.sql.ShardingKey superShardingKey,
                                         final int timeout)
        throws SQLException {
        return this.delegate.setShardingKeyIfValid(shardingKey, superShardingKey, timeout);
    }

    @Override
    public boolean setShardingKeyIfValid(final java.sql.ShardingKey shardingKey, final int timeout)
        throws SQLException {
        return this.delegate.setShardingKeyIfValid(shardingKey, timeout);
    }

    @Override
    public void setShardingKey(final java.sql.ShardingKey shardingKey, final java.sql.ShardingKey superShardingKey)
        throws SQLException {
        this.delegate.setShardingKey(shardingKey, superShardingKey);
    }

    @Override
    public void setShardingKey(final java.sql.ShardingKey shardingKey)
        throws SQLException {
        this.delegate.setShardingKey(shardingKey);
    }

    @Override
    public <T> T unwrap(final Class<T> iface)
        throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        return this.delegate.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(final Class<?> iface)
        throws SQLException {
        return iface.isInstance(this) || this.delegate.isWrapperFor(iface);
    }
}
