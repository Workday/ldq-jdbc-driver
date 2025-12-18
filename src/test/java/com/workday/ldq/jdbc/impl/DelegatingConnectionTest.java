/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.ShardingKey;
import java.sql.Statement;
import java.sql.Struct;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link DelegatingConnection} to ensure all methods properly delegate
 * to the underlying connection without modification.
 * <p>
 * Note: SpotBugs warnings about unclosed Statement resources are false positives.
 * This test class uses Mockito mocks which don't require actual resource cleanup.
 * The verify() calls create mock proxies, not real database resources.
 *
 */
@ExtendWith(MockitoExtension.class)
class DelegatingConnectionTest {

    @Mock
    private Connection mockDelegate;

    private DelegatingConnection delegatingConnection;

    @BeforeEach
    void setUp() {
        this.delegatingConnection = new DelegatingConnection(this.mockDelegate) {
            // Concrete implementation for testing
        };
    }

    @Test
    @DisplayName("createStatement() delegates without modification")
    void testCreateStatement()
        throws SQLException {
        final Statement mockStatement = org.mockito.Mockito.mock(Statement.class);
        when(this.mockDelegate.createStatement()).thenReturn(mockStatement);

        try (Statement result = this.delegatingConnection.createStatement()) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).createStatement();
    }

    @Test
    @DisplayName("createStatement(int, int) delegates without modification")
    void testCreateStatementWithParams()
        throws SQLException {
        final Statement mockStatement = org.mockito.Mockito.mock(Statement.class);
        when(this.mockDelegate.createStatement(anyInt(), anyInt())).thenReturn(mockStatement);

        try (Statement result = this.delegatingConnection.createStatement(
            ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).createStatement(
            ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
    }

    @Test
    @DisplayName("createStatement(int, int, int) delegates without modification")
    void testCreateStatementWithThreeParams()
        throws SQLException {
        final Statement mockStatement = org.mockito.Mockito.mock(Statement.class);
        when(this.mockDelegate.createStatement(anyInt(), anyInt(), anyInt())).thenReturn(mockStatement);

        try (Statement result = this.delegatingConnection.createStatement(
            ResultSet.TYPE_SCROLL_INSENSITIVE,
            ResultSet.CONCUR_UPDATABLE,
            ResultSet.HOLD_CURSORS_OVER_COMMIT)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).createStatement(
            ResultSet.TYPE_SCROLL_INSENSITIVE,
            ResultSet.CONCUR_UPDATABLE,
            ResultSet.HOLD_CURSORS_OVER_COMMIT);
    }

    @Test
    @DisplayName("prepareStatement(String) delegates without modification")
    void testPrepareStatement()
        throws SQLException {
        final PreparedStatement mockStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        when(this.mockDelegate.prepareStatement(anyString())).thenReturn(mockStatement);

        try (PreparedStatement result = this.delegatingConnection.prepareStatement("SELECT 1")) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareStatement("SELECT 1");
    }

    @Test
    @DisplayName("prepareStatement(String, int, int) delegates without modification")
    void testPrepareStatementWithParams()
        throws SQLException {
        final PreparedStatement mockStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        when(this.mockDelegate.prepareStatement(anyString(), anyInt(), anyInt())).thenReturn(mockStatement);

        try (PreparedStatement result = this.delegatingConnection.prepareStatement("SELECT 1",
            ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareStatement("SELECT 1",
            ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
    }

    @Test
    @DisplayName("prepareStatement(String, int, int, int) delegates without modification")
    void testPrepareStatementWithThreeParams()
        throws SQLException {
        final PreparedStatement mockStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        when(this.mockDelegate.prepareStatement(anyString(), anyInt(), anyInt(), anyInt())).thenReturn(mockStatement);

        try (PreparedStatement result = this.delegatingConnection.prepareStatement("SELECT 1",
            ResultSet.TYPE_SCROLL_INSENSITIVE,
            ResultSet.CONCUR_UPDATABLE,
            ResultSet.HOLD_CURSORS_OVER_COMMIT)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareStatement("SELECT 1",
            ResultSet.TYPE_SCROLL_INSENSITIVE,
            ResultSet.CONCUR_UPDATABLE,
            ResultSet.HOLD_CURSORS_OVER_COMMIT);
    }


    @Test
    @DisplayName("prepareStatement(String, int) delegates without modification")
    void testPrepareStatementWithAutoGeneratedKeys()
        throws SQLException {
        final PreparedStatement mockStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        when(this.mockDelegate.prepareStatement(anyString(), anyInt())).thenReturn(mockStatement);

        try (PreparedStatement result = this.delegatingConnection.prepareStatement("INSERT INTO t VALUES (1)",
            1)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareStatement("INSERT INTO t VALUES (1)", 1);
    }

    @Test
    @DisplayName("prepareStatement(String, int[]) delegates without modification")
    void testPrepareStatementWithColumnIndexes()
        throws SQLException {
        final PreparedStatement mockStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        final int[] columnIndexes = {1, 2};
        when(this.mockDelegate.prepareStatement(anyString(), any(int[].class))).thenReturn(mockStatement);

        try (PreparedStatement result =
            this.delegatingConnection.prepareStatement("INSERT INTO t VALUES (1)", columnIndexes)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareStatement("INSERT INTO t VALUES (1)", columnIndexes);
    }

    @Test
    @DisplayName("prepareStatement(String, String[]) delegates without modification")
    void testPrepareStatementWithColumnNames()
        throws SQLException {
        final PreparedStatement mockStatement = org.mockito.Mockito.mock(PreparedStatement.class);
        final String[] columnNames = {"id", "name"};
        when(this.mockDelegate.prepareStatement(anyString(), any(String[].class))).thenReturn(mockStatement);

        try (PreparedStatement result =
            this.delegatingConnection.prepareStatement("INSERT INTO t VALUES (1)", columnNames)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareStatement("INSERT INTO t VALUES (1)", columnNames);
    }

    @Test
    @DisplayName("prepareCall(String) delegates without modification")
    void testPrepareCall()
        throws SQLException {
        final CallableStatement mockStatement = org.mockito.Mockito.mock(CallableStatement.class);
        when(this.mockDelegate.prepareCall(anyString())).thenReturn(mockStatement);

        try (CallableStatement result = this.delegatingConnection.prepareCall("{call proc}")) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareCall("{call proc}");
    }

    @Test
    @DisplayName("prepareCall(String, int, int) delegates without modification")
    void testPrepareCallWithParams()
        throws SQLException {
        final CallableStatement mockStatement = org.mockito.Mockito.mock(CallableStatement.class);
        when(this.mockDelegate.prepareCall(anyString(), anyInt(), anyInt())).thenReturn(mockStatement);

        try (CallableStatement result = this.delegatingConnection.prepareCall("{call proc}",
            ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareCall("{call proc}",
            ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
    }

    @Test
    @DisplayName("prepareCall(String, int, int, int) delegates without modification")
    void testPrepareCallWithThreeParams()
        throws SQLException {
        final CallableStatement mockStatement = org.mockito.Mockito.mock(CallableStatement.class);
        when(this.mockDelegate.prepareCall(anyString(), anyInt(), anyInt(), anyInt())).thenReturn(mockStatement);

        try (CallableStatement result = this.delegatingConnection.prepareCall("{call proc}",
            ResultSet.TYPE_SCROLL_INSENSITIVE,
            ResultSet.CONCUR_UPDATABLE,
            ResultSet.HOLD_CURSORS_OVER_COMMIT)) {
            assertSame(mockStatement, result);
        }

        verify(this.mockDelegate).prepareCall("{call proc}",
            ResultSet.TYPE_SCROLL_INSENSITIVE,
            ResultSet.CONCUR_UPDATABLE,
            ResultSet.HOLD_CURSORS_OVER_COMMIT);
    }

    @Test
    @DisplayName("nativeSQL() delegates without modification")
    void testNativeSQL()
        throws SQLException {
        when(this.mockDelegate.nativeSQL(anyString())).thenReturn("native sql");

        final String result = this.delegatingConnection.nativeSQL("SELECT 1");

        assertEquals("native sql", result);
        verify(this.mockDelegate).nativeSQL("SELECT 1");
    }

    @Test
    @DisplayName("setAutoCommit() delegates without modification")
    void testSetAutoCommit()
        throws SQLException {
        this.delegatingConnection.setAutoCommit(true);

        verify(this.mockDelegate).setAutoCommit(true);
    }

    @Test
    @DisplayName("getAutoCommit() delegates without modification")
    void testGetAutoCommit()
        throws SQLException {
        when(this.mockDelegate.getAutoCommit()).thenReturn(true);

        final boolean result = this.delegatingConnection.getAutoCommit();

        assertTrue(result);
        verify(this.mockDelegate).getAutoCommit();
    }

    @Test
    @DisplayName("commit() delegates without modification")
    void testCommit()
        throws SQLException {
        this.delegatingConnection.commit();

        verify(this.mockDelegate).commit();
    }

    @Test
    @DisplayName("rollback() delegates without modification")
    void testRollback()
        throws SQLException {
        this.delegatingConnection.rollback();

        verify(this.mockDelegate).rollback();
    }

    @Test
    @DisplayName("rollback(Savepoint) delegates without modification")
    void testRollbackWithSavepoint()
        throws SQLException {
        final Savepoint mockSavepoint = org.mockito.Mockito.mock(Savepoint.class);

        this.delegatingConnection.rollback(mockSavepoint);

        verify(this.mockDelegate).rollback(mockSavepoint);
    }

    @Test
    @DisplayName("close() delegates without modification")
    void testClose()
        throws SQLException {
        this.delegatingConnection.close();

        verify(this.mockDelegate).close();
    }

    @Test
    @DisplayName("isClosed() delegates without modification")
    void testIsClosed()
        throws SQLException {
        when(this.mockDelegate.isClosed()).thenReturn(true);

        final boolean result = this.delegatingConnection.isClosed();

        assertTrue(result);
        verify(this.mockDelegate).isClosed();
    }

    @Test
    @DisplayName("getMetaData() delegates without modification")
    void testGetMetaData()
        throws SQLException {
        final DatabaseMetaData mockMetaData = org.mockito.Mockito.mock(DatabaseMetaData.class);
        when(this.mockDelegate.getMetaData()).thenReturn(mockMetaData);

        final DatabaseMetaData result = this.delegatingConnection.getMetaData();

        assertSame(mockMetaData, result);
        verify(this.mockDelegate).getMetaData();
    }

    @Test
    @DisplayName("setReadOnly() delegates without modification")
    void testSetReadOnly()
        throws SQLException {
        this.delegatingConnection.setReadOnly(true);

        verify(this.mockDelegate).setReadOnly(true);
    }

    @Test
    @DisplayName("isReadOnly() delegates without modification")
    void testIsReadOnly()
        throws SQLException {
        when(this.mockDelegate.isReadOnly()).thenReturn(true);

        final boolean result = this.delegatingConnection.isReadOnly();

        assertTrue(result);
        verify(this.mockDelegate).isReadOnly();
    }

    @Test
    @DisplayName("setCatalog() delegates without modification")
    void testSetCatalog()
        throws SQLException {
        this.delegatingConnection.setCatalog("catalog");

        verify(this.mockDelegate).setCatalog("catalog");
    }

    @Test
    @DisplayName("getCatalog() delegates without modification")
    void testGetCatalog()
        throws SQLException {
        when(this.mockDelegate.getCatalog()).thenReturn("catalog");

        final String result = this.delegatingConnection.getCatalog();

        assertEquals("catalog", result);
        verify(this.mockDelegate).getCatalog();
    }

    @Test
    @DisplayName("setTransactionIsolation() delegates without modification")
    void testSetTransactionIsolation()
        throws SQLException {
        this.delegatingConnection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);

        verify(this.mockDelegate).setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
    }

    @Test
    @DisplayName("getTransactionIsolation() delegates without modification")
    void testGetTransactionIsolation()
        throws SQLException {
        when(this.mockDelegate.getTransactionIsolation()).thenReturn(Connection.TRANSACTION_READ_COMMITTED);

        final int result = this.delegatingConnection.getTransactionIsolation();

        assertEquals(Connection.TRANSACTION_READ_COMMITTED, result);
        verify(this.mockDelegate).getTransactionIsolation();
    }

    @Test
    @DisplayName("getWarnings() delegates without modification")
    void testGetWarnings()
        throws SQLException {
        final java.sql.SQLWarning mockWarning = org.mockito.Mockito.mock(java.sql.SQLWarning.class);
        when(this.mockDelegate.getWarnings()).thenReturn(mockWarning);

        final java.sql.SQLWarning result = this.delegatingConnection.getWarnings();

        assertSame(mockWarning, result);
        verify(this.mockDelegate).getWarnings();
    }

    @Test
    @DisplayName("clearWarnings() delegates without modification")
    void testClearWarnings()
        throws SQLException {
        this.delegatingConnection.clearWarnings();

        verify(this.mockDelegate).clearWarnings();
    }

    @Test
    @DisplayName("getTypeMap() delegates without modification")
    void testGetTypeMap()
        throws SQLException {
        final Map<String, Class<?>> mockTypeMap = org.mockito.Mockito.mock(Map.class);
        when(this.mockDelegate.getTypeMap()).thenReturn(mockTypeMap);

        final Map<String, Class<?>> result = this.delegatingConnection.getTypeMap();

        assertSame(mockTypeMap, result);
        verify(this.mockDelegate).getTypeMap();
    }

    @Test
    @DisplayName("setTypeMap() delegates without modification")
    void testSetTypeMap()
        throws SQLException {
        final Map<String, Class<?>> mockTypeMap = org.mockito.Mockito.mock(Map.class);

        this.delegatingConnection.setTypeMap(mockTypeMap);

        verify(this.mockDelegate).setTypeMap(mockTypeMap);
    }

    @Test
    @DisplayName("setHoldability() delegates without modification")
    void testSetHoldability()
        throws SQLException {
        this.delegatingConnection.setHoldability(1);

        verify(this.mockDelegate).setHoldability(1);
    }

    @Test
    @DisplayName("getHoldability() delegates without modification")
    void testGetHoldability()
        throws SQLException {
        when(this.mockDelegate.getHoldability()).thenReturn(1);

        final int result = this.delegatingConnection.getHoldability();

        assertEquals(1, result);
        verify(this.mockDelegate).getHoldability();
    }

    @Test
    @DisplayName("setSavepoint() delegates without modification")
    void testSetSavepoint()
        throws SQLException {
        final Savepoint mockSavepoint = org.mockito.Mockito.mock(Savepoint.class);
        when(this.mockDelegate.setSavepoint()).thenReturn(mockSavepoint);

        final Savepoint result = this.delegatingConnection.setSavepoint();

        assertSame(mockSavepoint, result);
        verify(this.mockDelegate).setSavepoint();
    }

    @Test
    @DisplayName("setSavepoint(String) delegates without modification")
    void testSetSavepointWithName()
        throws SQLException {
        final Savepoint mockSavepoint = org.mockito.Mockito.mock(Savepoint.class);
        when(this.mockDelegate.setSavepoint(anyString())).thenReturn(mockSavepoint);

        final Savepoint result = this.delegatingConnection.setSavepoint("sp1");

        assertSame(mockSavepoint, result);
        verify(this.mockDelegate).setSavepoint("sp1");
    }

    @Test
    @DisplayName("releaseSavepoint() delegates without modification")
    void testReleaseSavepoint()
        throws SQLException {
        final Savepoint mockSavepoint = org.mockito.Mockito.mock(Savepoint.class);

        this.delegatingConnection.releaseSavepoint(mockSavepoint);

        verify(this.mockDelegate).releaseSavepoint(mockSavepoint);
    }

    @Test
    @DisplayName("createClob() delegates without modification")
    void testCreateClob()
        throws SQLException {
        final Clob mockClob = org.mockito.Mockito.mock(Clob.class);
        when(this.mockDelegate.createClob()).thenReturn(mockClob);

        final Clob result = this.delegatingConnection.createClob();

        assertSame(mockClob, result);
        verify(this.mockDelegate).createClob();
    }

    @Test
    @DisplayName("createBlob() delegates without modification")
    void testCreateBlob()
        throws SQLException {
        final Blob mockBlob = org.mockito.Mockito.mock(Blob.class);
        when(this.mockDelegate.createBlob()).thenReturn(mockBlob);

        final Blob result = this.delegatingConnection.createBlob();

        assertSame(mockBlob, result);
        verify(this.mockDelegate).createBlob();
    }

    @Test
    @DisplayName("createNClob() delegates without modification")
    void testCreateNClob()
        throws SQLException {
        final NClob mockNClob = org.mockito.Mockito.mock(NClob.class);
        when(this.mockDelegate.createNClob()).thenReturn(mockNClob);

        final NClob result = this.delegatingConnection.createNClob();

        assertSame(mockNClob, result);
        verify(this.mockDelegate).createNClob();
    }

    @Test
    @DisplayName("createSQLXML() delegates without modification")
    void testCreateSQLXML()
        throws SQLException {
        final SQLXML mockSQLXML = org.mockito.Mockito.mock(SQLXML.class);
        when(this.mockDelegate.createSQLXML()).thenReturn(mockSQLXML);

        final SQLXML result = this.delegatingConnection.createSQLXML();

        assertSame(mockSQLXML, result);
        verify(this.mockDelegate).createSQLXML();
    }

    @Test
    @DisplayName("isValid() delegates without modification")
    void testIsValid()
        throws SQLException {
        when(this.mockDelegate.isValid(anyInt())).thenReturn(true);

        final boolean result = this.delegatingConnection.isValid(10);

        assertTrue(result);
        verify(this.mockDelegate).isValid(10);
    }

    @Test
    @DisplayName("setClientInfo(String, String) delegates without modification")
    void testSetClientInfoWithNameValue()
        throws SQLClientInfoException {
        this.delegatingConnection.setClientInfo("name", "value");

        verify(this.mockDelegate).setClientInfo("name", "value");
    }

    @Test
    @DisplayName("setClientInfo(Properties) delegates without modification")
    void testSetClientInfoWithProperties()
        throws SQLClientInfoException {
        final Properties props = new Properties();

        this.delegatingConnection.setClientInfo(props);

        verify(this.mockDelegate).setClientInfo(props);
    }

    @Test
    @DisplayName("getClientInfo(String) delegates without modification")
    void testGetClientInfoWithName()
        throws SQLException {
        when(this.mockDelegate.getClientInfo(anyString())).thenReturn("value");

        final String result = this.delegatingConnection.getClientInfo("name");

        assertEquals("value", result);
        verify(this.mockDelegate).getClientInfo("name");
    }

    @Test
    @DisplayName("getClientInfo() delegates without modification")
    void testGetClientInfo()
        throws SQLException {
        final Properties mockProps = new Properties();
        when(this.mockDelegate.getClientInfo()).thenReturn(mockProps);

        final Properties result = this.delegatingConnection.getClientInfo();

        assertSame(mockProps, result);
        verify(this.mockDelegate).getClientInfo();
    }

    @Test
    @DisplayName("createArrayOf() delegates without modification")
    void testCreateArrayOf()
        throws SQLException {
        final Array mockArray = org.mockito.Mockito.mock(Array.class);
        final Object[] elements = {1, 2, 3};
        when(this.mockDelegate.createArrayOf(anyString(), any(Object[].class))).thenReturn(mockArray);

        final Array result = this.delegatingConnection.createArrayOf("INTEGER", elements);

        assertSame(mockArray, result);
        verify(this.mockDelegate).createArrayOf("INTEGER", elements);
    }

    @Test
    @DisplayName("createStruct() delegates without modification")
    void testCreateStruct()
        throws SQLException {
        final Struct mockStruct = org.mockito.Mockito.mock(Struct.class);
        final Object[] attributes = {1, "test"};
        when(this.mockDelegate.createStruct(anyString(), any(Object[].class))).thenReturn(mockStruct);

        final Struct result = this.delegatingConnection.createStruct("TYPE", attributes);

        assertSame(mockStruct, result);
        verify(this.mockDelegate).createStruct("TYPE", attributes);
    }

    @Test
    @DisplayName("setSchema() delegates without modification")
    void testSetSchema()
        throws SQLException {
        this.delegatingConnection.setSchema("schema");

        verify(this.mockDelegate).setSchema("schema");
    }

    @Test
    @DisplayName("getSchema() delegates without modification")
    void testGetSchema()
        throws SQLException {
        when(this.mockDelegate.getSchema()).thenReturn("schema");

        final String result = this.delegatingConnection.getSchema();

        assertEquals("schema", result);
        verify(this.mockDelegate).getSchema();
    }

    @Test
    @DisplayName("abort() delegates without modification")
    void testAbort()
        throws SQLException {
        final Executor mockExecutor = org.mockito.Mockito.mock(Executor.class);

        this.delegatingConnection.abort(mockExecutor);

        verify(this.mockDelegate).abort(mockExecutor);
    }

    @Test
    @DisplayName("setNetworkTimeout() delegates without modification")
    void testSetNetworkTimeout()
        throws SQLException {
        final Executor mockExecutor = org.mockito.Mockito.mock(Executor.class);

        this.delegatingConnection.setNetworkTimeout(mockExecutor, 1000);

        verify(this.mockDelegate).setNetworkTimeout(mockExecutor, 1000);
    }

    @Test
    @DisplayName("getNetworkTimeout() delegates without modification")
    void testGetNetworkTimeout()
        throws SQLException {
        when(this.mockDelegate.getNetworkTimeout()).thenReturn(1000);

        final int result = this.delegatingConnection.getNetworkTimeout();

        assertEquals(1000, result);
        verify(this.mockDelegate).getNetworkTimeout();
    }

    @Test
    @DisplayName("beginRequest() delegates without modification")
    void testBeginRequest()
        throws SQLException {
        this.delegatingConnection.beginRequest();

        verify(this.mockDelegate).beginRequest();
    }

    @Test
    @DisplayName("endRequest() delegates without modification")
    void testEndRequest()
        throws SQLException {
        this.delegatingConnection.endRequest();

        verify(this.mockDelegate).endRequest();
    }

    @Test
    @DisplayName("setShardingKeyIfValid(ShardingKey, ShardingKey, int) delegates without modification")
    void testSetShardingKeyIfValidWithTwoKeys()
        throws SQLException {
        final ShardingKey mockKey1 = org.mockito.Mockito.mock(ShardingKey.class);
        final ShardingKey mockKey2 = org.mockito.Mockito.mock(ShardingKey.class);
        when(this.mockDelegate.setShardingKeyIfValid(any(ShardingKey.class), any(ShardingKey.class), anyInt()))
            .thenReturn(true);

        final boolean result = this.delegatingConnection.setShardingKeyIfValid(mockKey1, mockKey2, 10);

        assertTrue(result);
        verify(this.mockDelegate).setShardingKeyIfValid(mockKey1, mockKey2, 10);
    }

    @Test
    @DisplayName("setShardingKeyIfValid(ShardingKey, int) delegates without modification")
    void testSetShardingKeyIfValidWithOneKey()
        throws SQLException {
        final ShardingKey mockKey = org.mockito.Mockito.mock(ShardingKey.class);
        when(this.mockDelegate.setShardingKeyIfValid(any(ShardingKey.class), anyInt())).thenReturn(true);

        final boolean result = this.delegatingConnection.setShardingKeyIfValid(mockKey, 10);

        assertTrue(result);
        verify(this.mockDelegate).setShardingKeyIfValid(mockKey, 10);
    }

    @Test
    @DisplayName("setShardingKey(ShardingKey, ShardingKey) delegates without modification")
    void testSetShardingKeyWithTwoKeys()
        throws SQLException {
        final ShardingKey mockKey1 = org.mockito.Mockito.mock(ShardingKey.class);
        final ShardingKey mockKey2 = org.mockito.Mockito.mock(ShardingKey.class);

        this.delegatingConnection.setShardingKey(mockKey1, mockKey2);

        verify(this.mockDelegate).setShardingKey(mockKey1, mockKey2);
    }

    @Test
    @DisplayName("setShardingKey(ShardingKey) delegates without modification")
    void testSetShardingKeyWithOneKey()
        throws SQLException {
        final ShardingKey mockKey = org.mockito.Mockito.mock(ShardingKey.class);

        this.delegatingConnection.setShardingKey(mockKey);

        verify(this.mockDelegate).setShardingKey(mockKey);
    }

    @Test
    @DisplayName("unwrap() returns this when interface matches")
    void testUnwrapReturnsThis()
        throws SQLException {
        final Connection result = this.delegatingConnection.unwrap(Connection.class);

        assertSame(this.delegatingConnection, result);
        verify(this.mockDelegate, never()).unwrap(any());
    }

    @Test
    @DisplayName("unwrap() delegates when interface does not match")
    void testUnwrapDelegates()
        throws SQLException {
        final Statement mockStatement = mock(Statement.class);
        when(this.mockDelegate.unwrap(eq(Statement.class))).thenReturn(mockStatement);

        final Statement result = this.delegatingConnection.unwrap(Statement.class);

        assertSame(mockStatement, result);
        verify(this.mockDelegate).unwrap(Statement.class);
    }

    @Test
    @DisplayName("isWrapperFor() returns true when interface matches")
    void testIsWrapperForReturnsTrue()
        throws SQLException {
        final boolean result = this.delegatingConnection.isWrapperFor(Connection.class);

        assertTrue(result);
        verify(this.mockDelegate, never()).isWrapperFor(any());
    }

    @Test
    @DisplayName("isWrapperFor() delegates when interface does not match")
    void testIsWrapperForDelegates()
        throws SQLException {
        when(this.mockDelegate.isWrapperFor(eq(Statement.class))).thenReturn(true);

        final boolean result = this.delegatingConnection.isWrapperFor(Statement.class);

        assertTrue(result);
        verify(this.mockDelegate).isWrapperFor(Statement.class);
    }
}
