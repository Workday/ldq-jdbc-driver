/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.RowIdLifetime;
import java.sql.SQLException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link DelegatingDatabaseMetaData}.
 * Tests a representative sample of methods covering different return types and parameter patterns.
 *
 */
@ExtendWith(MockitoExtension.class)
class DelegatingDatabaseMetaDataTest {

    @Mock
    private DatabaseMetaData mockDelegate;

    @Mock
    private Connection mockConnection;

    private DelegatingDatabaseMetaData delegatingMetaData;

    @BeforeEach
    void setUp() {
        this.delegatingMetaData = new ConcreteDelegatingDatabaseMetaData(this.mockDelegate, this.mockConnection);
    }

    // Concrete implementation for testing
    private static class ConcreteDelegatingDatabaseMetaData
        extends DelegatingDatabaseMetaData {

        protected ConcreteDelegatingDatabaseMetaData(final DatabaseMetaData delegate, final Connection connection) {
            super(delegate, connection);
        }
    }

    // Constructor and field tests

    @Test
    @DisplayName("Constructor initializes delegate and connection fields")
    void testConstructor() {
        assertSame(this.mockDelegate, this.delegatingMetaData.delegate);
        assertSame(this.mockConnection, this.delegatingMetaData.connection);
    }

    @Test
    @DisplayName("getConnection() returns the connection field")
    void testGetConnection() {
        final Connection result = this.delegatingMetaData.getConnection();
        assertSame(this.mockConnection, result);
    }

    // Boolean methods - no parameters

    @Test
    @DisplayName("allProceduresAreCallable() delegates")
    void testAllProceduresAreCallable()
        throws SQLException {
        when(this.mockDelegate.allProceduresAreCallable()).thenReturn(true);

        final boolean result = this.delegatingMetaData.allProceduresAreCallable();

        assertTrue(result);
        verify(this.mockDelegate).allProceduresAreCallable();
    }

    @Test
    @DisplayName("supportsTransactions() delegates")
    void testSupportsTransactions()
        throws SQLException {
        when(this.mockDelegate.supportsTransactions()).thenReturn(false);

        final boolean result = this.delegatingMetaData.supportsTransactions();

        assertFalse(result);
        verify(this.mockDelegate).supportsTransactions();
    }

    // String methods

    @Test
    @DisplayName("getURL() delegates")
    void testGetURL()
        throws SQLException {
        when(this.mockDelegate.getURL()).thenReturn("jdbc:test://localhost");

        final String result = this.delegatingMetaData.getURL();

        assertEquals("jdbc:test://localhost", result);
        verify(this.mockDelegate).getURL();
    }

    @Test
    @DisplayName("getDatabaseProductName() delegates")
    void testGetDatabaseProductName()
        throws SQLException {
        when(this.mockDelegate.getDatabaseProductName()).thenReturn("TestDB");

        final String result = this.delegatingMetaData.getDatabaseProductName();

        assertEquals("TestDB", result);
        verify(this.mockDelegate).getDatabaseProductName();
    }

    // Int methods

    @Test
    @DisplayName("getDriverMajorVersion() delegates")
    void testGetDriverMajorVersion() {
        when(this.mockDelegate.getDriverMajorVersion()).thenReturn(1);

        final int result = this.delegatingMetaData.getDriverMajorVersion();

        assertEquals(1, result);
        verify(this.mockDelegate).getDriverMajorVersion();
    }

    @Test
    @DisplayName("getMaxConnections() delegates")
    void testGetMaxConnections()
        throws SQLException {
        when(this.mockDelegate.getMaxConnections()).thenReturn(100);

        final int result = this.delegatingMetaData.getMaxConnections();

        assertEquals(100, result);
        verify(this.mockDelegate).getMaxConnections();
    }

    // Methods with parameters

    @Test
    @DisplayName("supportsConvert(int, int) delegates")
    void testSupportsConvertWithParams()
        throws SQLException {
        when(this.mockDelegate.supportsConvert(anyInt(), anyInt())).thenReturn(true);

        final boolean result = this.delegatingMetaData.supportsConvert(1, 2);

        assertTrue(result);
        verify(this.mockDelegate).supportsConvert(1, 2);
    }

    @Test
    @DisplayName("supportsTransactionIsolationLevel(int) delegates")
    void testSupportsTransactionIsolationLevel()
        throws SQLException {
        when(this.mockDelegate.supportsTransactionIsolationLevel(anyInt())).thenReturn(true);

        final boolean result = this.delegatingMetaData.supportsTransactionIsolationLevel(
            Connection.TRANSACTION_READ_COMMITTED);

        assertTrue(result);
        verify(this.mockDelegate).supportsTransactionIsolationLevel(Connection.TRANSACTION_READ_COMMITTED);
    }

    // ResultSet-returning methods

    @Test
    @DisplayName("getTables() delegates")
    void testGetTables()
        throws SQLException {
        final ResultSet mockResultSet = mock(ResultSet.class);
        when(this.mockDelegate.getTables(anyString(), anyString(), anyString(), any(String[].class)))
            .thenReturn(mockResultSet);

        final ResultSet result = this.delegatingMetaData.getTables("catalog", "schema%", "table%",
            new String[]{"TABLE"});

        assertSame(mockResultSet, result);
        verify(this.mockDelegate).getTables("catalog", "schema%", "table%", new String[]{"TABLE"});
    }

    @Test
    @DisplayName("getColumns() delegates")
    void testGetColumns()
        throws SQLException {
        final ResultSet mockResultSet = mock(ResultSet.class);
        when(this.mockDelegate.getColumns(anyString(), anyString(), anyString(), anyString()))
            .thenReturn(mockResultSet);

        final ResultSet result = this.delegatingMetaData.getColumns("catalog", "schema", "table", "column%");

        assertSame(mockResultSet, result);
        verify(this.mockDelegate).getColumns("catalog", "schema", "table", "column%");
    }

    @Test
    @DisplayName("getPrimaryKeys() delegates")
    void testGetPrimaryKeys()
        throws SQLException {
        final ResultSet mockResultSet = mock(ResultSet.class);
        when(this.mockDelegate.getPrimaryKeys(anyString(), anyString(), anyString()))
            .thenReturn(mockResultSet);

        final ResultSet result = this.delegatingMetaData.getPrimaryKeys("catalog", "schema", "table");

        assertSame(mockResultSet, result);
        verify(this.mockDelegate).getPrimaryKeys("catalog", "schema", "table");
    }

    @Test
    @DisplayName("getIndexInfo() delegates with all parameters")
    void testGetIndexInfo()
        throws SQLException {
        final ResultSet mockResultSet = mock(ResultSet.class);
        when(this.mockDelegate.getIndexInfo(anyString(), anyString(), anyString(), anyBoolean(), anyBoolean()))
            .thenReturn(mockResultSet);

        final ResultSet result = this.delegatingMetaData.getIndexInfo("catalog", "schema", "table", true, false);

        assertSame(mockResultSet, result);
        verify(this.mockDelegate).getIndexInfo("catalog", "schema", "table", true, false);
    }

    // Special return types

    @Test
    @DisplayName("getRowIdLifetime() delegates")
    void testGetRowIdLifetime()
        throws SQLException {
        when(this.mockDelegate.getRowIdLifetime()).thenReturn(RowIdLifetime.ROWID_VALID_SESSION);

        final RowIdLifetime result = this.delegatingMetaData.getRowIdLifetime();

        assertEquals(RowIdLifetime.ROWID_VALID_SESSION, result);
        verify(this.mockDelegate).getRowIdLifetime();
    }

    // Wrapper methods

    @Test
    @DisplayName("unwrap() returns this when interface matches")
    void testUnwrapReturnsThis()
        throws SQLException {
        final DatabaseMetaData result = this.delegatingMetaData.unwrap(DatabaseMetaData.class);

        assertSame(this.delegatingMetaData, result);
        verify(this.mockDelegate, never()).unwrap(any());
    }

    @Test
    @DisplayName("unwrap() delegates when interface does not match")
    void testUnwrapDelegates()
        throws SQLException {
        when(this.mockDelegate.unwrap(eq(Connection.class))).thenReturn(this.mockConnection);

        final Connection result = this.delegatingMetaData.unwrap(Connection.class);

        assertSame(this.mockConnection, result);
        verify(this.mockDelegate).unwrap(Connection.class);
    }

    @Test
    @DisplayName("isWrapperFor() returns true when interface matches")
    void testIsWrapperForReturnsTrue()
        throws SQLException {
        final boolean result = this.delegatingMetaData.isWrapperFor(DatabaseMetaData.class);

        assertTrue(result);
        verify(this.mockDelegate, never()).isWrapperFor(any());
    }

    @Test
    @DisplayName("isWrapperFor() delegates when interface does not match")
    void testIsWrapperForDelegates()
        throws SQLException {
        when(this.mockDelegate.isWrapperFor(eq(Connection.class))).thenReturn(true);

        final boolean result = this.delegatingMetaData.isWrapperFor(Connection.class);

        assertTrue(result);
        verify(this.mockDelegate).isWrapperFor(Connection.class);
    }
}
