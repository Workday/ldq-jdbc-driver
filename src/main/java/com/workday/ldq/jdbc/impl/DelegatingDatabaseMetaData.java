/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

/**
 * Base wrapper for DatabaseMetaData that delegates all calls to the underlying implementation.
 * Subclasses can override specific methods to customize behavior.
 *
 */
abstract class DelegatingDatabaseMetaData
    implements DatabaseMetaData {

    protected final DatabaseMetaData delegate;
    protected final Connection connection;

    protected DelegatingDatabaseMetaData(final DatabaseMetaData delegate, final Connection connection) {
        this.delegate = delegate;
        this.connection = connection;
    }

    @Override
    public boolean allProceduresAreCallable()
        throws SQLException {
        return this.delegate.allProceduresAreCallable();
    }

    @Override
    public boolean allTablesAreSelectable()
        throws SQLException {
        return this.delegate.allTablesAreSelectable();
    }

    @Override
    public String getURL()
        throws SQLException {
        return this.delegate.getURL();
    }

    @Override
    public String getUserName()
        throws SQLException {
        return this.delegate.getUserName();
    }

    @Override
    public boolean isReadOnly()
        throws SQLException {
        return this.delegate.isReadOnly();
    }

    @Override
    public boolean nullsAreSortedHigh()
        throws SQLException {
        return this.delegate.nullsAreSortedHigh();
    }

    @Override
    public boolean nullsAreSortedLow()
        throws SQLException {
        return this.delegate.nullsAreSortedLow();
    }

    @Override
    public boolean nullsAreSortedAtStart()
        throws SQLException {
        return this.delegate.nullsAreSortedAtStart();
    }

    @Override
    public boolean nullsAreSortedAtEnd()
        throws SQLException {
        return this.delegate.nullsAreSortedAtEnd();
    }

    @Override
    public String getDatabaseProductName()
        throws SQLException {
        return this.delegate.getDatabaseProductName();
    }

    @Override
    public String getDatabaseProductVersion()
        throws SQLException {
        return this.delegate.getDatabaseProductVersion();
    }

    @Override
    public String getDriverName()
        throws SQLException {
        return this.delegate.getDriverName();
    }

    @Override
    public String getDriverVersion()
        throws SQLException {
        return this.delegate.getDriverVersion();
    }

    @Override
    public int getDriverMajorVersion() {
        return this.delegate.getDriverMajorVersion();
    }

    @Override
    public int getDriverMinorVersion() {
        return this.delegate.getDriverMinorVersion();
    }

    @Override
    public boolean usesLocalFiles()
        throws SQLException {
        return this.delegate.usesLocalFiles();
    }

    @Override
    public boolean usesLocalFilePerTable()
        throws SQLException {
        return this.delegate.usesLocalFilePerTable();
    }

    @Override
    public boolean supportsMixedCaseIdentifiers()
        throws SQLException {
        return this.delegate.supportsMixedCaseIdentifiers();
    }

    @Override
    public boolean storesUpperCaseIdentifiers()
        throws SQLException {
        return this.delegate.storesUpperCaseIdentifiers();
    }

    @Override
    public boolean storesLowerCaseIdentifiers()
        throws SQLException {
        return this.delegate.storesLowerCaseIdentifiers();
    }

    @Override
    public boolean storesMixedCaseIdentifiers()
        throws SQLException {
        return this.delegate.storesMixedCaseIdentifiers();
    }

    @Override
    public boolean supportsMixedCaseQuotedIdentifiers()
        throws SQLException {
        return this.delegate.supportsMixedCaseQuotedIdentifiers();
    }

    @Override
    public boolean storesUpperCaseQuotedIdentifiers()
        throws SQLException {
        return this.delegate.storesUpperCaseQuotedIdentifiers();
    }

    @Override
    public boolean storesLowerCaseQuotedIdentifiers()
        throws SQLException {
        return this.delegate.storesLowerCaseQuotedIdentifiers();
    }

    @Override
    public boolean storesMixedCaseQuotedIdentifiers()
        throws SQLException {
        return this.delegate.storesMixedCaseQuotedIdentifiers();
    }

    @Override
    public String getIdentifierQuoteString()
        throws SQLException {
        return this.delegate.getIdentifierQuoteString();
    }

    @Override
    public String getSQLKeywords()
        throws SQLException {
        return this.delegate.getSQLKeywords();
    }

    @Override
    public String getNumericFunctions()
        throws SQLException {
        return this.delegate.getNumericFunctions();
    }

    @Override
    public String getStringFunctions()
        throws SQLException {
        return this.delegate.getStringFunctions();
    }

    @Override
    public String getSystemFunctions()
        throws SQLException {
        return this.delegate.getSystemFunctions();
    }

    @Override
    public String getTimeDateFunctions()
        throws SQLException {
        return this.delegate.getTimeDateFunctions();
    }

    @Override
    public String getSearchStringEscape()
        throws SQLException {
        return this.delegate.getSearchStringEscape();
    }

    @Override
    public String getExtraNameCharacters()
        throws SQLException {
        return this.delegate.getExtraNameCharacters();
    }

    @Override
    public boolean supportsAlterTableWithAddColumn()
        throws SQLException {
        return this.delegate.supportsAlterTableWithAddColumn();
    }

    @Override
    public boolean supportsAlterTableWithDropColumn()
        throws SQLException {
        return this.delegate.supportsAlterTableWithDropColumn();
    }

    @Override
    public boolean supportsColumnAliasing()
        throws SQLException {
        return this.delegate.supportsColumnAliasing();
    }

    @Override
    public boolean nullPlusNonNullIsNull()
        throws SQLException {
        return this.delegate.nullPlusNonNullIsNull();
    }

    @Override
    public boolean supportsConvert()
        throws SQLException {
        return this.delegate.supportsConvert();
    }

    @Override
    public boolean supportsConvert(final int fromType, final int toType)
        throws SQLException {
        return this.delegate.supportsConvert(fromType, toType);
    }

    @Override
    public boolean supportsTableCorrelationNames()
        throws SQLException {
        return this.delegate.supportsTableCorrelationNames();
    }

    @Override
    public boolean supportsDifferentTableCorrelationNames()
        throws SQLException {
        return this.delegate.supportsDifferentTableCorrelationNames();
    }

    @Override
    public boolean supportsExpressionsInOrderBy()
        throws SQLException {
        return this.delegate.supportsExpressionsInOrderBy();
    }

    @Override
    public boolean supportsOrderByUnrelated()
        throws SQLException {
        return this.delegate.supportsOrderByUnrelated();
    }

    @Override
    public boolean supportsGroupBy()
        throws SQLException {
        return this.delegate.supportsGroupBy();
    }

    @Override
    public boolean supportsGroupByUnrelated()
        throws SQLException {
        return this.delegate.supportsGroupByUnrelated();
    }

    @Override
    public boolean supportsGroupByBeyondSelect()
        throws SQLException {
        return this.delegate.supportsGroupByBeyondSelect();
    }

    @Override
    public boolean supportsLikeEscapeClause()
        throws SQLException {
        return this.delegate.supportsLikeEscapeClause();
    }

    @Override
    public boolean supportsMultipleResultSets()
        throws SQLException {
        return this.delegate.supportsMultipleResultSets();
    }

    @Override
    public boolean supportsMultipleTransactions()
        throws SQLException {
        return this.delegate.supportsMultipleTransactions();
    }

    @Override
    public boolean supportsNonNullableColumns()
        throws SQLException {
        return this.delegate.supportsNonNullableColumns();
    }

    @Override
    public boolean supportsMinimumSQLGrammar()
        throws SQLException {
        return this.delegate.supportsMinimumSQLGrammar();
    }

    @Override
    public boolean supportsCoreSQLGrammar()
        throws SQLException {
        return this.delegate.supportsCoreSQLGrammar();
    }

    @Override
    public boolean supportsExtendedSQLGrammar()
        throws SQLException {
        return this.delegate.supportsExtendedSQLGrammar();
    }

    @Override
    public boolean supportsANSI92EntryLevelSQL()
        throws SQLException {
        return this.delegate.supportsANSI92EntryLevelSQL();
    }

    @Override
    public boolean supportsANSI92IntermediateSQL()
        throws SQLException {
        return this.delegate.supportsANSI92IntermediateSQL();
    }

    @Override
    public boolean supportsANSI92FullSQL()
        throws SQLException {
        return this.delegate.supportsANSI92FullSQL();
    }

    @Override
    public boolean supportsIntegrityEnhancementFacility()
        throws SQLException {
        return this.delegate.supportsIntegrityEnhancementFacility();
    }

    @Override
    public boolean supportsOuterJoins()
        throws SQLException {
        return this.delegate.supportsOuterJoins();
    }

    @Override
    public boolean supportsFullOuterJoins()
        throws SQLException {
        return this.delegate.supportsFullOuterJoins();
    }

    @Override
    public boolean supportsLimitedOuterJoins()
        throws SQLException {
        return this.delegate.supportsLimitedOuterJoins();
    }

    @Override
    public String getSchemaTerm()
        throws SQLException {
        return this.delegate.getSchemaTerm();
    }

    @Override
    public String getProcedureTerm()
        throws SQLException {
        return this.delegate.getProcedureTerm();
    }

    @Override
    public String getCatalogTerm()
        throws SQLException {
        return this.delegate.getCatalogTerm();
    }

    @Override
    public boolean isCatalogAtStart()
        throws SQLException {
        return this.delegate.isCatalogAtStart();
    }

    @Override
    public String getCatalogSeparator()
        throws SQLException {
        return this.delegate.getCatalogSeparator();
    }

    @Override
    public boolean supportsSchemasInDataManipulation()
        throws SQLException {
        return this.delegate.supportsSchemasInDataManipulation();
    }

    @Override
    public boolean supportsSchemasInProcedureCalls()
        throws SQLException {
        return this.delegate.supportsSchemasInProcedureCalls();
    }

    @Override
    public boolean supportsSchemasInTableDefinitions()
        throws SQLException {
        return this.delegate.supportsSchemasInTableDefinitions();
    }

    @Override
    public boolean supportsSchemasInIndexDefinitions()
        throws SQLException {
        return this.delegate.supportsSchemasInIndexDefinitions();
    }

    @Override
    public boolean supportsSchemasInPrivilegeDefinitions()
        throws SQLException {
        return this.delegate.supportsSchemasInPrivilegeDefinitions();
    }

    @Override
    public boolean supportsCatalogsInDataManipulation()
        throws SQLException {
        return this.delegate.supportsCatalogsInDataManipulation();
    }

    @Override
    public boolean supportsCatalogsInProcedureCalls()
        throws SQLException {
        return this.delegate.supportsCatalogsInProcedureCalls();
    }

    @Override
    public boolean supportsCatalogsInTableDefinitions()
        throws SQLException {
        return this.delegate.supportsCatalogsInTableDefinitions();
    }

    @Override
    public boolean supportsCatalogsInIndexDefinitions()
        throws SQLException {
        return this.delegate.supportsCatalogsInIndexDefinitions();
    }

    @Override
    public boolean supportsCatalogsInPrivilegeDefinitions()
        throws SQLException {
        return this.delegate.supportsCatalogsInPrivilegeDefinitions();
    }

    @Override
    public boolean supportsPositionedDelete()
        throws SQLException {
        return this.delegate.supportsPositionedDelete();
    }

    @Override
    public boolean supportsPositionedUpdate()
        throws SQLException {
        return this.delegate.supportsPositionedUpdate();
    }

    @Override
    public boolean supportsSelectForUpdate()
        throws SQLException {
        return this.delegate.supportsSelectForUpdate();
    }

    @Override
    public boolean supportsStoredProcedures()
        throws SQLException {
        return this.delegate.supportsStoredProcedures();
    }

    @Override
    public boolean supportsSubqueriesInComparisons()
        throws SQLException {
        return this.delegate.supportsSubqueriesInComparisons();
    }

    @Override
    public boolean supportsSubqueriesInExists()
        throws SQLException {
        return this.delegate.supportsSubqueriesInExists();
    }

    @Override
    public boolean supportsSubqueriesInIns()
        throws SQLException {
        return this.delegate.supportsSubqueriesInIns();
    }

    @Override
    public boolean supportsSubqueriesInQuantifieds()
        throws SQLException {
        return this.delegate.supportsSubqueriesInQuantifieds();
    }

    @Override
    public boolean supportsCorrelatedSubqueries()
        throws SQLException {
        return this.delegate.supportsCorrelatedSubqueries();
    }

    @Override
    public boolean supportsUnion()
        throws SQLException {
        return this.delegate.supportsUnion();
    }

    @Override
    public boolean supportsUnionAll()
        throws SQLException {
        return this.delegate.supportsUnionAll();
    }

    @Override
    public boolean supportsOpenCursorsAcrossCommit()
        throws SQLException {
        return this.delegate.supportsOpenCursorsAcrossCommit();
    }

    @Override
    public boolean supportsOpenCursorsAcrossRollback()
        throws SQLException {
        return this.delegate.supportsOpenCursorsAcrossRollback();
    }

    @Override
    public boolean supportsOpenStatementsAcrossCommit()
        throws SQLException {
        return this.delegate.supportsOpenStatementsAcrossCommit();
    }

    @Override
    public boolean supportsOpenStatementsAcrossRollback()
        throws SQLException {
        return this.delegate.supportsOpenStatementsAcrossRollback();
    }

    @Override
    public int getMaxBinaryLiteralLength()
        throws SQLException {
        return this.delegate.getMaxBinaryLiteralLength();
    }

    @Override
    public int getMaxCharLiteralLength()
        throws SQLException {
        return this.delegate.getMaxCharLiteralLength();
    }

    @Override
    public int getMaxColumnNameLength()
        throws SQLException {
        return this.delegate.getMaxColumnNameLength();
    }

    @Override
    public int getMaxColumnsInGroupBy()
        throws SQLException {
        return this.delegate.getMaxColumnsInGroupBy();
    }

    @Override
    public int getMaxColumnsInIndex()
        throws SQLException {
        return this.delegate.getMaxColumnsInIndex();
    }

    @Override
    public int getMaxColumnsInOrderBy()
        throws SQLException {
        return this.delegate.getMaxColumnsInOrderBy();
    }

    @Override
    public int getMaxColumnsInSelect()
        throws SQLException {
        return this.delegate.getMaxColumnsInSelect();
    }

    @Override
    public int getMaxColumnsInTable()
        throws SQLException {
        return this.delegate.getMaxColumnsInTable();
    }

    @Override
    public int getMaxConnections()
        throws SQLException {
        return this.delegate.getMaxConnections();
    }

    @Override
    public int getMaxCursorNameLength()
        throws SQLException {
        return this.delegate.getMaxCursorNameLength();
    }

    @Override
    public int getMaxIndexLength()
        throws SQLException {
        return this.delegate.getMaxIndexLength();
    }

    @Override
    public int getMaxSchemaNameLength()
        throws SQLException {
        return this.delegate.getMaxSchemaNameLength();
    }

    @Override
    public int getMaxProcedureNameLength()
        throws SQLException {
        return this.delegate.getMaxProcedureNameLength();
    }

    @Override
    public int getMaxCatalogNameLength()
        throws SQLException {
        return this.delegate.getMaxCatalogNameLength();
    }

    @Override
    public int getMaxRowSize()
        throws SQLException {
        return this.delegate.getMaxRowSize();
    }

    @Override
    public boolean doesMaxRowSizeIncludeBlobs()
        throws SQLException {
        return this.delegate.doesMaxRowSizeIncludeBlobs();
    }

    @Override
    public int getMaxStatementLength()
        throws SQLException {
        return this.delegate.getMaxStatementLength();
    }

    @Override
    public int getMaxStatements()
        throws SQLException {
        return this.delegate.getMaxStatements();
    }

    @Override
    public int getMaxTableNameLength()
        throws SQLException {
        return this.delegate.getMaxTableNameLength();
    }

    @Override
    public int getMaxTablesInSelect()
        throws SQLException {
        return this.delegate.getMaxTablesInSelect();
    }

    @Override
    public int getMaxUserNameLength()
        throws SQLException {
        return this.delegate.getMaxUserNameLength();
    }

    @Override
    public int getDefaultTransactionIsolation()
        throws SQLException {
        return this.delegate.getDefaultTransactionIsolation();
    }

    @Override
    public boolean supportsTransactions()
        throws SQLException {
        return this.delegate.supportsTransactions();
    }

    @Override
    public boolean supportsTransactionIsolationLevel(final int level)
        throws SQLException {
        return this.delegate.supportsTransactionIsolationLevel(level);
    }

    @Override
    public boolean supportsDataDefinitionAndDataManipulationTransactions()
        throws SQLException {
        return this.delegate.supportsDataDefinitionAndDataManipulationTransactions();
    }

    @Override
    public boolean supportsDataManipulationTransactionsOnly()
        throws SQLException {
        return this.delegate.supportsDataManipulationTransactionsOnly();
    }

    @Override
    public boolean dataDefinitionCausesTransactionCommit()
        throws SQLException {
        return this.delegate.dataDefinitionCausesTransactionCommit();
    }

    @Override
    public boolean dataDefinitionIgnoredInTransactions()
        throws SQLException {
        return this.delegate.dataDefinitionIgnoredInTransactions();
    }

    @Override
    public java.sql.ResultSet getProcedures(final String catalog,
                                            final String schemaPattern,
                                            final String procedureNamePattern)
        throws SQLException {
        return this.delegate.getProcedures(catalog, schemaPattern, procedureNamePattern);
    }

    @Override
    public java.sql.ResultSet getProcedureColumns(final String catalog,
                                                  final String schemaPattern,
                                                  final String procedureNamePattern,
                                                  final String columnNamePattern)
        throws SQLException {
        return this.delegate.getProcedureColumns(catalog, schemaPattern, procedureNamePattern, columnNamePattern);
    }

    @Override
    public java.sql.ResultSet getTables(final String catalog,
                                        final String schemaPattern,
                                        final String tableNamePattern,
                                        final String[] types)
        throws SQLException {
        return this.delegate.getTables(catalog, schemaPattern, tableNamePattern, types);
    }

    @Override
    public java.sql.ResultSet getSchemas()
        throws SQLException {
        return this.delegate.getSchemas();
    }

    @Override
    public java.sql.ResultSet getCatalogs()
        throws SQLException {
        return this.delegate.getCatalogs();
    }

    @Override
    public java.sql.ResultSet getTableTypes()
        throws SQLException {
        return this.delegate.getTableTypes();
    }

    @Override
    public java.sql.ResultSet getColumns(final String catalog,
                                         final String schemaPattern,
                                         final String tableNamePattern,
                                         final String columnNamePattern)
        throws SQLException {
        return this.delegate.getColumns(catalog, schemaPattern, tableNamePattern, columnNamePattern);
    }

    @Override
    public java.sql.ResultSet getColumnPrivileges(final String catalog,
                                                  final String schema,
                                                  final String table,
                                                  final String columnNamePattern)
        throws SQLException {
        return this.delegate.getColumnPrivileges(catalog, schema, table, columnNamePattern);
    }

    @Override
    public java.sql.ResultSet getTablePrivileges(final String catalog,
                                                 final String schemaPattern,
                                                 final String tableNamePattern)
        throws SQLException {
        return this.delegate.getTablePrivileges(catalog, schemaPattern, tableNamePattern);
    }

    @Override
    public java.sql.ResultSet getBestRowIdentifier(final String catalog,
                                                   final String schema,
                                                   final String table,
                                                   final int scope,
                                                   final boolean nullable)
        throws SQLException {
        return this.delegate.getBestRowIdentifier(catalog, schema, table, scope, nullable);
    }

    @Override
    public java.sql.ResultSet getVersionColumns(final String catalog,
                                                final String schema,
                                                final String table)
        throws SQLException {
        return this.delegate.getVersionColumns(catalog, schema, table);
    }

    @Override
    public java.sql.ResultSet getPrimaryKeys(final String catalog,
                                             final String schema,
                                             final String table)
        throws SQLException {
        return this.delegate.getPrimaryKeys(catalog, schema, table);
    }

    @Override
    public java.sql.ResultSet getImportedKeys(final String catalog,
                                              final String schema,
                                              final String table)
        throws SQLException {
        return this.delegate.getImportedKeys(catalog, schema, table);
    }

    @Override
    public java.sql.ResultSet getExportedKeys(final String catalog,
                                              final String schema,
                                              final String table)
        throws SQLException {
        return this.delegate.getExportedKeys(catalog, schema, table);
    }

    @Override
    public java.sql.ResultSet getCrossReference(final String parentCatalog,
                                                final String parentSchema,
                                                final String parentTable,
                                                final String foreignCatalog,
                                                final String foreignSchema,
                                                final String foreignTable)
        throws SQLException {
        return this.delegate.getCrossReference(parentCatalog, parentSchema, parentTable,
            foreignCatalog, foreignSchema, foreignTable);
    }

    @Override
    public java.sql.ResultSet getTypeInfo()
        throws SQLException {
        return this.delegate.getTypeInfo();
    }

    @Override
    public java.sql.ResultSet getIndexInfo(final String catalog,
                                           final String schema,
                                           final String table,
                                           final boolean unique,
                                           final boolean approximate)
        throws SQLException {
        return this.delegate.getIndexInfo(catalog, schema, table, unique, approximate);
    }

    @Override
    public boolean supportsResultSetType(final int type)
        throws SQLException {
        return this.delegate.supportsResultSetType(type);
    }

    @Override
    public boolean supportsResultSetConcurrency(final int type, final int concurrency)
        throws SQLException {
        return this.delegate.supportsResultSetConcurrency(type, concurrency);
    }

    @Override
    public boolean ownUpdatesAreVisible(final int type)
        throws SQLException {
        return this.delegate.ownUpdatesAreVisible(type);
    }

    @Override
    public boolean ownDeletesAreVisible(final int type)
        throws SQLException {
        return this.delegate.ownDeletesAreVisible(type);
    }

    @Override
    public boolean ownInsertsAreVisible(final int type)
        throws SQLException {
        return this.delegate.ownInsertsAreVisible(type);
    }

    @Override
    public boolean othersUpdatesAreVisible(final int type)
        throws SQLException {
        return this.delegate.othersUpdatesAreVisible(type);
    }

    @Override
    public boolean othersDeletesAreVisible(final int type)
        throws SQLException {
        return this.delegate.othersDeletesAreVisible(type);
    }

    @Override
    public boolean othersInsertsAreVisible(final int type)
        throws SQLException {
        return this.delegate.othersInsertsAreVisible(type);
    }

    @Override
    public boolean updatesAreDetected(final int type)
        throws SQLException {
        return this.delegate.updatesAreDetected(type);
    }

    @Override
    public boolean deletesAreDetected(final int type)
        throws SQLException {
        return this.delegate.deletesAreDetected(type);
    }

    @Override
    public boolean insertsAreDetected(final int type)
        throws SQLException {
        return this.delegate.insertsAreDetected(type);
    }

    @Override
    public boolean supportsBatchUpdates()
        throws SQLException {
        return this.delegate.supportsBatchUpdates();
    }

    @Override
    public java.sql.ResultSet getUDTs(final String catalog,
                                      final String schemaPattern,
                                      final String typeNamePattern,
                                      final int[] types)
        throws SQLException {
        return this.delegate.getUDTs(catalog, schemaPattern, typeNamePattern, types);
    }

    @Override
    public boolean supportsSavepoints()
        throws SQLException {
        return this.delegate.supportsSavepoints();
    }

    @Override
    public boolean supportsNamedParameters()
        throws SQLException {
        return this.delegate.supportsNamedParameters();
    }

    @Override
    public boolean supportsMultipleOpenResults()
        throws SQLException {
        return this.delegate.supportsMultipleOpenResults();
    }

    @Override
    public boolean supportsGetGeneratedKeys()
        throws SQLException {
        return this.delegate.supportsGetGeneratedKeys();
    }

    @Override
    public java.sql.ResultSet getSuperTypes(final String catalog,
                                            final String schemaPattern,
                                            final String typeNamePattern)
        throws SQLException {
        return this.delegate.getSuperTypes(catalog, schemaPattern, typeNamePattern);
    }

    @Override
    public java.sql.ResultSet getSuperTables(final String catalog,
                                             final String schemaPattern,
                                             final String tableNamePattern)
        throws SQLException {
        return this.delegate.getSuperTables(catalog, schemaPattern, tableNamePattern);
    }

    @Override
    public java.sql.ResultSet getAttributes(final String catalog,
                                            final String schemaPattern,
                                            final String typeNamePattern,
                                            final String attributeNamePattern)
        throws SQLException {
        return this.delegate.getAttributes(catalog, schemaPattern, typeNamePattern, attributeNamePattern);
    }

    @Override
    public boolean supportsResultSetHoldability(final int holdability)
        throws SQLException {
        return this.delegate.supportsResultSetHoldability(holdability);
    }

    @Override
    public int getResultSetHoldability()
        throws SQLException {
        return this.delegate.getResultSetHoldability();
    }

    @Override
    public int getDatabaseMajorVersion()
        throws SQLException {
        return this.delegate.getDatabaseMajorVersion();
    }

    @Override
    public int getDatabaseMinorVersion()
        throws SQLException {
        return this.delegate.getDatabaseMinorVersion();
    }

    @Override
    public int getJDBCMajorVersion()
        throws SQLException {
        return this.delegate.getJDBCMajorVersion();
    }

    @Override
    public int getJDBCMinorVersion()
        throws SQLException {
        return this.delegate.getJDBCMinorVersion();
    }

    @Override
    public int getSQLStateType()
        throws SQLException {
        return this.delegate.getSQLStateType();
    }

    @Override
    public boolean locatorsUpdateCopy()
        throws SQLException {
        return this.delegate.locatorsUpdateCopy();
    }

    @Override
    public boolean supportsStatementPooling()
        throws SQLException {
        return this.delegate.supportsStatementPooling();
    }

    @Override
    public java.sql.RowIdLifetime getRowIdLifetime()
        throws SQLException {
        return this.delegate.getRowIdLifetime();
    }

    @Override
    public java.sql.ResultSet getSchemas(final String catalog, final String schemaPattern)
        throws SQLException {
        return this.delegate.getSchemas(catalog, schemaPattern);
    }

    @Override
    public boolean supportsStoredFunctionsUsingCallSyntax()
        throws SQLException {
        return this.delegate.supportsStoredFunctionsUsingCallSyntax();
    }

    @Override
    public boolean autoCommitFailureClosesAllResultSets()
        throws SQLException {
        return this.delegate.autoCommitFailureClosesAllResultSets();
    }

    @Override
    public java.sql.ResultSet getClientInfoProperties()
        throws SQLException {
        return this.delegate.getClientInfoProperties();
    }

    @Override
    public java.sql.ResultSet getFunctions(final String catalog,
                                           final String schemaPattern,
                                           final String functionNamePattern)
        throws SQLException {
        return this.delegate.getFunctions(catalog, schemaPattern, functionNamePattern);
    }

    @Override
    public java.sql.ResultSet getFunctionColumns(final String catalog,
                                                 final String schemaPattern,
                                                 final String functionNamePattern,
                                                 final String columnNamePattern)
        throws SQLException {
        return this.delegate.getFunctionColumns(catalog, schemaPattern, functionNamePattern, columnNamePattern);
    }

    @Override
    public java.sql.ResultSet getPseudoColumns(final String catalog,
                                               final String schemaPattern,
                                               final String tableNamePattern,
                                               final String columnNamePattern)
        throws SQLException {
        return this.delegate.getPseudoColumns(catalog, schemaPattern, tableNamePattern, columnNamePattern);
    }

    @Override
    public boolean generatedKeyAlwaysReturned()
        throws SQLException {
        return this.delegate.generatedKeyAlwaysReturned();
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

    @Override
    public long getMaxLogicalLobSize()
        throws SQLException {
        return this.delegate.getMaxLogicalLobSize();
    }

    @Override
    public boolean supportsRefCursors()
        throws SQLException {
        return this.delegate.supportsRefCursors();
    }

    @Override
    public boolean supportsSharding()
        throws SQLException {
        return this.delegate.supportsSharding();
    }

    @Override
    public Connection getConnection() {
        return this.connection;
    }
}
