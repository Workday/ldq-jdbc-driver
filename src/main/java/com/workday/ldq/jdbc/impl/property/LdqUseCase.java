/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.property;

import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.jakarta.annotation.Nullable;

import java.util.Arrays;

/**
 * Defines the use case for Live Data Query (LDQ) connections.
 * Used to categorize and track different types of LDQ usage patterns.
 *
 */
public enum LdqUseCase {

    /**
     * Standard Live Data Query use case for interactive queries.
     */
    LDQ,

    /**
     * Extract, Transform, Load (ETL) use case for batch data processing.
     */
    ETL,

    /**
     * Agentic use case for AI/ML-driven queries.
     */
    AGENTIC;

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    /**
     * Parse a use case from a string value.
     *
     * @param value The string value (case-insensitive)
     * @return The corresponding LdqUseCase, or default if the value is null/empty
     * @throws IllegalArgumentException if the value doesn't match any known use case
     */
    public static @Nonnull LdqUseCase fromString(@Nullable final String value) {
        if (DriverPropertyUtil.IS_NOT_EMPTY.negate().test(value)) {
            return LDQ;
        }

        final String normalized = value.trim().toUpperCase();
        try {
            return LdqUseCase.valueOf(normalized);
        }
        catch (final IllegalArgumentException e) {
            throw new IllegalArgumentException(
                String.format("Invalid value for property %s: '%s'. Supported values: %s",
                    DriverProperty.WD_LDQ_USE_CASE.getKey(),
                    value,
                    Arrays.toString(values())));
        }
    }
}
