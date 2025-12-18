/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth.token;

/**
 * JWT claim names following RFC 7519 standard and Workday-specific claims.
 * Uses final class pattern instead of interface antipattern.
 * Not all claims are used in the current implementation.
 * Including all completeness and future-proofing.
 *
 */
public final class JWTClaimNames {

    private JWTClaimNames() {
        // Prevent instantiation
    }

    // Standard JWT claims from RFC 7519
    public static final String ISSUER = "iss";
    public static final String SUBJECT = "sub";
    public static final String AUDIENCE = "aud";
    public static final String EXPIRATION_TIME = "exp";
    public static final String NOT_BEFORE = "nbf";
    public static final String ISSUED_AT = "iat";
    public static final String JWT_ID = "jti";

    // OAuth 2.0 specific claims
    public static final String SCOPE = "scope";
    public static final String CLIENT_ID = "client_id";

    // Workday-specific custom claims
    public static final String TENANT = "tenant";
    public static final String ENVIRONMENT = "env";
}
