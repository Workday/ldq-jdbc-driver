/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl;

import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;

/**
 * Constants for LDQ JDBC driver.
 *
 */
public class LDQJdbcAuthnConstants {

    private LDQJdbcAuthnConstants() {
        // Utility class
    }

    // Driver constants
    public static final String LDQ_PRODUCT_NAME = "Workday Live Data Query";
    public static final String LDQ_JDBC_DRIVER_NAME = "Workday Live Data Query JDBC Driver";
    public static final Pattern VERSION_PATTERN = Pattern.compile("^(\\d+)(\\.(\\d+))?($|[.-])");

    // JDBC Driver URL prefix constants
    public static final String JDBC_WORKDAY_PREFIX = "jdbc:workday:";
    public static final String JDBC_TRINO_PREFIX = "jdbc:trino:";

    // JWT assertion Properties and constants
    public static final String DEFAULT_JWT_ASSERTION_TOKEN_EXPIRY = "wd.oauth.assertion.token.expiry";
    public static final int ASSERTION_TOKEN_EXPIRY_IN_SECONDS = 10;
    public static final String WDAY_AUDIENCE = "wd";
    public static final JWSAlgorithm DEFAULT_JWS_ALGORITHM = JWSAlgorithm.RS256;
    public static final Boolean DEFAULT_SSL = true;

    // HTTP request constants
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String USER_AGENT = "User-Agent";

    // OAuth2 configuration constants
    public static final String GRANT_TYPE_PARAM = "grant_type";
    public static final String ASSERTION_PARAM = "assertion";
    public static final String OAUTH_2_JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    public static final String GRANT_TYPE_ACCESS_TOKEN = "access_token";
    public static final String ACCESS_TOKEN_FIELD = "access_token";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String X_TENANT_HEADER = "x-tenant";
    public static final String X_TRINO_CLUSTER_TYPE_HEADER = "X-Trino-Cluster-Type";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String TENANT_CLAIM_NAME = "tenant";
    public static final String ACCESS_TOKEN_KEY = "token";

    // OAuth2 URL parameter names
    public static final String PARAM_RESPONSE_TYPE = "response_type";
    public static final String PARAM_CLIENT_ID = "client_id";
    public static final String PARAM_CLIENT_SECRET = "client_secret";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_REDIRECT_URI = "redirect_uri";
    public static final String PARAM_AUTHORIZATION_CODE = "code";
    public static final String PARAM_ERROR = "error";
    public static final String PARAM_ERROR_DESCRIPTION = "error_description";
    public static final String PARAM_REFRESH_TOKEN = "refresh_token";
    public static final String PARAM_CODE_VERIFIER = "code_verifier";
    public static final String PARAM_CODE_CHALLENGE = "code_challenge";
    public static final String PARAM_CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    // OAuth2 parameter values
    public static final String RESPONSE_TYPE_CODE = "code";

    /**
     * HTTP path prefix prepended to Trino statement requests when talking to the LDQ gateway
     * (for example {@code /dataservice/v1/statement}).
     */
    public static final String LDQ_GATEWAY_PATH_PREFIX = "/dataservice";

    // Refresh early if the token will expire within this many min
    public static final String EARLY_REFRESH_SKEW_MIN_PROP = "wd.token.early-refresh-skew-min";
    public static final long DEFAULT_EARLY_REFRESH_SKEW_MIN = 3L;

    // JSON processing constants
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // HTTP client properties and timeout constants
    public static final String OAUTH_HTTP_CONNECT_TIMEOUT_PROP = "wd.oauth.http-connect-timeout";
    public static final String OAUTH_HTTP_READ_TIMEOUT_PROP = "wd.oauth.http-read-timeout";
    public static final String OAUTH_HTTP_REQUEST_TIMEOUT_PROP = "wd.oauth.http-request-timeout";
    public static final int DEFAULT_HTTP_CONNECT_TIMEOUT_MILLIS = 30000;
    public static final int DEFAULT_HTTP_READ_TIMEOUT_MILLIS = 30000;
    public static final int DEFAULT_HTTP_REQUEST_TIMEOUT_MILLIS = 30000;
    public static final long DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS = TimeUnit.SECONDS.toMillis(10);

    // Retry configuration properties and constants
    public static final String HTTP_RETRY_MAX_RETRIES_PROP = "wd.http.retry.max-retries";
    public static final String HTTP_RETRY_DELAY_MILLIS_PROP = "wd.http.retry.delay-millis";
    public static final String HTTP_RETRY_BACKOFF_MULTIPLIER_PROP = "wd.http.retry.backoff-multiplier";
    public static final String HTTP_RETRY_MAX_DELAY_MILLIS_PROP = "wd.http.retry.max-delay-millis";
    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final long DEFAULT_RETRY_DELAY_MILLIS = 1000L;
    public static final double DEFAULT_BACKOFF_MULTIPLIER = 2.0;
    public static final long DEFAULT_MAX_RETRY_DELAY_MILLIS = 30000L; // 30 seconds
    public static final long MAX_PRIVATE_KEY_FILE_SIZE_IN_BYTES = 10 * 1024;

    // Connection pool configuration properties and constants.
    // Keep-alive must stay below any intermediary proxy's session/idle timeout (e.g., Galahad's 60s);
    // otherwise pooled connections get handed out after the proxy has already killed them.
    public static final String HTTP_CONNECTION_POOL_KEEP_ALIVE_SECONDS_PROP =
        "wd.http.connection-pool.keep-alive-seconds";
    public static final String HTTP_CONNECTION_POOL_MAX_IDLE_CONNECTIONS_PROP =
        "wd.http.connection-pool.max-idle-connections";
    public static final long DEFAULT_CONNECTION_POOL_KEEP_ALIVE_SECONDS = 60L;
    public static final int DEFAULT_CONNECTION_POOL_MAX_IDLE_CONNECTIONS = 5;

    // HTTP status codes from Apache HttpComponents httpcore
    public static final int TOO_MANY_REQUESTS = 429;
    public static final int BAD_GATEWAY = 502;
    public static final int SERVICE_UNAVAILABLE = 503;
    public static final int GATEWAY_TIMEOUT = 504;

    // HTTP method constants
    public static final String HTTP_METHOD_POST = "POST";

    // Error message constants
    public static final String JWT_ASSERTION_CANNOT_BE_NULL_OR_EMPTY = "JWT assertion cannot be null or empty";
    public static final String TOKEN_URL_CANNOT_BE_NULL_OR_EMPTY = "Token URL cannot be null or empty";
    public static final String FAILED_TO_INITIALIZE_HTTP_CLIENT = "Failed to initialize HTTP client";
    public static final String FAILED_TO_OBTAIN_ACCESS_TOKEN = "Failed to obtain access token: HTTP ";
    public static final String NO_ACCESS_TOKEN_FIELD_IN_RESPONSE = "No access_token field in response";
    public static final String NO_ACCESS_TOKEN_FOUND_IN_RESPONSE = "No access token found in response";
    public static final String ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR =
        "Access token request failed due to network error";
    public static final String INVALID_PRIVATE_KEY_FORMAT =
        "Invalid private key format. Expected PKCS#1 or PKCS#8 PEM format, found %s";
    public static final String FAILED_TO_CONVERT_PEM_TO_PRIVATE_KEY =
        "Failed to convert to private key Object. Unsupported format or algorithm.";
    public static final String NO_PRIVATE_KEY_CONFIGURED =
        "No private key source configured. Provide value for wd.sslPrivateKey (PEM format)";
    public static final String FAILED_TO_PARSE_PRIVATE_KEY =
        "Failed to parse private key. Ensure the provided private key is in PEM format";
    public static final String TENANT_CLAIM_IS_MISSING =
        "Tenant claim is missing or empty in the token";
    public static final String ERROR_PARSING_JWT_ACCESS_TOKEN = "Error parsing JWT access token when extracting tenant";
    public static final String PRIVATE_KEY_FILE_NOT_FOUND = "Private key file not found";
    public static final String FAILED_TO_READ_PRIVATE_KEY_FROM_FILE = "Failed to read private key from file";
    public static final String PRIVATE_KEY_FILE_IS_TOO_LARGE = "Private key file is too large (max " +
        (MAX_PRIVATE_KEY_FILE_SIZE_IN_BYTES / 1024) + " KB).";
    public static final String PRIVATE_KEY_FILE_PATH_NOT_ABSOLUTE = "Private key file path must be absolute, got: ";
    public static final String RESPONSE_BODY_FROM_TOKEN_ENDPOINT = "Empty response body from token endpoint";
    public static final String MSG_INVALID_REFRESH_TOKEN = "Refresh token cannot be null or empty";
    public static final String FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE =
        "Failed to parse access token from token response";
    public static final String AUTHORIZATION_CODE_CANNOT_BE_NULL = "Authorization code cannot be null or empty";
    public static final String REDIRECT_URI_HOST_ERROR = "Redirect URI must use localhost or 127.0.0.1, provided ";
    public static final String REDIRECT_URI_PORT_ERROR = "Redirect URI port must be between 1024 and 65535." +
        " Ports below 1024 are privileged and require administrator/root access, provided: ";

    // Constants used by the driver layer
    public static final String WD_CLIENT_ID_KEY = "wd.authn.clientId";
    public static final String WD_CLIENT_ID_DESCRIPTION = "OAuth 2.0 client ID";
    public static final String WD_CLIENT_SECRET_KEY = "wd.authn.clientSecret";
    public static final String WD_CLIENT_SECRET_DESCRIPTION = "OAuth 2.0 client secret";
    public static final String WD_AUTHORIZATION_ENDPOINT_KEY = "wd.authn.authorizationEndpoint";
    public static final String WD_AUTHORIZATION_ENDPOINT_DESCRIPTION = "OAuth 2.0 authorization endpoint URL";
    public static final String WD_AUTHORIZATION_REDIRECT_URL_KEY = "wd.authn.redirectUrl";
    public static final String WD_AUTHORIZATION_REDIRECT_URL_DESCRIPTION = "OAuth 2.0 redirect URL";
    public static final String WD_ISU_KEY = "wd.authn.isu";
    public static final String WD_ISU_DESCRIPTION = "Workday Integration System User (ISU)";
    public static final String WD_TOKEN_ENDPOINT_KEY = "wd.authn.accessTokenEndpoint";
    public static final String WD_TOKEN_ENDPOINT_DESCRIPTION = "OAuth 2.0 token endpoint URL";
    public static final String WD_SSL_PRIVATE_KEY = "wd.authn.privateKey";
    public static final String WD_SSL_PRIVATE_KEY_FILE_PATH = "wd.authn.privateKeyFilePath";
    public static final String WD_SSL_PRIVATE_KEY_DESCRIPTION = "Private key for JWT signing in PEM format";
    public static final String WD_SSL_PRIVATE_KEY_FILE_PATH_DESCRIPTION =
        "Absolute file path to Private key for JWT signing in PEM format";
    public static final String WD_SSL_TRUST_STORE_PASSWORD_KEY = "wd.ssl.trustStorePassword";
    public static final String WD_SSL_TRUST_STORE_PASSWORD_DESCRIPTION = "Truststore password";
    public static final String WD_SSL_TRUST_STORE_PATH_KEY = "wd.ssl.trustStorePath";
    public static final String WD_SSL_TRUST_STORE_PATH_DESCRIPTION = "Path to truststore file";
    public static final String WD_AUTH_MODEL_KEY = "wd.authn.authModel";
    public static final String WD_AUTH_MODEL_DESCRIPTION = "Authentication model to be used";
    public static final String WD_SESSION_PROPERTIES_KEY = "wd.sessionProperties";
    public static final String WD_SESSION_PROPERTIES_DESCRIPTION = "Trino session properties";
    public static final String WD_HTTP_TIMEOUT = "wd.http.timeout";
    public static final String WD_HTTP_TIMEOUT_DESCRIPTION =
        "Http request timeout in duration like 30s, 1m, 1m30s etc, default is 30s";
    public static final String WD_LDQ_USE_CASE_KEY = "wd.ldqUseCase";
    public static final String WD_LDQ_USE_CASE_DESCRIPTION =
        "LDQ use case type: ldq (default), etl, or agentic";
    public static final String WD_ACCESS_TOKEN_KEY = "wd.authn.accessToken";
    public static final String WD_ACCESS_TOKEN_DESCRIPTION =
        "Pre-issued access token to use directly";
}
