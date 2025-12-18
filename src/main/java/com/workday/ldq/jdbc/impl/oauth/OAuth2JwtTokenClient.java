/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_FIELD;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ASSERTION_PARAM;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_OBTAIN_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GRANT_TYPE_PARAM;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.JWT_ASSERTION_CANNOT_BE_NULL_OR_EMPTY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OAUTH_2_JWT_GRANT_TYPE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OBJECT_MAPPER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TOKEN_URL_CANNOT_BE_NULL_OR_EMPTY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.USER_AGENT;
import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import io.trino.jdbc.$internal.okhttp3.FormBody;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;
import io.trino.jdbc.$internal.okhttp3.ResponseBody;

import java.io.IOException;
import java.text.ParseException;

import com.fasterxml.jackson.databind.JsonNode;

import com.workday.ldq.jdbc.api.LDQJdbcDriver;
import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Java client for making OAuth2 token requests using OkHttpClient
 * Supports JWT bearer grant type
 *
 */
class OAuth2JwtTokenClient {

    private final OkHttpClient httpClient;

    public OAuth2JwtTokenClient(final OkHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Request a token response from the OAuth 2.0 token endpoint.
     * <p>
     * JWT Bearer grant typically does not return refresh tokens, so the returned
     * TokenResponse will only contain an access token.
     *
     * @param jwtAssertion The JWT assertion for the bearer grant
     * @param tokenUrl     The OAuth 2.0 token endpoint URL
     * @return TokenResponse containing an access token (refresh token will be null for JWT Bearer)
     * @throws LDQJdbcDriverRuntimeException if the request fails
     */
    public TokenResponse requestToken(final String jwtAssertion, final String tokenUrl) {
        // Input validation
        if (IS_NOT_EMPTY.negate().test(jwtAssertion)) {
            throw new LDQJdbcDriverRuntimeException(JWT_ASSERTION_CANNOT_BE_NULL_OR_EMPTY);
        }
        if (IS_NOT_EMPTY.negate().test(tokenUrl)) {
            throw new LDQJdbcDriverRuntimeException(TOKEN_URL_CANNOT_BE_NULL_OR_EMPTY);
        }

        return fetchAccessToken(() -> requestTokenResponseNode(jwtAssertion, tokenUrl));
    }

    /**
     * Executes a token request and parses the response.
     *
     * @param supplier Supplier that executes the HTTP request
     * @return TokenResponse containing access token and optional refresh token
     */
    private TokenResponse fetchAccessToken(final TokenRequestSupplier supplier) {
        try {
            final JsonNode jsonResponse = supplier.get();
            // JWT Bearer grant typically doesn't return a refresh token, so fallback is null
            return OAuth2TokenUtil.parseTokenResponse(jsonResponse, null);
        }
        catch (final IOException e) {
            throw new LDQJdbcDriverRuntimeException(ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR, e);
        }
        catch (final ParseException e) {
            throw new LDQJdbcDriverRuntimeException(FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE, e);
        }
    }

    @FunctionalInterface
    private interface TokenRequestSupplier {

        JsonNode get()
            throws IOException;
    }

    /**
     * Makes an HTTP request to the OAuth 2.0 token endpoint and returns the full JSON response.
     *
     * @param jwtAssertion The JWT assertion for the bearer grant
     * @param tokenUrl     The OAuth 2.0 token endpoint URL
     * @return The JsonNode containing the full token response
     * @throws IOException                       if the request fails due to a network error
     * @throws LDQJdbcDriverRuntimeException if the request fails
     */
    protected JsonNode requestTokenResponseNode(final String jwtAssertion, final String tokenUrl)
        throws IOException {
        // Build form data using OkHttp's FormBody
        final FormBody formBody = new FormBody.Builder()
            .add(GRANT_TYPE_PARAM, OAUTH_2_JWT_GRANT_TYPE)
            .add(ASSERTION_PARAM, jwtAssertion)
            .build();

        final Request request = new Request.Builder()
            .url(tokenUrl)
            .post(formBody)
            .addHeader(USER_AGENT, LDQJdbcDriver.LDQ_JDBC_DRIVER_USER_AGENT_INFO)
            .build();

        try (Response response = this.httpClient.newCall(request).execute()) {

            if (!response.isSuccessful()) {
                throw new LDQJdbcDriverRuntimeException(
                    FAILED_TO_OBTAIN_ACCESS_TOKEN + response.code() + " " + response.message());
            }

            final ResponseBody body = response.body();
            if (body == null) {
                throw new LDQJdbcDriverRuntimeException(
                    LDQJdbcAuthnConstants.RESPONSE_BODY_FROM_TOKEN_ENDPOINT);
            }
            return OBJECT_MAPPER.readTree(body.string());
        }
    }

    /**
     * Makes an HTTP request to the OAuth 2.0 token endpoint and returns the access token node.
     * <p>
     * This method is maintained for backward compatibility.
     *
     * @param jwtAssertion The JWT assertion for the bearer grant
     * @param tokenUrl     The OAuth 2.0 token endpoint URL
     * @return The JsonNode containing the access token field, or null if not found
     * @throws IOException                       if the request fails due to a network error
     * @throws LDQJdbcDriverRuntimeException if the request fails
     * @deprecated Use {@link #requestTokenResponseNode(String, String)} instead
     */
    @Deprecated
    protected JsonNode requestAccessTokenNode(final String jwtAssertion, final String tokenUrl)
        throws IOException {
        final JsonNode jsonResponse = requestTokenResponseNode(jwtAssertion, tokenUrl);
        return jsonResponse != null ? jsonResponse.get(ACCESS_TOKEN_FIELD) : null;
    }

}
