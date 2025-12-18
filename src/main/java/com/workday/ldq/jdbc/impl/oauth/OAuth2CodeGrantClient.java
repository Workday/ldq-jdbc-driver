/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.AUTHORIZATION_CODE_CANNOT_BE_NULL;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.CODE_CHALLENGE_METHOD_S256;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_OBTAIN_ACCESS_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GRANT_TYPE_PARAM;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.GRANT_TYPE_REFRESH_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.MSG_INVALID_REFRESH_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.OBJECT_MAPPER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_AUTHORIZATION_CODE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_CLIENT_ID;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_CLIENT_SECRET;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_CODE_CHALLENGE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_CODE_CHALLENGE_METHOD;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_CODE_VERIFIER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_REDIRECT_URI;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_REFRESH_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_RESPONSE_TYPE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_STATE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.RESPONSE_BODY_FROM_TOKEN_ENDPOINT;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.RESPONSE_TYPE_CODE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.USER_AGENT;
import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.okhttp3.FormBody;
import io.trino.jdbc.$internal.okhttp3.HttpUrl;
import io.trino.jdbc.$internal.okhttp3.OkHttpClient;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;
import io.trino.jdbc.$internal.okhttp3.ResponseBody;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;

import com.workday.ldq.jdbc.api.LDQJdbcDriver;
import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Java client for OAuth 2.0 Authorization Code Grant flow.
 * Handles browser-based user authentication and authorization code exchange.
 *
 */
class OAuth2CodeGrantClient {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final OkHttpClient httpClient;

    public OAuth2CodeGrantClient(final OkHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Get authorization code from the Workday authorization endpoint.
     * Opens browser for user authentication and waits for callback.
     *
     * @param authorizationEndpoint Workday authorization endpoint URL
     * @param clientId              OAuth 2.0 client ID
     * @param redirectUri           Redirect URI (e.g., https://localhost:8888/callback)
     * @return Authorization code
     * @throws LDQJdbcDriverRuntimeException if authorization fails
     */
    public String getAuthorizationCode(@Nonnull final String authorizationEndpoint,
                                       @Nonnull final String clientId,
                                       @Nonnull final String redirectUri) {
        final String state = generateState();
        final String authorizationUrl = HttpUrl.get(authorizationEndpoint)
            .newBuilder()
            .addQueryParameter(PARAM_RESPONSE_TYPE, RESPONSE_TYPE_CODE)
            .addQueryParameter(PARAM_CLIENT_ID, clientId)
            .addQueryParameter(PARAM_STATE, state)
            .addQueryParameter(PARAM_REDIRECT_URI, redirectUri)
            .build()
            .toString();

        return OAuth2CallbackServer.waitForAuthorizationCode(redirectUri, state, authorizationUrl, clientId);
    }

    /**
     * Exchange authorization code for token response (access token plus optional refresh token).
     *
     * @param authorizationCode Authorization code from callback
     * @param tokenEndpoint     Token endpoint URL
     * @param clientId          OAuth 2.0 client ID
     * @param clientSecret      OAuth 2.0 client secret
     * @param redirectUri       Redirect URI (must match the one used in an authorization request)
     * @return TokenResponse containing an access token and optional refresh token
     * @throws LDQJdbcDriverRuntimeException if token exchange fails
     */
    public TokenResponse exchangeCodeForTokenResponse(final String authorizationCode,
                                                      @Nonnull final String tokenEndpoint,
                                                      @Nonnull final String clientId,
                                                      @Nonnull final String clientSecret,
                                                      @Nonnull final String redirectUri) {
        if (IS_NOT_EMPTY.negate().test(authorizationCode)) {
            throw new LDQJdbcDriverRuntimeException(AUTHORIZATION_CODE_CANNOT_BE_NULL);
        }
        return executeCodeExchange(() -> requestAccessTokenWithCode(authorizationCode, tokenEndpoint,
            clientId, clientSecret, redirectUri));
    }

    /**
     * Exchange a refresh token for a new access token.
     *
     * @param refreshToken  The refresh token from a previous authorization
     * @param tokenEndpoint Token endpoint URL
     * @param clientId      OAuth 2.0 client ID
     * @param clientSecret  OAuth 2.0 client secret
     * @return TokenResponse containing a new access token and possibly a new refresh token
     * @throws LDQJdbcDriverRuntimeException if token refresh fails
     */
    public TokenResponse getTokenUsingRefreshToken(final String refreshToken,
                                                   @Nonnull final String tokenEndpoint,
                                                   @Nonnull final String clientId,
                                                   @Nonnull final String clientSecret) {
        return executeRefreshTokenExchange(refreshToken, () -> requestAccessTokenWithRefreshToken(refreshToken,
            tokenEndpoint, clientId, clientSecret));
    }

    /**
     * Makes an HTTP POST request to exchange authorization code for an access token.
     *
     * @param authorizationCode Authorization code
     * @param tokenEndpoint     Token endpoint URL
     * @param clientId          Client ID
     * @param clientSecret      Client secret
     * @param redirectUri       Redirect URI
     * @return JsonNode containing an access token
     * @throws IOException if request fails
     */
    @VisibleForTesting
    protected JsonNode requestAccessTokenWithCode(@Nonnull final String authorizationCode,
                                                  @Nonnull final String tokenEndpoint,
                                                  @Nonnull final String clientId,
                                                  @Nonnull final String clientSecret,
                                                  @Nonnull final String redirectUri)
        throws IOException {
        final FormBody formBody = new FormBody.Builder()
            .add(GRANT_TYPE_PARAM, GRANT_TYPE_AUTHORIZATION_CODE)
            .add(PARAM_AUTHORIZATION_CODE, authorizationCode)
            .add(PARAM_REDIRECT_URI, redirectUri)
            .add(PARAM_CLIENT_ID, clientId)
            .add(PARAM_CLIENT_SECRET, clientSecret)
            .build();

        return executeTokenRequest(tokenEndpoint, formBody);
    }

    /**
     * Makes HTTP request to exchange a refresh token for a new access token.
     * Protected to allow test mocking.
     *
     * @param refreshToken  The refresh token
     * @param tokenEndpoint Token endpoint URL
     * @param clientId      OAuth 2.0 client ID
     * @param clientSecret  OAuth 2.0 client secret
     * @return JsonNode containing the token response
     * @throws IOException if request fails
     */
    @VisibleForTesting
    protected JsonNode requestAccessTokenWithRefreshToken(@Nonnull final String refreshToken,
                                                          @Nonnull final String tokenEndpoint,
                                                          @Nonnull final String clientId,
                                                          @Nonnull final String clientSecret)
        throws IOException {
        final FormBody formBody = new FormBody.Builder()
            .add(GRANT_TYPE_PARAM, GRANT_TYPE_REFRESH_TOKEN)
            .add(PARAM_REFRESH_TOKEN, refreshToken)
            .add(PARAM_CLIENT_ID, clientId)
            .add(PARAM_CLIENT_SECRET, clientSecret)
            .build();

        return executeTokenRequest(tokenEndpoint, formBody);
    }

    /**
     * Get authorization code from the Workday authorization endpoint using PKCE (RFC 7636).
     * Appends {@code code_challenge} and {@code code_challenge_method=S256} to the authorization URL.
     *
     * @param authorizationEndpoint Workday authorization endpoint URL
     * @param clientId              OAuth 2.0 client ID
     * @param redirectUri           Redirect URI (e.g., https://localhost:8888/callback)
     * @param codeChallenge         Base64url-encoded SHA-256 hash of the code_verifier
     * @return Authorization code
     * @throws LDQJdbcDriverRuntimeException if authorization fails
     */
    public String getAuthorizationCodeWithPkce(@Nonnull final String authorizationEndpoint,
                                               @Nonnull final String clientId,
                                               @Nonnull final String redirectUri,
                                               @Nonnull final String codeChallenge) {
        final String state = generateState();
        final String authorizationUrl = HttpUrl.get(authorizationEndpoint)
            .newBuilder()
            .addQueryParameter(PARAM_RESPONSE_TYPE, RESPONSE_TYPE_CODE)
            .addQueryParameter(PARAM_CLIENT_ID, clientId)
            .addQueryParameter(PARAM_STATE, state)
            .addQueryParameter(PARAM_REDIRECT_URI, redirectUri)
            .addQueryParameter(PARAM_CODE_CHALLENGE, codeChallenge)
            .addQueryParameter(PARAM_CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD_S256)
            .build()
            .toString();

        return OAuth2CallbackServer.waitForAuthorizationCode(redirectUri, state, authorizationUrl, clientId);
    }

    /**
     * Exchange authorization code for token response using PKCE (RFC 7636).
     * Sends {@code code_verifier} in place of {@code client_secret} -- no client secret is required.
     *
     * @param authorizationCode Authorization code from callback
     * @param tokenEndpoint     Token endpoint URL
     * @param clientId          OAuth 2.0 client ID
     * @param redirectUri       Redirect URI (must match the one used in the authorization request)
     * @param codeVerifier      The original code_verifier whose hash was sent as code_challenge
     * @return TokenResponse containing an access token and optional refresh token
     * @throws LDQJdbcDriverRuntimeException if token exchange fails
     */
    public TokenResponse exchangeCodeForTokenResponseWithVerifier(final String authorizationCode,
                                                                  @Nonnull final String tokenEndpoint,
                                                                  @Nonnull final String clientId,
                                                                  @Nonnull final String redirectUri,
                                                                  @Nonnull final String codeVerifier) {
        if (IS_NOT_EMPTY.negate().test(authorizationCode)) {
            throw new LDQJdbcDriverRuntimeException(AUTHORIZATION_CODE_CANNOT_BE_NULL);
        }
        return executeCodeExchange(() -> requestAccessTokenWithCodeVerifier(authorizationCode,
            tokenEndpoint, clientId, redirectUri, codeVerifier));
    }

    /**
     * Exchange a refresh token for a new access token without a client secret (public client).
     * Per RFC 7636, PKCE clients authenticate via {@code client_id} only.
     *
     * @param refreshToken  The refresh token from a previous authorization
     * @param tokenEndpoint Token endpoint URL
     * @param clientId      OAuth 2.0 client ID
     * @return TokenResponse containing a new access token and possibly a new refresh token
     * @throws LDQJdbcDriverRuntimeException if token refresh fails
     */
    public TokenResponse getTokenUsingRefreshTokenPublicClient(@Nonnull final String refreshToken,
                                                               @Nonnull final String tokenEndpoint,
                                                               @Nonnull final String clientId) {
        return executeRefreshTokenExchange(refreshToken,
            () -> requestAccessTokenWithRefreshTokenPublicClient(refreshToken, tokenEndpoint, clientId));
    }

    /**
     * Makes an HTTP POST request to exchange authorization code for an access token using PKCE.
     * Sends {@code code_verifier} instead of {@code client_secret}.
     *
     * @param authorizationCode Authorization code
     * @param tokenEndpoint     Token endpoint URL
     * @param clientId          Client ID
     * @param redirectUri       Redirect URI
     * @param codeVerifier      PKCE code verifier
     * @return JsonNode containing the token response
     * @throws IOException if request fails
     */
    @VisibleForTesting
    protected JsonNode requestAccessTokenWithCodeVerifier(@Nonnull final String authorizationCode,
                                                          @Nonnull final String tokenEndpoint,
                                                          @Nonnull final String clientId,
                                                          @Nonnull final String redirectUri,
                                                          @Nonnull final String codeVerifier)
        throws IOException {
        final FormBody formBody = new FormBody.Builder()
            .add(GRANT_TYPE_PARAM, GRANT_TYPE_AUTHORIZATION_CODE)
            .add(PARAM_AUTHORIZATION_CODE, authorizationCode)
            .add(PARAM_REDIRECT_URI, redirectUri)
            .add(PARAM_CLIENT_ID, clientId)
            .add(PARAM_CODE_VERIFIER, codeVerifier)
            .build();

        return executeTokenRequest(tokenEndpoint, formBody);
    }

    /**
     * Makes an HTTP POST request to exchange a refresh token for a new access token without a client secret.
     *
     * @param refreshToken  The refresh token
     * @param tokenEndpoint Token endpoint URL
     * @param clientId      OAuth 2.0 client ID
     * @return JsonNode containing the token response
     * @throws IOException if request fails
     */
    @VisibleForTesting
    protected JsonNode requestAccessTokenWithRefreshTokenPublicClient(@Nonnull final String refreshToken,
                                                                      @Nonnull final String tokenEndpoint,
                                                                      @Nonnull final String clientId)
        throws IOException {
        final FormBody formBody = new FormBody.Builder()
            .add(GRANT_TYPE_PARAM, GRANT_TYPE_REFRESH_TOKEN)
            .add(PARAM_REFRESH_TOKEN, refreshToken)
            .add(PARAM_CLIENT_ID, clientId)
            .build();

        return executeTokenRequest(tokenEndpoint, formBody);
    }

    /**
     * Generates a random state parameter for CSRF protection.
     *
     * @return Base64URL-encoded random state
     */
    @VisibleForTesting
    protected static String generateState() {
        final byte[] stateBytes = new byte[16];
        SECURE_RANDOM.nextBytes(stateBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes);
    }

    @FunctionalInterface
    private interface TokenRequestSupplier {

        JsonNode get()
            throws IOException;
    }

    private TokenResponse executeCodeExchange(@Nonnull final TokenRequestSupplier supplier) {
        return parseTokenResponse(supplier, null);
    }

    private TokenResponse executeRefreshTokenExchange(final String refreshToken,
                                                      final TokenRequestSupplier supplier) {
        if (IS_NOT_EMPTY.negate().test(refreshToken)) {
            throw new LDQJdbcDriverRuntimeException(MSG_INVALID_REFRESH_TOKEN);
        }
        // Some OAuth servers rotate refresh tokens; fall back to the original if absent
        return parseTokenResponse(supplier, refreshToken);
    }

    /**
     * Executes a token request and parses the response to extract access and refresh tokens.
     *
     * @param supplier             Supplier that executes the HTTP request
     * @param fallbackRefreshToken If non-null, use as fallback when the response lacks refresh_token
     * @return TokenResponse containing an access token and optional refresh token
     */
    private TokenResponse parseTokenResponse(@Nonnull final TokenRequestSupplier supplier,
                                             final String fallbackRefreshToken) {
        try {
            final JsonNode responseNode = supplier.get();
            return OAuth2TokenUtil.parseTokenResponse(responseNode, fallbackRefreshToken);
        }
        catch (final IOException e) {
            throw new LDQJdbcDriverRuntimeException(ACCESS_TOKEN_REQUEST_FAILED_DUE_TO_NETWORK_ERROR, e);
        }
        catch (final ParseException e) {
            throw new LDQJdbcDriverRuntimeException(FAILED_TO_PARSE_ACCESS_TOKEN_FROM_TOKEN_RESPONSE, e);
        }
    }

    private JsonNode executeTokenRequest(@Nonnull final String tokenEndpoint,
                                         @Nonnull final FormBody formBody)
        throws IOException {
        final Request request = new Request.Builder()
            .url(tokenEndpoint)
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
                throw new LDQJdbcDriverRuntimeException(RESPONSE_BODY_FROM_TOKEN_ENDPOINT);
            }
            return OBJECT_MAPPER.readTree(body.string());
        }
    }

}
