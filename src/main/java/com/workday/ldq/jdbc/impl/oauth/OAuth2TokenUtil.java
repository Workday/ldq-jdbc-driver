/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ACCESS_TOKEN_FIELD;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.ASSERTION_TOKEN_EXPIRY_IN_SECONDS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_JWS_ALGORITHM;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_JWT_ASSERTION_TOKEN_EXPIRY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_CONVERT_PEM_TO_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_PARSE_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.INVALID_PRIVATE_KEY_FORMAT;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.NO_ACCESS_TOKEN_FIELD_IN_RESPONSE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.NO_ACCESS_TOKEN_FOUND_IN_RESPONSE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.NO_PRIVATE_KEY_CONFIGURED;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_REFRESH_TOKEN;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.WDAY_AUDIENCE;
import static com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames.CLIENT_ID;
import static com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames.EXPIRATION_TIME;
import static com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames.SUBJECT;
import static com.workday.ldq.jdbc.impl.oauth.token.JWTClaimNames.TENANT;
import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.oauth.token.BearerAccessToken;
import com.workday.ldq.jdbc.impl.oauth.token.TokenResponse;

/**
 * Manages OAuth 2.0 JWT Bearer Grant Type token acquisition.
 * This class handles the creation of JWT assertions and token requests.
 *
 */
public class OAuth2TokenUtil {

    private static final Logger LOG = Logger.getLogger(OAuth2TokenUtil.class.getName());
    private static final int TOKEN_EXPIRY_IN_SECONDS = Integer.getInteger(DEFAULT_JWT_ASSERTION_TOKEN_EXPIRY,
        ASSERTION_TOKEN_EXPIRY_IN_SECONDS);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int CODE_VERIFIER_BYTE_LENGTH = 64;

    private OAuth2TokenUtil() {
        // Private constructor for utility class
    }

    /**
     * Create a JWT assertion for the OAuth 2.0 JWT Bearer Grant Type.
     *
     * @param config auth configuration
     * @return JWT assertion as a string
     */
    public static String createJWTAssertion(@Nonnull final OAuth2Config config)
        throws LDQJdbcDriverRuntimeException {
        try {
            final PrivateKey privateKey = loadPrivateKey(config.getPrivateKey());
            final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(config.getClientId())
                .subject(config.getIsu())
                .audience(WDAY_AUDIENCE)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(TOKEN_EXPIRY_IN_SECONDS)))
                .build();

            final JWSSigner signer = new RSASSASigner(privateKey);
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(DEFAULT_JWS_ALGORITHM).build(), claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        }
        catch (final JOSEException exp) {
            throw new LDQJdbcDriverRuntimeException("Failed to create JWT assertion", exp);
        }
    }

    /**
     * Load a private key from PEM string.
     * Supports PKCS#1 (RSA) and PKCS#8
     */
    @VisibleForTesting
    static PrivateKey loadPrivateKey(final String privateKey) {
        if (IS_NOT_EMPTY.negate().test(privateKey)) {
            throw new LDQJdbcDriverRuntimeException(NO_PRIVATE_KEY_CONFIGURED);
        }

        try (StringReader keyReader = new StringReader(privateKey);
             PEMParser pemParser = new PEMParser(keyReader)) {

            final Object object = pemParser.readObject();
            if (object == null) {
                // this happens if the provided private key is not in PEM format
                throw new LDQJdbcDriverRuntimeException(FAILED_TO_PARSE_PRIVATE_KEY);
            }
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (object instanceof PEMKeyPair) {
                // PKCS#1 format (RSA PRIVATE KEY)
                return converter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
            }
            else if (object instanceof PrivateKeyInfo) {
                // PKCS#8 format (PRIVATE KEY)
                return converter.getPrivateKey((PrivateKeyInfo) object);
            }
            else {
                throw new LDQJdbcDriverRuntimeException(
                    INVALID_PRIVATE_KEY_FORMAT + " Format found: " + object.getClass().getName());
            }
        }
        catch (final IOException e) {
            throw new LDQJdbcDriverRuntimeException(FAILED_TO_CONVERT_PEM_TO_PRIVATE_KEY, e);
        }
    }

    public static void shutdownExecutorService(@Nonnull final ExecutorService executorService) {
        try {
            executorService.shutdown();
            if (!executorService.awaitTermination(DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS, TimeUnit.MILLISECONDS)) {
                LOG.log(Level.WARNING, "scheduledExecutor is still running after shutdown(). Calling shutdownNow().");
                executorService.shutdownNow();
                if (!executorService.awaitTermination(DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS, TimeUnit.MILLISECONDS)) {
                    LOG.log(Level.WARNING, String.format("scheduledExecutor is still running %d ms after shutdownNow()",
                        DEFAULT_SCHEDULED_EXECUTOR_SHUTDOWN_MS));
                }
            }
        }
        catch (final InterruptedException ex) {
            LOG.log(Level.SEVERE, "Interrupted while awaiting termination of scheduledExecutor", ex);
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Generates a cryptographically random code_verifier per RFC 7636 Section 4.1.
     * Uses random bytes defined by {@link #CODE_VERIFIER_BYTE_LENGTH}, encoded as Base64url without padding,
     * producing exactly 86 characters.
     *
     * @return Base64url-encoded code_verifier (86 characters, unreserved character set)
     */
    public static String generateCodeVerifier() {
        final byte[] randomBytes = new byte[CODE_VERIFIER_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Computes the code_challenge from a code_verifier using the S256 method (RFC 7636 Section 4.2).
     * code_challenge = BASE64URL(SHA-256(code_verifier))
     *
     * @param codeVerifier the code_verifier generated by {@link #generateCodeVerifier()}
     * @return Base64url-encoded SHA-256 hash of the verifier (43 characters)
     */
    public static String generateCodeChallenge(@Nonnull final String codeVerifier) {
        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        }
        catch (final NoSuchAlgorithmException e) {
            // SHA-256 is required by the Java specification and will always be available
            throw new IllegalStateException("SHA-256 algorithm is unavailable", e);
        }
    }

    /**
     * Extracts and parses the access token from a token endpoint JSON response.
     *
     * @param responseNode JSON response from token endpoint
     * @return BearerAccessToken with parsed claims
     * @throws LDQJdbcDriverRuntimeException if the access token field is missing or empty
     * @throws ParseException                    if the access token is not a valid JWT
     */
    public static BearerAccessToken parseBearerAccessTokenFromResponse(@Nonnull final JsonNode responseNode)
        throws ParseException {
        final JsonNode accessTokenNode = responseNode.get(ACCESS_TOKEN_FIELD);
        if (accessTokenNode == null) {
            throw new LDQJdbcDriverRuntimeException(NO_ACCESS_TOKEN_FIELD_IN_RESPONSE);
        }
        final String accessTokenStr = accessTokenNode.asText();
        if (IS_NOT_EMPTY.negate().test(accessTokenStr)) {
            throw new LDQJdbcDriverRuntimeException(NO_ACCESS_TOKEN_FOUND_IN_RESPONSE);
        }
        final SignedJWT decodedToken = SignedJWT.parse(accessTokenStr);
        final Map<String, Object> claims = decodedToken.getJWTClaimsSet().getClaims();
        return BearerAccessToken.builder()
            .token(accessTokenStr)
            .expiryTime(claims.get(EXPIRATION_TIME))
            .idToken(decodedToken.getHeader().getKeyID())
            .tenant(claims.get(TENANT))
            .subject(claims.get(SUBJECT))
            .clientId(claims.get(CLIENT_ID))
            .build();
    }

    /**
     * Parses a token response and extracts both access token and refresh token.
     *
     * @param responseNode          The JSON response from the token endpoint
     * @param fallbackRefreshToken  If non-null, use as fallback when response lacks refresh_token
     * @return TokenResponse containing access token and optional refresh token
     * @throws ParseException if the access token cannot be parsed
     */
    public static TokenResponse parseTokenResponse(@Nonnull final JsonNode responseNode,
                                                   final String fallbackRefreshToken)
        throws ParseException {
        final BearerAccessToken accessToken = parseBearerAccessTokenFromResponse(responseNode);

        final JsonNode refreshTokenNode = responseNode.get(PARAM_REFRESH_TOKEN);
        final String refreshToken = refreshTokenNode != null
            ? refreshTokenNode.asText()
            : fallbackRefreshToken;

        return new TokenResponse(accessToken, refreshToken);
    }

}
