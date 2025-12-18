/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.FAILED_TO_PARSE_PRIVATE_KEY;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.NO_PRIVATE_KEY_CONFIGURED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import com.workday.ldq.jdbc.TestPrivateKeyPem;
import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Unit tests for OAuth2TokenUtil class.
 * Tests JWT assertion creation and algorithm parsing functionality.
 */
public class OAuth2TokenUtilTest {

    @Test
    public void testEmptyPrivateKey_ShouldThrowException() {
        assertThrows(LDQJdbcDriverRuntimeException.class, () -> OAuth2TokenUtil.loadPrivateKey(""),
            NO_PRIVATE_KEY_CONFIGURED);
    }

    @Test
    public void testNullPrivateKey_ShouldThrowException() {
        assertThrows(LDQJdbcDriverRuntimeException.class, () -> OAuth2TokenUtil.loadPrivateKey(null),
            NO_PRIVATE_KEY_CONFIGURED);
    }

    @Test
    public void testLoadPrivateKeyPKCS1()
        throws IOException {
        final KeyPair keyPair = TestPrivateKeyPem.generateRsaKeyPair();
        final String pkcs1Key = TestPrivateKeyPem.toPkcs1Pem(keyPair);
        final PrivateKey privateKey = OAuth2TokenUtil.loadPrivateKey(pkcs1Key);
        assertNotNull(privateKey);
        assertTrue(privateKey instanceof RSAPrivateKey);
    }

    @Test
    public void testLoadPrivateKeyPKCS8()
        throws IOException {
        final KeyPair keyPair = TestPrivateKeyPem.generateRsaKeyPair();
        final String pkcs8Key = TestPrivateKeyPem.toPkcs8Pem(keyPair.getPrivate());
        final PrivateKey privateKey = OAuth2TokenUtil.loadPrivateKey(pkcs8Key);
        assertNotNull(privateKey);
        assertTrue(privateKey instanceof RSAPrivateKey);
    }

    @Test
    public void testLoadPrivateKey() {
        final String incorrectFormatPK = "-----BEGIN PRIVATE KEY-----testbadformat";
        assertThrows(LDQJdbcDriverRuntimeException.class, () -> OAuth2TokenUtil.loadPrivateKey(incorrectFormatPK),
            FAILED_TO_PARSE_PRIVATE_KEY);
    }

    @Test
    void testGenerateCodeVerifierLength() {
        final String verifier = OAuth2TokenUtil.generateCodeVerifier();
        assertEquals(86, verifier.length());
    }

    @Test
    void testGenerateCodeVerifierCharacterSet() {
        final String verifier = OAuth2TokenUtil.generateCodeVerifier();
        assertTrue(Pattern.matches("[A-Za-z0-9\\-_]+", verifier),
            "code_verifier must only contain base64url characters (RFC 7636 unreserved subset)");
    }

    @Test
    void testGenerateCodeVerifierIsUnique() {
        final String verifier1 = OAuth2TokenUtil.generateCodeVerifier();
        final String verifier2 = OAuth2TokenUtil.generateCodeVerifier();
        assertNotEquals(verifier1, verifier2, "Each code_verifier must be unique");
    }

    @Test
    void testGenerateCodeChallengeLength() {
        final String verifier = OAuth2TokenUtil.generateCodeVerifier();
        final String challenge = OAuth2TokenUtil.generateCodeChallenge(verifier);
        assertEquals(43, challenge.length());
    }

    @Test
    void testGenerateCodeChallengeIsDeterministic() {
        final String verifier = OAuth2TokenUtil.generateCodeVerifier();
        final String challenge1 = OAuth2TokenUtil.generateCodeChallenge(verifier);
        final String challenge2 = OAuth2TokenUtil.generateCodeChallenge(verifier);
        assertEquals(challenge1, challenge2, "Same verifier must always produce the same challenge");
    }

    @Test
    void testGenerateCodeChallengeIsUniquePerVerifier() {
        final String challenge1 = OAuth2TokenUtil.generateCodeChallenge(OAuth2TokenUtil.generateCodeVerifier());
        final String challenge2 = OAuth2TokenUtil.generateCodeChallenge(OAuth2TokenUtil.generateCodeVerifier());
        assertNotEquals(challenge1, challenge2, "Different verifiers must produce different challenges");
    }

    @Test
    void testGenerateCodeChallengeCharacterSet() {
        final String challenge = OAuth2TokenUtil.generateCodeChallenge(OAuth2TokenUtil.generateCodeVerifier());
        assertTrue(Pattern.matches("[A-Za-z0-9\\-_]+", challenge),
            "code_challenge must only contain base64url characters");
    }
}
