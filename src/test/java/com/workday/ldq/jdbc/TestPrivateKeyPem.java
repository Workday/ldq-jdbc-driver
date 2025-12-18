/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Generates ephemeral RSA private keys for unit tests (no checked-in PEM fixtures).
 */
public final class TestPrivateKeyPem {

    private TestPrivateKeyPem() {
    }

    public static KeyPair generateRsaKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        }
        catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA KeyPairGenerator unavailable", e);
        }
    }

    public static String toPkcs8Pem(final PrivateKey privateKey)
        throws IOException {
        try (StringWriter writer = new StringWriter();
             PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            pemWriter.flush();
            return writer.toString();
        }
    }

    public static String toPkcs1Pem(final KeyPair keyPair)
        throws IOException {
        final RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        final RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(
            rsaKey.getModulus(),
            rsaKey.getPublicExponent(),
            rsaKey.getPrivateExponent(),
            rsaKey.getPrimeP(),
            rsaKey.getPrimeQ(),
            rsaKey.getPrimeExponentP(),
            rsaKey.getPrimeExponentQ(),
            rsaKey.getCrtCoefficient());
        try (StringWriter writer = new StringWriter();
             PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("RSA PRIVATE KEY", rsaPrivateKey.getEncoded()));
            pemWriter.flush();
            return writer.toString();
        }
    }

    public static Path writePkcs8KeyFile(final Path directory)
        throws IOException {
        final Path keyFile = directory.resolve("test-private-key.pem");
        Files.writeString(keyFile, toPkcs8Pem(generateRsaKeyPair().getPrivate()));
        return keyFile;
    }
}
