/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Test to validate that the shadow JAR manifest contains only the required attributes
 * and no unwanted attributes (e.g., vendor-specific attributes from proprietary build plugins).
 *
 */
class ManifestValidationTest {

    public static final Set<String> EXPECTED_ATTRIBUTES = Set.of(
        "Manifest-Version",
        "Main-Class",
        "Implementation-Title",
        "Implementation-Version",
        "Implementation-Vendor",
        "Automatic-Module-Name",
        "License",
        "Bundle-License",
        "Multi-Release"
    );
    private static File uberJarFile;

    @BeforeAll
    static void setup() {
        // Find the shadow JAR
        final File buildLibsDir = findBuildLibsDir();
        final File[] jarFiles = buildLibsDir.listFiles(
            (dir, name) -> name.startsWith("ldq-jdbc-driver-") && name.endsWith("-all.jar")
        );
        assertNotNull(jarFiles, "JAR output directory not found at: " + buildLibsDir.getAbsolutePath() +
            ". Make sure to run 'mvn package' (or './gradlew shadowJar') before running this test.");
        assertTrue(jarFiles.length > 0, "No fat JAR (*-all.jar) found in " + buildLibsDir.getAbsolutePath() +
            ". Make sure to run 'mvn package' (or './gradlew shadowJar') before running this test.");

        // Use the first matching JAR (should only be one)
        uberJarFile = jarFiles[0];
    }

    @Test
    void testManifestContainsOnlyRequiredAttributes()
        throws IOException {
        try (JarFile jar = new JarFile(uberJarFile)) {
            final Manifest manifest = jar.getManifest();
            assertNotNull(manifest, "Manifest not found in JAR");

            final Attributes mainAttributes = manifest.getMainAttributes();
            final Set<String> attributeKeys = mainAttributes.keySet()
                .stream()
                .map(Object::toString)
                .collect(Collectors.toSet());

            // Check that all expected attributes are present
            for (final String expected : EXPECTED_ATTRIBUTES) {
                assertTrue(
                    mainAttributes.containsKey(new Attributes.Name(expected)),
                    "Missing expected attribute: " + expected
                );
                attributeKeys.remove(expected);
            }

            // If all expected attributes are removed, attributeKeys should be empty
            if (!attributeKeys.isEmpty()) {
                throw new AssertionError("Found unexpected attributes in manifest: " + attributeKeys);
            }
        }
    }

    @Test
    void testJarContainsLicenseFile()
        throws IOException {
        try (JarFile jar = new JarFile(uberJarFile)) {
            final JarEntry licenseEntry = jar.getJarEntry("META-INF/LICENSE");
            assertNotNull(licenseEntry, "META-INF/LICENSE file not found in JAR");

            // Verify it's not empty
            assertTrue(licenseEntry.getSize() > 0, "META-INF/LICENSE file is empty");
        }
    }

    @Test
    void testJarContainsNoticeFile()
        throws IOException {
        try (JarFile jar = new JarFile(uberJarFile)) {
            final JarEntry noticeEntry = jar.getJarEntry("META-INF/NOTICE");
            assertNotNull(noticeEntry, "META-INF/NOTICE file not found in JAR");

            // Verify it's not empty
            assertTrue(noticeEntry.getSize() > 0, "META-INF/NOTICE file is empty");
        }
    }

    private static File findBuildLibsDir() {
        final File current = new File(".").getAbsoluteFile();

        // Maven: target/ (primary for this standalone repo)
        File outDir = new File(current, "target");
        if (outDir.exists()) {
            return outDir;
        }

        // Gradle: build/libs/
        outDir = new File(current, "build/libs");
        if (outDir.exists()) {
            return outDir;
        }

        outDir = new File(current, "ldq-jdbc-driver/target");
        if (outDir.exists()) {
            return outDir;
        }

        outDir = new File(current, "ldq-jdbc-driver/build/libs");
        if (outDir.exists()) {
            return outDir;
        }

        throw new IllegalStateException("Could not find Maven target/ or Gradle build/libs directory");
    }
}
