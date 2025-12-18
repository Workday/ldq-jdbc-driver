/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    `java-library`
    `maven-publish`
    alias(libs.plugins.shadow)
}

group = "com.workday.ldq.jdbc"
version = libs.versions.ldq.jdbc.driver.get()

val artifactBaseName = "ldq-jdbc-driver"

// JDK 11 for external use and alignment with Trino JDBC
val javaReleaseVersion = libs.versions.java.get().toInt()

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(javaReleaseVersion))
    }
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(javaReleaseVersion)
}

tasks.withType<Javadoc>().configureEach {
    options.encoding = "UTF-8"
    (options as StandardJavadocDocletOptions).apply {
        source = javaReleaseVersion.toString()
        addStringOption("Xdoclint:none", "-quiet")
    }
    exclude("**/impl/**")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.trino.jdbc)
    implementation(libs.nimbusds.jose.jwt)
    implementation(libs.jackson.databind)
    implementation(libs.bundles.bouncycastle)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.bundles.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.bundles.mockito)
    testImplementation(libs.mockwebserver)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    if (name != "manifestValidationTest") {
        filter {
            excludeTestsMatching("com.workday.ldq.jdbc.integration.*")
            excludeTestsMatching("com.workday.ldq.jdbc.ManifestValidationTest")
        }
    }
}

// test on 11
tasks.test {
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(javaReleaseVersion))
    })
}

// Optional multi-JDK unit tests (same idea as SDE module)
listOf(JavaVersion.VERSION_17, JavaVersion.VERSION_21, JavaVersion.VERSION_25).map { v -> v.majorVersion.toInt() }
    .forEach { version ->
        val testTask = tasks.register<Test>("testOnJava$version") {
            javaLauncher.set(javaToolchains.launcherFor {
                languageVersion.set(JavaLanguageVersion.of(version))
            })
        }
        tasks.check { dependsOn(testTask) }
    }

tasks.jar {
    archiveBaseName.set(artifactBaseName)
    manifest {
        attributes(
            "Main-Class" to "com.workday.ldq.jdbc.api.LDQJdbcDriver",
            "Implementation-Title" to "Workday Live Data Query JDBC Driver",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Workday Inc.",
            "Automatic-Module-Name" to "com.workday.ldq.jdbc",
            "License" to "Apache-2.0",
            "Bundle-License" to "Apache-2.0;link=\"https://www.apache.org/licenses/LICENSE-2.0\""
        )
    }
    from("LICENSE") { into("META-INF") }
    from("NOTICE") { into("META-INF") }
}

tasks.shadowJar {
    mergeServiceFiles()
    mergeServiceFiles {
        include("META-INF/services/java.sql.Driver")
    }
    archiveBaseName.set(artifactBaseName)
    archiveClassifier.set("all")
    archiveVersion.set(project.version.toString())

    relocate("com.fasterxml.jackson", "com.workday.ldq.jdbc.shaded.jackson")
    relocate("com.nimbusds", "com.workday.ldq.jdbc.shaded.nimbusds")
    relocate("org.bouncycastle", "com.workday.ldq.jdbc.shaded.bouncycastle")

    from("LICENSE") { into("META-INF") }
    from("NOTICE") { into("META-INF") }

    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")

    doFirst {
        manifest.attributes.clear()
        manifest.attributes(
            "Manifest-Version" to "1.0",
            "Main-Class" to "com.workday.ldq.jdbc.api.LDQJdbcDriver",
            "Implementation-Title" to "Workday Live Data Query JDBC Driver",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Workday Inc.",
            "Automatic-Module-Name" to "com.workday.ldq.jdbc",
            "License" to "Apache-2.0",
            "Bundle-License" to "Apache-2.0;link=\"https://www.apache.org/licenses/LICENSE-2.0\""
        )
    }
}

// Stage the self-contained shaded driver jar where the JMeter performance runner can load it
// (JMeter's classpath). Using the shaded jar avoids dependency clashes with JMeter's own libs,
// and it already registers both TrinoDriver and DataServiceDriver via META-INF/services.
tasks.register<Copy>("collectJmeterLibs") {
    description = "Assembles the shaded driver jar into build/jmeter-lib for the JMeter perf suite."
    group = "build"
    from(tasks.shadowJar.flatMap { it.archiveFile })
    into(layout.buildDirectory.dir("jmeter-lib"))
}

tasks.register<Test>("manifestValidationTest") {
    group = "verification"
    description = "Validates fat JAR manifest/LICENSE/NOTICE (requires shadowJar)"
    dependsOn(tasks.shadowJar)
    filter {
        includeTestsMatching("com.workday.ldq.jdbc.ManifestValidationTest")
    }
    testClassesDirs = tasks.test.get().testClassesDirs
    classpath = tasks.test.get().classpath
}

tasks.build {
    dependsOn(tasks.shadowJar, "javadocJar")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = artifactBaseName
            // The shadow plugin adds the fat JAR (classifier "all") to the java component,
            // so from(components["java"]) already publishes it. Adding it again explicitly
            // caused "multiple artifacts with the identical extension and classifier".
            from(components["java"])
            pom {
                name.set("Workday Live Data Query JDBC Driver")
                description.set("JDBC driver for Workday Live Data Query (LDQ) — OAuth wrapper over Trino JDBC.")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
            }
        }
    }
}
