/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

// Toolchain auto-provisioning is not used. Builds need JDK 11 (and optionally 17/21/25
// for testOnJava*). Gradle auto-detects standard local installations.

rootProject.name = "ldq-jdbc-driver"
