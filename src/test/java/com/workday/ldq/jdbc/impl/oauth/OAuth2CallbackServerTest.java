/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Unit tests for OAuth2CallbackServer class.
 * Tests URI validation, localhost detection, and query parameter parsing.
 *
 */
class OAuth2CallbackServerTest {

    @ParameterizedTest
    @MethodSource("provideValidRedirectUris")
    @DisplayName("validateRedirectUri accepts valid URIs")
    void testValidateRedirectUri_ValidUris_Success(final String uriString, final String description)
        throws Exception {
        final URI uri = new URI(uriString);

        // Should not throw
        OAuth2CallbackServer.validateRedirectUri(uri);
    }

    private static Stream<Arguments> provideValidRedirectUris() {
        return Stream.of(
            Arguments.of("https://localhost:8888/oauth/v1/callback", "localhost with port 8888"),
            Arguments.of("https://127.0.0.1:9000/oauth/v1/callback", "127.0.0.1 with port 9000"),
            Arguments.of("https://[::1]:8888/oauth/v1/callback", "IPv6 loopback"),
            Arguments.of("https://localhost:1024/callback", "Lower port bound (1024)"),
            Arguments.of("https://localhost:8888/callback", "Common port (8888)"),
            Arguments.of("https://localhost:65535/callback", "Upper port bound (65535)"),

            // HTTP is supported for loopback redirects (RFC 8252 7.3)
            Arguments.of("http://localhost:8888/oauth/v1/callback", "HTTP localhost with port 8888"),
            Arguments.of("http://127.0.0.1:9000/oauth/v1/callback", "HTTP 127.0.0.1 with port 9000"),
            Arguments.of("http://[::1]:8888/oauth/v1/callback", "HTTP IPv6 loopback"),
            Arguments.of("http://localhost:1024/callback", "HTTP lower port bound (1024)"),
            Arguments.of("http://localhost:65535/callback", "HTTP upper port bound (65535)")
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidRedirectUris")
    @DisplayName("validateRedirectUri rejects invalid URIs")
    void testValidateRedirectUri_InvalidUris_ThrowsException(final String uriString,
                                                             final String expectedMessageFragment,
                                                             final String description)
        throws Exception {
        final URI uri = new URI(uriString);

        final LDQJdbcDriverRuntimeException exception = assertThrows(
            LDQJdbcDriverRuntimeException.class,
            () -> OAuth2CallbackServer.validateRedirectUri(uri),
            description
        );

        if (expectedMessageFragment != null && !expectedMessageFragment.isEmpty()) {
            assertTrue(
                exception.getMessage().contains(expectedMessageFragment),
                description + " - Expected message to contain: '" + expectedMessageFragment
                    + "', but was: '" + exception.getMessage() + "'"
            );
        }
        else {
            assertNotNull(exception.getMessage(), description);
        }
    }

    private static Stream<Arguments> provideInvalidRedirectUris() {
        return Stream.of(
            // Scheme validation
            Arguments.of(
                "lttp://localhost:8888/oauth/v1/callback", // mostly a typo like scenario
                "Invalid or missing scheme",
                "Invalid scheme should be rejected"
            ),

            // Host validation
            Arguments.of(
                "https://evil.com:8888/oauth/v1/callback",
                "evil.com",
                "Remote host should be rejected"
            ),
            Arguments.of(
                "https://example.com:8888/callback",
                "example.com",
                "Non-localhost domain should be rejected"
            ),

            // Port validation - privileged ports
            Arguments.of(
                "https://localhost:0/callback",
                "0",
                "Port 0 should be rejected"
            ),
            Arguments.of(
                "https://localhost:1/callback",
                "1",
                "Port 1 should be rejected"
            ),
            Arguments.of(
                "https://localhost:80/callback",
                "80",
                "Port 80 (privileged) should be rejected"
            ),
            Arguments.of(
                "https://localhost:443/callback",
                "443",
                "Port 443 (privileged) should be rejected"
            ),
            Arguments.of(
                "https://localhost:1023/callback",
                "1023",
                "Port 1023 (below 1024) should be rejected"
            ),

            // Port validation - above max
            Arguments.of(
                "https://localhost:65536/callback",
                "65536",
                "Port 65536 (above max) should be rejected"
            ),
            Arguments.of(
                "https://localhost:99999/callback",
                "99999",
                "Port 99999 should be rejected"
            ),

            // Missing port
            Arguments.of(
                "https://localhost/oauth/v1/callback",
                null,
                "Missing port should be rejected"
            ),

            // Path validation - missing path
            Arguments.of(
                "https://localhost:8888",
                "must include a path",
                "Missing path should be rejected"
            ),
            // Path validation - root path only
            Arguments.of(
                "https://localhost:8888/",
                "cannot be just '/'",
                "Root path only should be rejected"
            )
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "localhost", "LOCALHOST", "LocalHost",  // Case variations
        "127.0.0.1",                             // IPv4 loopback
        "::1", "[::1]", "0:0:0:0:0:0:0:1"       // IPv6 loopback variations
    })
    @DisplayName("isLocalhost accepts all valid localhost representations")
    void testIsLocalhost_ValidLocalhost_ReturnsTrue(final String host) {
        assertTrue(OAuth2CallbackServer.isLocalhost(host));
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "192.168.1.1", "10.0.0.1", "evil.com", ""})
    @NullSource
    @DisplayName("isLocalhost rejects non-localhost hosts and null")
    void testIsLocalhost_Invalid_ReturnsFalse(final String host) {
        assertFalse(OAuth2CallbackServer.isLocalhost(host));
    }

    @Test
    @DisplayName("parseQueryParams parses simple query string")
    void testParseQueryParams_SimpleQuery_Success() {
        final String query = "code=ABC123&state=XYZ789";

        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertEquals(2, params.size());
        assertEquals("ABC123", params.get("code"));
        assertEquals("XYZ789", params.get("state"));
    }

    @Test
    @DisplayName("parseQueryParams handles URL encoded values")
    void testParseQueryParams_UrlEncoded_Success() {
        final String query = "name=John+Doe&message=Hello%20World";

        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertEquals("John Doe", params.get("name"));
        assertEquals("Hello World", params.get("message"));
    }

    @Test
    @DisplayName("parseQueryParams handles empty value")
    void testParseQueryParams_EmptyValue_Success() {
        final String query = "key1=value1&key2=&key3=value3";

        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertEquals(3, params.size());
        assertEquals("value1", params.get("key1"));
        assertEquals("", params.get("key2"));
        assertEquals("value3", params.get("key3"));
    }

    @Test
    @DisplayName("parseQueryParams handles single parameter")
    void testParseQueryParams_SingleParam_Success() {
        final String query = "token=abc123";

        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertEquals(1, params.size());
        assertEquals("abc123", params.get("token"));
    }

    @Test
    @DisplayName("parseQueryParams returns empty map for null query")
    void testParseQueryParams_NullQuery_ReturnsEmptyMap() {
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(null);

        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    @Test
    @DisplayName("parseQueryParams returns empty map for empty query")
    void testParseQueryParams_EmptyQuery_ReturnsEmptyMap() {
        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams("");

        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    @Test
    @DisplayName("parseQueryParams ignores malformed parameters")
    void testParseQueryParams_MalformedParams_IgnoresThem() {
        final String query = "key1=value1&=nokey&key2=value2";

        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        // Should parse valid params and ignore malformed ones
        assertEquals("value1", params.get("key1"));
        assertEquals("value2", params.get("key2"));
    }

    @Test
    @DisplayName("parseQueryParams handles special characters")
    void testParseQueryParams_SpecialCharacters_Success() {
        final String query = "email=user%40example.com&path=%2Fhome%2Fuser";

        final Map<String, String> params = OAuth2CallbackServer.parseQueryParams(query);

        assertEquals("user@example.com", params.get("email"));
        assertEquals("/home/user", params.get("path"));
    }

    @Test
    @DisplayName("startHttpServer creates a plain HTTP server that serves the callback and root contexts")
    void testStartHttpServer_Http()
        throws Exception {
        final URI redirectUri = new URI("http://localhost:0/callback");
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final HttpHandler noopHandler = exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        };

        HttpServer server = null;
        try {
            server = OAuth2CallbackServer.startCallbackServer(redirectUri, executor, noopHandler, noopHandler);

            assertFalse(server instanceof HttpsServer, "http scheme must not start a TLS server");

            final int boundPort = server.getAddress().getPort();
            final HttpURLConnection callbackConnection =
                (HttpURLConnection) new URL("http://localhost:" + boundPort + "/callback").openConnection();
            assertEquals(200, callbackConnection.getResponseCode(), "callback context should respond over plain HTTP");

            final HttpURLConnection rootConnection =
                (HttpURLConnection) new URL("http://localhost:" + boundPort + "/").openConnection();
            assertEquals(200, rootConnection.getResponseCode(), "root context should respond over plain HTTP");
        }
        finally {
            executor.shutdownNow();
            if (server != null) {
                server.stop(0);
            }
        }
    }

    @Test
    @DisplayName("startHttpsServer creates a TLS-backed HttpsServer")
    void testStartHttpsServer_Https()
        throws Exception {
        final URI redirectUri = new URI("https://localhost:0/callback");
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final HttpHandler noopHandler = exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        };

        HttpServer server = null;
        try {
            server = OAuth2CallbackServer.startCallbackServer(redirectUri, executor, noopHandler, noopHandler);

            assertInstanceOf(HttpsServer.class, server, "https scheme must start a TLS server");
        }
        finally {
            executor.shutdownNow();
            if (server != null) {
                server.stop(0);
            }
        }
    }

}
