/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.CONTENT_TYPE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_AUTHORIZATION_CODE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_ERROR;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_ERROR_DESCRIPTION;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.PARAM_STATE;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.REDIRECT_URI_HOST_ERROR;
import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.nio.charset.StandardCharsets.UTF_8;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;

import java.awt.Desktop;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;
import com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants;

/**
 * Local HTTP/HTTPS callback server for the OAuth 2.0 Authorization Code Grant flow.
 * Handles self-signed certificate creation, browser launching, and authorization
 * code capture from the Workday redirect.
 *
 */
class OAuth2CallbackServer {

    private static final Logger LOG = Logger.getLogger(OAuth2CallbackServer.class.getName());
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int RESPONSE_TIMEOUT_SECONDS = 3;
    private static final int MAX_CONCURRENT_REQUESTS = 2;
    private static final int HTTP_SERVER_BACKLOG = 2;
    private static final String HTTPS_SCHEME = "https";
    private static final String HTTP_SCHEME = "http";
    public static final String ROOT_PATH_RESPONSE = "OAuth callback server is running. Waiting for authorization...";
    public static final String ROOT_PATH = "/";
    public static final String SIGNATURE_ALGORITHM_SHA_256_WITH_RSA_ENCRYPTION = "SHA256WithRSAEncryption";
    public static final String CALLBACK_SERVER_CERTIFICATE_CN = "CN=localhost";
    public static final String SYSTEM_OS_NAME = "os.name";
    public static final String MAC_OS = "mac";
    public static final String WINDOWS = "win";
    public static final String UNIX_IDENTIFIER = "nix";
    public static final String LINUX_IDENTIFIER = "nux";

    // Shared SSL context — generated once so the browser shows only one certificate warning
    private static volatile SSLContext SHARED_SSL_CONTEXT = null;
    private static final Object SSL_CONTEXT_LOCK = new Object();

    private static final long AUTHORIZATION_TIMEOUT_SECONDS = 180; // 3 minutes

    private static final String STATE_MISMATCH_ERROR = "State mismatch - possible CSRF attack";
    private static final String AUTHORIZATION_FAILED_ERROR = "Authorization failed: ";
    private static final String AUTHORIZATION_TIMEOUT_ERROR =
        "Authorization timeout - user did not complete authentication within %d seconds. "
            + "If the browser shows a Workday error page, verify that client_id '%s' is correct "
            + "and that the redirect_uri matches what is registered in Workday.";
    private static final String FAILED_TO_START_CALLBACK_SERVER = "Failed to start local callback server";

    private OAuth2CallbackServer() {
        // Utility class
    }

    /**
     * Starts a local callback server, opens the authorization URL in the browser, and
     * blocks until the authorization code arrives or the timeout expires.
     *
     * @param redirectUri      Redirect URI (e.g., {@code http(s)://localhost:8888/callback})
     * @param expectedState    CSRF state value that must match the callback
     * @param authorizationUrl Full authorization URL to open in the browser
     * @param clientId         OAuth 2.0 client ID (used in timeout error message)
     * @return Authorization code received from the callback
     * @throws LDQJdbcDriverRuntimeException if the server fails to start, times out, or the
     *                                           authorization fails
     */
    static String waitForAuthorizationCode(@Nonnull final String redirectUri,
                                           @Nonnull final String expectedState,
                                           @Nonnull final String authorizationUrl,
                                           @Nonnull final String clientId) {
        ExecutorService executor = null;
        HttpServer callbackServer = null;
        try {
            final URI uri = new URI(redirectUri);
            validateRedirectUri(uri);

            final CompletableFuture<String> authCodeFuture = new CompletableFuture<>();
            final CompletableFuture<Void> responseDeliveredFuture = new CompletableFuture<>();
            executor = Executors.newFixedThreadPool(MAX_CONCURRENT_REQUESTS);

            final HttpHandler callbackPathHandler =
                new AuthorizationCallbackHandler(expectedState, authCodeFuture, responseDeliveredFuture);

            final HttpHandler rootPathHandler = exchange -> {
                try {
                    if (LOG.isLoggable(Level.FINEST)) {
                        LOG.fine(String.format("Received request to: %s ", exchange.getRequestURI()));
                    }
                    final byte[] bytes = ROOT_PATH_RESPONSE.getBytes(UTF_8);
                    exchange.sendResponseHeaders(HTTP_OK, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                    }
                }
                finally {
                    exchange.close();
                }
            };

            callbackServer = startCallbackServer(uri, executor, callbackPathHandler, rootPathHandler);
            // Using a browser connect to authorizationUrl location
            openBrowser(authorizationUrl);

            final String authorizationCode = authCodeFuture.get(AUTHORIZATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            LOG.fine("Authorization code received successfully");

            // Wait for the browser to receive the success HTML before shutting down
            try {
                responseDeliveredFuture.get(RESPONSE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
            catch (final Exception ignored) {
                // best-effort — server stops regardless
            }

            return authorizationCode;
        }
        catch (final TimeoutException e) {
            throw new LDQJdbcDriverRuntimeException(
                String.format(AUTHORIZATION_TIMEOUT_ERROR, AUTHORIZATION_TIMEOUT_SECONDS, clientId), e);
        }
        catch (final Exception e) {
            throw new LDQJdbcDriverRuntimeException(FAILED_TO_START_CALLBACK_SERVER, e);
        }
        finally {
            if (executor != null) {
                OAuth2TokenUtil.shutdownExecutorService(executor);
            }
            if (callbackServer != null) {
                callbackServer.stop(0);
                LOG.finer("Local callback server stopped");
            }
        }
    }

    @VisibleForTesting
    static void validateRedirectUri(final URI uri) {
        final String host = uri.getHost();
        if (!isLocalhost(host)) {
            throw new LDQJdbcDriverRuntimeException(REDIRECT_URI_HOST_ERROR + host);
        }

        if (!(HTTPS_SCHEME.equalsIgnoreCase(uri.getScheme()) || HTTP_SCHEME.equalsIgnoreCase(uri.getScheme()))) {
            throw new LDQJdbcDriverRuntimeException(
                String.format("Invalid or missing scheme for redirect URI: %s", uri.toString()));
        }

        final int port = uri.getPort();
        if (port < 1024 || port > 65535) {
            throw new LDQJdbcDriverRuntimeException(LDQJdbcAuthnConstants.REDIRECT_URI_PORT_ERROR + port);
        }

        final String path = uri.getPath();
        if (IS_NOT_EMPTY.negate().test(path)) {
            throw new LDQJdbcDriverRuntimeException("Redirect URI must include a path (e.g., /callback)");
        }

        if (ROOT_PATH.equals(path)) {
            throw new LDQJdbcDriverRuntimeException(
                "Redirect URI path cannot be just '/' - must include a specific path (e.g., /callback)");
        }
    }

    @VisibleForTesting
    protected static boolean isLocalhost(final String host) {
        if (host == null) {
            return false;
        }
        final String normalized = host.toLowerCase()
            .replace("[", "")  // Remove brackets
            .replace("]", "");

        return normalized.equals("localhost")
            || normalized.equals("127.0.0.1")
            || normalized.equals("::1")  // IPv6 loopback
            || normalized.equals("0:0:0:0:0:0:0:1");  // IPv6 loopback (expanded)
    }

    /**
     * Starts either HTTP or HTTPS server based on the redirect URI scheme.
     *
     * @param redirectUri     Full redirect URI (scheme determines HTTP vs HTTPS)
     * @param executor        Thread pool for handling requests
     * @param callbackHandler OAuth callback path handler
     * @param rootPathHandler root path handler
     * @return Started callback server
     * @throws IOException if server creation fails
     */
    @VisibleForTesting
    static HttpServer startCallbackServer(@Nonnull final URI redirectUri,
                                          @Nonnull final ExecutorService executor,
                                          @Nonnull final HttpHandler callbackHandler,
                                          @Nonnull final HttpHandler rootPathHandler)
        throws IOException {

        final HttpServer server;
        if (HTTPS_SCHEME.equalsIgnoreCase(redirectUri.getScheme())) {
            LOG.fine("Creating HTTPS server with self-signed certificate...");
            final SSLContext sslContext = createSelfSignedSSLContext();
            final HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(),
                redirectUri.getPort()), HTTP_SERVER_BACKLOG);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            server = httpsServer;
        }
        else {
            LOG.fine("Creating HTTP server...");
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), redirectUri.getPort()),
                HTTP_SERVER_BACKLOG);
        }

        // Common configuration for both HTTP and HTTPS
        server.createContext(redirectUri.getPath(), callbackHandler);
        server.createContext(ROOT_PATH, rootPathHandler);
        server.setExecutor(executor);
        server.start();

        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine(String.format("Local callback server started successfully - port: %d", redirectUri.getPort()));
        }

        return server;
    }

    /**
     * Creates (or returns the cached) SSL context backed by a self-signed certificate.
     * The context is shared across all instances, so the browser shows only one warning.
     */
    private static SSLContext createSelfSignedSSLContext() {
        if (SHARED_SSL_CONTEXT != null) {
            LOG.fine("Reusing existing self-signed SSL certificate for localhost");
            return SHARED_SSL_CONTEXT;
        }

        synchronized (SSL_CONTEXT_LOCK) {
            if (SHARED_SSL_CONTEXT != null) {
                LOG.fine("Reusing existing self-signed SSL certificate for localhost (after lock)");
                return SHARED_SSL_CONTEXT;
            }

            try {
                LOG.fine("Generating new self-signed SSL certificate for localhost (first time only)...");

                final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048, SECURE_RANDOM);
                final KeyPair keyPair = keyPairGenerator.generateKeyPair();

                final X509Certificate cert = createSelfSignedCertificate(keyPair);

                final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                keyStore.setKeyEntry("localhost", keyPair.getPrivate(), new char[0],
                    new Certificate[]{cert});

                final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, new char[0]);

                final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                sslContext.init(keyManagerFactory.getKeyManagers(), null, SECURE_RANDOM);

                SHARED_SSL_CONTEXT = sslContext;
                return sslContext;
            }
            catch (final Exception e) {
                throw new LDQJdbcDriverRuntimeException(
                    "Failed to create SSL context for HTTPS callback server", e);
            }
        }
    }

    private static X509Certificate createSelfSignedCertificate(final KeyPair keyPair) {
        try {
            final Instant now = Instant.now();
            final Date notBefore = Date.from(now);
            final Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

            final X509v3CertificateBuilder certBuilder =
                getX509v3CertificateBuilder(keyPair, notBefore, notAfter);

            final ContentSigner signer =
                new JcaContentSignerBuilder(SIGNATURE_ALGORITHM_SHA_256_WITH_RSA_ENCRYPTION)
                    .build(keyPair.getPrivate());

            final X509CertificateHolder certHolder = certBuilder.build(signer);
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        }
        catch (final Exception e) {
            throw new LDQJdbcDriverRuntimeException("Failed to create self-signed certificate", e);
        }
    }

    private static X509v3CertificateBuilder getX509v3CertificateBuilder(final KeyPair keyPair,
                                                                        final Date notBefore,
                                                                        final Date notAfter) {
        final X500Name issuer =
            new X500Name(CALLBACK_SERVER_CERTIFICATE_CN);

        return new JcaX509v3CertificateBuilder(
            issuer,
            new BigInteger(64, SECURE_RANDOM),
            notBefore,
            notAfter,
            issuer,
            keyPair.getPublic()
        );
    }

    /**
     * Opens the authorization URL in the system's default browser.
     * Falls back to OS-specific commands for headless or unsupported environments.
     */
    private static void openBrowser(final String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
                return;
            }
        }
        catch (final Exception e) {
            LOG.log(Level.WARNING, "Desktop API unavailable, falling back to OS command: " + e.getMessage(), e);
        }

        try {
            final String os = System.getProperty(SYSTEM_OS_NAME).toLowerCase();
            if (os.contains(MAC_OS)) {
                new ProcessBuilder("open", url).start();
            }
            else if (os.contains(WINDOWS)) {
                new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url).start();
            }
            else if (os.contains(UNIX_IDENTIFIER) || os.contains(LINUX_IDENTIFIER)) {
                new ProcessBuilder("xdg-open", url).start();
            }
            else {
                LOG.warning("Browser opening not supported on OS: " + System.getProperty(SYSTEM_OS_NAME)
                    + ". Open manually: " + url);
            }
        }
        catch (final Exception e) {
            LOG.log(Level.WARNING, "Failed to open browser. Open manually: " + url, e);
        }
    }

    /**
     * Parses query parameters from a URL query string.
     *
     * @param query Query string (maybe {@code null})
     * @return Map of parameter name to decoded value
     */
    @VisibleForTesting
    static Map<String, String> parseQueryParams(final String query) {
        final Map<String, String> params = new HashMap<>();
        if (IS_NOT_EMPTY.negate().test(query)) {
            return params;
        }

        final String[] pairs = query.split("&");
        for (final String pair : pairs) {
            final int idx = pair.indexOf("=");
            if (idx > 0) {
                final String key = URLDecoder.decode(pair.substring(0, idx), UTF_8);
                final String value = URLDecoder.decode(pair.substring(idx + 1), UTF_8);
                params.put(key, value);
            }
        }
        return params;
    }

    private static class AuthorizationCallbackHandler
        implements HttpHandler {

        private final String expectedState;
        private final CompletableFuture<String> authCodeFuture;
        private final CompletableFuture<Void> responseDeliveredFuture;

        AuthorizationCallbackHandler(final String expectedState,
                                     final CompletableFuture<String> authCodeFuture,
                                     final CompletableFuture<Void> responseDeliveredFuture) {
            this.expectedState = expectedState;
            this.authCodeFuture = authCodeFuture;
            this.responseDeliveredFuture = responseDeliveredFuture;
        }

        @Override
        public void handle(final HttpExchange exchange) {

            try {
                final String query = exchange.getRequestURI().getQuery();

                if (IS_NOT_EMPTY.negate().test(query)) {
                    LOG.warning("No query parameters received!");
                    this.authCodeFuture.completeExceptionally(
                        new LDQJdbcDriverRuntimeException("No query parameters received in callback"));
                    sendResponse(exchange, 400, "No query parameters received");
                    return;
                }

                final Map<String, String> params = parseQueryParams(query);
                LOG.fine("Callback received, parsed parameters: " + params.keySet());

                final String error = params.get(PARAM_ERROR);
                if (error != null) {
                    final String errorDescription = params.getOrDefault(PARAM_ERROR_DESCRIPTION, "Unknown error");
                    LOG.severe("Authorization error: " + error + " - " + errorDescription);
                    this.authCodeFuture.completeExceptionally(
                        new LDQJdbcDriverRuntimeException(AUTHORIZATION_FAILED_ERROR + error + " - " +
                            errorDescription));
                    sendResponse(exchange, 400, "Authorization failed: " + errorDescription);
                    return;
                }

                final String receivedState = params.get(PARAM_STATE);
                if (!this.expectedState.equals(receivedState)) {
                    LOG.severe("State mismatch!");
                    this.authCodeFuture.completeExceptionally(
                        new LDQJdbcDriverRuntimeException(STATE_MISMATCH_ERROR));
                    sendResponse(exchange, 400, "State mismatch - possible CSRF attack");
                    return;
                }

                final String code = params.get(PARAM_AUTHORIZATION_CODE);
                if (code == null || code.isEmpty()) {
                    LOG.severe("No authorization code in parameters!");
                    this.authCodeFuture.completeExceptionally(
                        new LDQJdbcDriverRuntimeException("No authorization code received"));
                    sendResponse(exchange, 400, "No authorization code received");
                    return;
                }

                if (!this.authCodeFuture.complete(code)) {
                    LOG.warning("Authorization already completed. Ignoring duplicate request.");
                    sendResponse(exchange, 410, "Authorization already completed");
                    return;
                }

                sendSuccessResponse(exchange);
            }
            catch (final Exception e) {
                LOG.log(Level.SEVERE, "Exception in callback handler", e);
                this.authCodeFuture.completeExceptionally(e);
                this.responseDeliveredFuture.completeExceptionally(e);
                try {
                    sendResponse(exchange, 500, "Internal error: " + e.getMessage());
                }
                catch (final IOException ioEx) {
                    LOG.log(Level.SEVERE, "Failed to send error response", ioEx);
                }
            }
            finally {
                exchange.close();
            }
        }

        private void sendResponse(final HttpExchange exchange, final int statusCode, final String message)
            throws IOException {
            final byte[] responseBytes = message.getBytes(UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }

        private void sendSuccessResponse(final HttpExchange exchange)
            throws IOException {
            final String htmlResponse = loadHtmlFromResource("/oauth/success.html");

            final byte[] responseBytes = htmlResponse.getBytes(UTF_8);
            exchange.getResponseHeaders().set(CONTENT_TYPE, "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(HTTP_OK, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
                os.flush();
            }
            this.responseDeliveredFuture.complete(null);
        }

        private String loadHtmlFromResource(final String resourcePath)
            throws IOException {
            try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
                if (is == null) {
                    throw new IOException("Resource not found: " + resourcePath);
                }
                return new String(is.readAllBytes(), UTF_8);
            }
        }
    }
}
