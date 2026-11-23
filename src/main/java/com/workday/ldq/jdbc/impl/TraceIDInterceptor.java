package com.workday.ldq.jdbc.impl;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.CONTENT_ENCODING_HEADER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_METHOD_POST;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TRACE_ID_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.WD_REQUEST_ID_HEADER;
import static io.trino.jdbc.$internal.client.ProtocolHeaders.TRINO_HEADERS;

import io.trino.jdbc.$internal.guava.annotations.VisibleForTesting;
import io.trino.jdbc.$internal.guava.cache.Cache;
import io.trino.jdbc.$internal.guava.cache.CacheBuilder;
import io.trino.jdbc.$internal.jakarta.annotation.Nonnull;
import io.trino.jdbc.$internal.jakarta.annotation.Nullable;
import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;
import io.trino.jdbc.$internal.okhttp3.ResponseBody;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OkHttp interceptor that manages Trace propagation for Trino queries.
 *
 * <p>This interceptor ensures that a single trace ID is maintained across all HTTP requests
 * for a single Trino query execution, even when OkHttp switches threads between requests.
 *
 * <p>The traceId is propagated in the HTTP header "X-Trino-Trace-Token" to pass a trace ID to the Trino server and
 * in the HTTP header "x-wd-request-id" to pass the trace ID to be used as common request ID for Galahad.
 * </p>
 *
 * <p>All query-related HTTP calls go through /v1/statement, so only those requests are tracked for a traceId;
 * Anything else (/v1/stage partial cancels, spooled segment downloads,/v1/info, ...) is passed through
 * untouched: no header, no key, no body peek.
 * </p>
 *
 * @author srinivas.dhanraj
 * @since Oct-2026
 */
public final class TraceIDInterceptor
    implements Interceptor {

    static final String TRINO_STATEMENT_URI_PATH = "/v1/statement";
    private static final Logger LOG = Logger.getLogger(TraceIDInterceptor.class.getName());

    // Pattern to extract query ID from Trino URLs like /v1/statement/queued/20260304_182502_00107_2xgc8/...
    private static final Pattern PATTERN_FOR_IN_PROGRESS_QUERIES = Pattern.compile(
        "/v1/statement/(?:queued|executing)/([^/]+)");

    // Pattern to extract query ID from JSON response: "id":"20260304_182502_00107_2xgc8"
    private static final Pattern JSON_QUERY_ID_PATTERN =
        Pattern.compile("\"id\"\\s*:\\s*\"(\\d{8}_\\d{6}_\\d{5}_[a-z0-9]+)\"");

    private static final long MAX_PEEK_BYTES = 1024L;
    private static final String NEXT_URI_FIELD = "\"nextUri\"";

    // Backstop for entries that are never removed explicitly, for example, a query abandoned by its client.
    private static final long TRACE_IDLE_TTL_HOURS = 1L;
    private static final long MAX_TRACKED_QUERIES = 10_000L;

    // Map query ID to TraceId - shared across all threads handling the same query
    // This is a bounded cache, so entries are removed after a TTL.
    private final Cache<String, String> queryTracingMap = CacheBuilder.newBuilder()
        .expireAfterAccess(TRACE_IDLE_TTL_HOURS, TimeUnit.HOURS)
        .maximumSize(MAX_TRACKED_QUERIES)
        .build();

    // Counter for generating unique temporary query IDs for POST requests
    private final AtomicLong requestCounter = new AtomicLong(0);

    @Override
    public Response intercept(final @Nonnull Chain chain)
        throws IOException {
        final Request request = chain.request();

        if (!request.url().encodedPath().contains(TRINO_STATEMENT_URI_PATH)) {
            return chain.proceed(request);
        }
        final String traceIdKey = extractTraceKey(request);

        // Detect if this is the start of a new query (POST to /v1/statement)
        final boolean isNewQuery = HTTP_METHOD_POST.equals(request.method())
            && request.url().encodedPath().endsWith(TRINO_STATEMENT_URI_PATH);

        final String traceId = getTraceID(traceIdKey, isNewQuery);

        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine(String.format("Request - %s %s (queryId: %s, traceId: %s)",
                request.method(), request.url().encodedPath(), traceIdKey, traceId));
        }

        final Request.Builder requestBuilder = request.newBuilder();
        if (traceId != null) {
            requestBuilder.header(TRINO_HEADERS.requestTraceToken(), traceId);
            requestBuilder.header(WD_REQUEST_ID_HEADER, traceId);
        }
        final Request requestWithTrace = requestBuilder.build();

        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine(String.format("TraceID after trace injection: %s - %s : %s",
                requestWithTrace.method(),
                requestWithTrace.url().encodedPath(),
                requestWithTrace.headers().get(TRINO_HEADERS.requestTraceToken())));
        }
        final Response response = chain.proceed(requestWithTrace);

        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine(String.format("Response - %s %s -> HTTP %d %s (queryId: %s, successful: %b)",
                requestWithTrace.method(),
                requestWithTrace.url().encodedPath(),
                response.code(),
                response.message(),
                traceIdKey,
                response.isSuccessful()));
        }

        // For POST requests, extract the real query ID from the response and update the map
        if (isNewQuery) {
            if (response.isSuccessful()) {
                // Read the head of the statement response to recover the real query ID on a POST
                final String responseHead = peekResponseHead(response);
                updateTraceIdWithRealQueryId(traceIdKey, traceId, responseHead);
            }
        }

        return response;
    }

    /**
     * Number of queries currently being tracked.
     *
     * @return the number of tracked queries
     */
    @VisibleForTesting
    long trackedQueryCount() {
        return this.queryTracingMap.size();
    }

    @Nullable
    private String getTraceID(final String traceKey, final boolean isNewQuery) {
        if (isNewQuery) {
            final String traceId = TRACE_ID_PREFIX + UUID.randomUUID();
            this.queryTracingMap.put(traceKey, traceId);
            return traceId;
        }
        return this.queryTracingMap.getIfPresent(traceKey);
    }

    /**
     * Extract query ID from the request URL.
     * For POST /v1/statement, returns a unique placeholder since the query ID isn't assigned yet.
     * For GET/DELETE /v1/statement/{state}/{queryId}/..., extracts the queryId.
     */
    private @Nonnull String extractTraceKey(final Request request) {
        final String path = request.url().encodedPath();
        // New Query - for POST /v1/statement
        if (HTTP_METHOD_POST.equals(request.method()) && path.endsWith(TRINO_STATEMENT_URI_PATH)) {
            return String.format("POST_%d", this.requestCounter.incrementAndGet());
        }

        // For GET/DELETE
        final Matcher matcher = PATTERN_FOR_IN_PROGRESS_QUERIES.matcher(path);
        if (matcher.find()) {
            return matcher.group(1);
        }

        // Fallback - shouldn't happen in a normal operation
        return String.format("UNKNOWN_%d", this.requestCounter.incrementAndGet());
    }

    /**
     * After a POST /v1/statement, extract the real query ID from the response body
     * and update the traceId map to use the real query ID instead of the temporary POST_threadId key.
     * <p>
     * Uses peekBody() to read the response without consuming it, avoiding the need to reconstruct
     * the response.
     *
     * @param tempQueryId  the temporary query ID (POST_n)
     * @param traceId      the traceId to associate with the real query ID
     * @param responseHead the decoded head of the POST response, or null if it could not be read
     * @return the real query ID the traceId is now filed under, or null if it could not be recovered
     */
    private String updateTraceIdWithRealQueryId(final String tempQueryId,
                                                final String traceId,
                                                @Nullable final String responseHead) {
        if (responseHead == null) {
            LOG.warning(String.format("Could not read POST response head; no query ID for %s", tempQueryId));
            return null;
        }

        final Matcher matcher = JSON_QUERY_ID_PATTERN.matcher(responseHead);
        if (!matcher.find()) {
            LOG.warning("Could not find query ID in response body");
            return null;
        }

        final String realQueryId = matcher.group(1);
        if (LOG.isLoggable(Level.FINE)) {
            LOG.fine(String.format("TRACE_ID DEBUG - POST response: tempQueryId=%s -> realQueryId=%s, hasNextUri=%b",
                tempQueryId, realQueryId, responseHead.contains(NEXT_URI_FIELD)));
        }

        // Remove the temporary key and add the real query ID
        this.queryTracingMap.invalidate(tempQueryId);
        this.queryTracingMap.put(realQueryId, traceId);
        LOG.info(String.format("TraceId='%s' for queryid='%s'", traceId, realQueryId));
        return realQueryId;
    }

    /**
     * Reads a bounded prefix of a statement response without consuming it.
     * <p>
     * Trino serialises QueryResults as id, infoUri, partialCancelUri, nextUri, columns, data, ...
     * Both "id" and "nextUri" therefore sit within the first few hundred bytes, well ahead of the
     * row data, so a bounded peek can read them without pulling a whole result page onto the heap.
     *
     * @param response the statement response
     * @return the decoded prefix, or null if it could not be read
     */
    @Nullable
    private String peekResponseHead(final Response response) {
        try {
            final String contentEncoding = response.header(CONTENT_ENCODING_HEADER);
            if (contentEncoding == null || contentEncoding.isBlank()) {
                final ResponseBody peekedBody = response.peekBody(MAX_PEEK_BYTES);
                final byte[] bodyBytes = peekedBody.bytes();
                return new String(bodyBytes, StandardCharsets.UTF_8);
            }
            return null;
        }
        catch (final Exception e) {
            LOG.warning(String.format("Failed to read response head: %s", e.getMessage()));
            return null;
        }
    }
}
