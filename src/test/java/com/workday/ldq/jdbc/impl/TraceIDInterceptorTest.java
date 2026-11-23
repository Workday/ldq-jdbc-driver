package com.workday.ldq.jdbc.impl;

import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.CONTENT_ENCODING_HEADER;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.HTTP_METHOD_POST;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.TRACE_ID_PREFIX;
import static com.workday.ldq.jdbc.impl.LDQJdbcAuthnConstants.WD_REQUEST_ID_HEADER;
import static com.workday.ldq.jdbc.impl.TraceIDInterceptor.TRINO_STATEMENT_URI_PATH;
import static io.trino.jdbc.$internal.client.ProtocolHeaders.TRINO_HEADERS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.trino.jdbc.$internal.okhttp3.Interceptor;
import io.trino.jdbc.$internal.okhttp3.MediaType;
import io.trino.jdbc.$internal.okhttp3.Protocol;
import io.trino.jdbc.$internal.okhttp3.Request;
import io.trino.jdbc.$internal.okhttp3.Response;
import io.trino.jdbc.$internal.okhttp3.ResponseBody;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests that query spans are always reclaimed.
 * <p>
 * Trino only issues DELETE when aborting a still-running query, so a query that runs to completion
 * never triggers the DELETE-based cleanup. These tests pin the behavior that every terminal path
 * still removes its entry.
 *
 * @author srinivas.dhanraj
 * @since Sep-2026
 */
class TraceIDInterceptorTest {

    private static final String QUERY_ID = "20260304_182502_00107_2xgc8";
    private static final String BASE_URL = "http://localhost:8080";
    private static final MediaType JSON = MediaType.get("application/json");
    private static final String TRINO_STATEMENT_EXECUTING_PATH_PREFIX =
        TraceIDInterceptor.TRINO_STATEMENT_URI_PATH + "/executing/";
    private static final String HTTP_METHOD_GET = "GET";
    private static final String HTTP_METHOD_DELETE = "DELETE";

    @Test
    @DisplayName("Retried error response on a poll keeps the same trace ID")
    void errorResponseOnPollKeepsTraceId()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        post(interceptor, body(QUERY_ID, true));

        final String pollPath = TRINO_STATEMENT_EXECUTING_PATH_PREFIX + QUERY_ID + "/1";
        final Request first = proceed(interceptor, newRequest(HTTP_METHOD_GET, pollPath),
            response(HttpURLConnection.HTTP_OK, body(QUERY_ID, true)));
        // 503 with no nextUri must not end tracking, since the same URI is retried.
        proceed(interceptor, newRequest(HTTP_METHOD_GET, pollPath),
            response(HttpURLConnection.HTTP_UNAVAILABLE, ""));
        assertEquals(1, interceptor.trackedQueryCount());

        final Request retry = proceed(interceptor, newRequest(HTTP_METHOD_GET, pollPath),
            response(HttpURLConnection.HTTP_OK, body(QUERY_ID, true)));

        assertEquals(first.header(TRINO_HEADERS.requestTraceToken()),
            retry.header(TRINO_HEADERS.requestTraceToken()));
    }

    @Test
    @DisplayName("IOException on a poll keeps the same trace ID for the retry")
    void ioExceptionOnPollKeepsTraceId()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        final Request first = post(interceptor, body(QUERY_ID, true));

        final String pollPath = TRINO_STATEMENT_EXECUTING_PATH_PREFIX + QUERY_ID + "/1";
        final Request failed = proceedFailing(interceptor, newRequest(HTTP_METHOD_GET, pollPath));
        assertEquals(1, interceptor.trackedQueryCount());

        final Request retry = proceed(interceptor, newRequest(HTTP_METHOD_GET, pollPath),
            response(HttpURLConnection.HTTP_OK, body(QUERY_ID, true)));

        assertEquals(first.header(TRINO_HEADERS.requestTraceToken()),
            failed.header(TRINO_HEADERS.requestTraceToken()));
        assertEquals(first.header(TRINO_HEADERS.requestTraceToken()),
            retry.header(TRINO_HEADERS.requestTraceToken()));
        assertEquals(1, interceptor.trackedQueryCount());
    }

    @Test
    @DisplayName("Non-statement requests pass through without a trace header or tracked entry")
    void nonStatementRequestsPassThroughUntouched()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        final String[] nonStatementPaths = {"/v1/stage/" + QUERY_ID + ".0", "/v1/info", "/v1/spooled/download/abc"};
        for (final String path : nonStatementPaths) {
            final Request sent = proceed(interceptor, newRequest(HTTP_METHOD_DELETE, path),
                response(HttpURLConnection.HTTP_OK, ""));

            assertNull(sent.header(TRINO_HEADERS.requestTraceToken()));
            assertNull(sent.header(WD_REQUEST_ID_HEADER));
        }
        assertEquals(0, interceptor.trackedQueryCount());
    }

    @Test
    @DisplayName("Trace headers are single valued")
    void traceHeadersAreSingleValued()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        final Request sent = post(interceptor, body(QUERY_ID, false));

        assertEquals(1, sent.headers().values(WD_REQUEST_ID_HEADER).size());
        assertEquals(1, sent.headers().values(TRINO_HEADERS.requestTraceToken()).size());
    }

    @Test
    @DisplayName("Trace ID sent on both headers carries the service prefix followed by a UUID")
    void traceIdHasServicePrefix()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        final Request sent = post(interceptor, body(QUERY_ID, true));

        for (final String header : new String[]{TRINO_HEADERS.requestTraceToken(), WD_REQUEST_ID_HEADER}) {
            final String traceId = sent.header(header);
            assertNotNull(traceId, header);
            assertTrue(traceId.startsWith(TRACE_ID_PREFIX), header + " should start with " + TRACE_ID_PREFIX);
            // the remainder must be a well-formed UUID
            UUID.fromString(traceId.substring(TRACE_ID_PREFIX.length()));
        }
        assertEquals(sent.header(TRINO_HEADERS.requestTraceToken()), sent.header(WD_REQUEST_ID_HEADER));
    }

    @Test
    @DisplayName("Service prefixed trace ID is unchanged when the query moves from the POST key to the real query ID")
    void servicePrefixSurvivesQueryIdRekey()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        final Request first = post(interceptor, body(QUERY_ID, true));
        final Request poll = get(interceptor, body(QUERY_ID, true));

        final String traceId = poll.header(TRINO_HEADERS.requestTraceToken());
        assertTrue(traceId.startsWith(TRACE_ID_PREFIX));
        assertEquals(first.header(TRINO_HEADERS.requestTraceToken()), traceId);
        assertEquals(traceId, poll.header(WD_REQUEST_ID_HEADER));
        assertEquals(first.header(WD_REQUEST_ID_HEADER), poll.header(WD_REQUEST_ID_HEADER));
    }

    @Test
    @DisplayName("Encoded POST response yields no response head, so the query ID is not recovered")
    void encodedPostResponseDoesNotRekeyQuery()
        throws Exception {
        final TraceIDInterceptor interceptor = new TraceIDInterceptor();
        final Response encoded = response(HttpURLConnection.HTTP_OK, body(QUERY_ID, true))
            .newBuilder()
            .header(CONTENT_ENCODING_HEADER, "gzip")
            .build();
        final Request first = proceed(interceptor, newRequest(HTTP_METHOD_POST, TRINO_STATEMENT_URI_PATH), encoded);
        assertNotNull(first.header(TRINO_HEADERS.requestTraceToken()));
        assertEquals(1, interceptor.trackedQueryCount());

        // The real query ID was never learned, so the poll finds no trace ID and no new one is minted.
        final Request poll = get(interceptor, body(QUERY_ID, true));

        assertNull(poll.header(TRINO_HEADERS.requestTraceToken()));
        assertNull(poll.header(WD_REQUEST_ID_HEADER));
        assertEquals(1, interceptor.trackedQueryCount());
    }

    private static Request post(final TraceIDInterceptor interceptor, final String responseBody)
        throws Exception {
        return proceed(interceptor, newRequest(HTTP_METHOD_POST, TRINO_STATEMENT_URI_PATH),
            response(HttpURLConnection.HTTP_OK, responseBody));
    }

    private static Request get(final TraceIDInterceptor interceptor, final String responseBody)
        throws Exception {
        return proceed(interceptor,
            newRequest(HTTP_METHOD_GET, TRINO_STATEMENT_EXECUTING_PATH_PREFIX + QUERY_ID + "/1"),
            response(HttpURLConnection.HTTP_OK, responseBody));
    }

    /**
     * Drives one interception and returns the request that actually reached the network.
     */
    private static Request proceed(final TraceIDInterceptor interceptor,
                                   final Request request,
                                   final Response response)
        throws Exception {
        final Interceptor.Chain chain = mock(Interceptor.Chain.class);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
            final Request sent = invocation.getArgument(0);
            return response.newBuilder().request(sent).build();
        });

        try (Response actual = interceptor.intercept(chain)) {
            return actual.request();
        }
    }

    /**
     * Drives one interception whose network call throws an IOException and returns the request that
     * was handed to the network.
     */
    private static Request proceedFailing(final TraceIDInterceptor interceptor, final Request request)
        throws Exception {
        final Interceptor.Chain chain = mock(Interceptor.Chain.class);
        final AtomicReference<Request> sent = new AtomicReference<>();
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
            sent.set(invocation.getArgument(0));
            throw new IOException("unexpected end of stream");
        });

        assertThrows(IOException.class, () -> interceptor.intercept(chain));
        return sent.get();
    }

    private static String body(final String queryId, final boolean hasNextUri) {
        // Mirrors Trino's QueryResults field order: id, infoUri, partialCancelUri, nextUri, ...
        final StringBuilder json = new StringBuilder()
            .append("{\"id\":\"").append(queryId).append("\"")
            .append(",\"infoUri\":\"").append(BASE_URL).append("/ui/query.html?").append(queryId).append("\"");
        if (hasNextUri) {
            json.append(",\"nextUri\":\"").append(BASE_URL)
                .append(TRINO_STATEMENT_EXECUTING_PATH_PREFIX).append(queryId).append("/1\"");
        }
        return json.append(",\"columns\":[],\"stats\":{}}").toString();
    }

    private static Response response(final int code, final String body) {
        return new Response.Builder()
            .request(newRequest(HTTP_METHOD_GET, TRINO_STATEMENT_URI_PATH))
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message("")
            .body(ResponseBody.create(body, JSON)).build();
    }

    private static Request newRequest(final String method, final String path) {
        final Request.Builder builder = new Request.Builder().url(BASE_URL + path);
        if (HTTP_METHOD_POST.equals(method)) {
            return builder.post(io.trino.jdbc.$internal.okhttp3.RequestBody.create("{}", JSON)).build();
        }
        return builder.method(method, null).build();
    }
}
