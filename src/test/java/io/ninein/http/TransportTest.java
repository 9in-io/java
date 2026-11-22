package io.ninein.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Both transports against a real local HTTP server. */
class TransportTest {
    static HttpServer server;
    static String base;

    @BeforeAll
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/echo", ex -> {
            byte[] body = read(ex.getRequestBody());
            String text = ex.getRequestMethod() + "|" + ex.getRequestHeaders().getFirst("X-Test") + "|" + ex.getRequestHeaders().getFirst("Content-Type")
                    + "|" + new String(body, StandardCharsets.UTF_8);
            respond(ex, 200, text);
        });
        server.createContext("/error", ex -> respond(ex, 400, "{\"error\":\"invalid_request\"}"));
        server.createContext("/redirect", ex -> {
            ex.getResponseHeaders().add("Location", base + "/echo");
            respond(ex, 302, "");
        });
        server.createContext("/slow", ex -> {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(ex, 200, "late");
        });
        server.createContext("/unauthorized", ex -> {
            read(ex.getRequestBody());
            ex.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"9in\"");
            ex.getResponseHeaders().add("Content-Type", "application/json");
            byte[] bytes = "{\"error\":\"invalid_client\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(401, bytes.length);
            ex.getResponseBody().write(bytes);
            ex.close();
        });
        server.createContext("/empty", ex -> {
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    static Stream<HttpTransport> transports() {
        return Stream.of(new UrlConnectionTransport(), new JavaHttpClientTransport());
    }

    @ParameterizedTest
    @MethodSource("transports")
    void getAndPost(HttpTransport t) throws IOException {
        HttpResponse get = t.send(HttpRequest.builder().url(base + "/echo").header("X-Test", "1").build());
        assertEquals(200, get.status());
        assertEquals("GET|1|null|", get.bodyText());
        assertEquals("text/plain", get.header("content-type"));
        HttpResponse post = t.send(HttpRequest.builder().method("post").url(base + "/echo").header("Content-Type", "application/x-www-form-urlencoded").body("a=1&b=%C3%A9").build());
        assertEquals("POST|null|application/x-www-form-urlencoded|a=1&b=%C3%A9", post.bodyText());
        HttpResponse delete = t.send(HttpRequest.builder().method("DELETE").url(base + "/echo").build());
        assertTrue(delete.bodyText().startsWith("DELETE|"));
        assertEquals(204, t.send(HttpRequest.builder().url(base + "/empty").build()).status());
    }

    @ParameterizedTest
    @MethodSource("transports")
    void errorsComeBackAsResponses(HttpTransport t) throws IOException {
        HttpResponse r = t.send(HttpRequest.builder().method("POST").url(base + "/error").body("x").build());
        assertEquals(400, r.status());
        assertEquals("{\"error\":\"invalid_request\"}", r.bodyText());
    }

    @ParameterizedTest
    @MethodSource("transports")
    void authenticationChallengesKeepTheirBody(HttpTransport t) throws IOException {
        // 9in answers a wrong client secret with 401, WWW-Authenticate: Basic and {"error":"invalid_client"}.
        HttpResponse post = t.send(HttpRequest.builder().method("POST").url(base + "/unauthorized")
                .header("Authorization", "Basic d3Jvbmc6d3Jvbmc=").header("Content-Type", "application/x-www-form-urlencoded").body("grant_type=client_credentials").build());
        assertEquals(401, post.status());
        assertEquals("{\"error\":\"invalid_client\"}", post.bodyText());
        HttpResponse get = t.send(HttpRequest.builder().url(base + "/unauthorized").build());
        assertEquals(401, get.status());
        assertEquals("{\"error\":\"invalid_client\"}", get.bodyText());
    }

    @ParameterizedTest
    @MethodSource("transports")
    void redirectsAreNotFollowed(HttpTransport t) throws IOException {
        HttpResponse r = t.send(HttpRequest.builder().url(base + "/redirect").header("Authorization", "Bearer secret").build());
        assertEquals(302, r.status());
        assertEquals(base + "/echo", r.header("Location"));
    }

    @Test
    void timeouts() {
        assertThrows(IOException.class, () -> new UrlConnectionTransport(Duration.ofSeconds(1), Duration.ofMillis(300)).send(HttpRequest.builder().url(base + "/slow").build()));
        assertThrows(IOException.class, () -> new JavaHttpClientTransport(Duration.ofMillis(300)).send(HttpRequest.builder().url(base + "/slow").build()));
    }

    @Test
    void onlyHttpUrls() {
        assertThrows(IOException.class, () -> new UrlConnectionTransport().send(HttpRequest.builder().url("file:///etc/passwd").build()));
        assertThrows(Exception.class, () -> new JavaHttpClientTransport().send(HttpRequest.builder().url("file:///etc/passwd").build()));
    }

    @Test
    void patch() throws IOException {
        // java.net.http can PATCH (the Management API needs it); the JDK's HttpURLConnection can't.
        HttpResponse r = new JavaHttpClientTransport().send(HttpRequest.builder().method("PATCH").url(base + "/echo").header("Content-Type", "application/json").body("{\"blocked\":true}").build());
        assertEquals("PATCH|null|application/json|{\"blocked\":true}", r.bodyText());
        assertThrows(ProtocolException.class, () -> new UrlConnectionTransport().send(HttpRequest.builder().method("PATCH").url(base + "/echo").body("{}").build()));
    }

    @Test
    void requestAndResponseValues() {
        HttpRequest r = HttpRequest.builder().method("post").url("https://x/y").header("Authorization", "Basic abc").body("secret=1").build();
        assertEquals("POST https://x/y", r.toString());
        assertEquals("Basic abc", r.header("authorization"));
        byte[] body = r.body();
        body[0] = 'X';
        assertEquals("secret=1", r.bodyText(), "defensive copies");
        assertThrows(IllegalStateException.class, () -> HttpRequest.builder().build());
        HttpResponse resp = HttpResponse.of(201, null, null);
        assertEquals("", resp.bodyText());
        assertTrue(resp.isSuccessful());
        assertEquals("HTTP 201", resp.toString());
    }

    static void respond(HttpExchange ex, int status, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/plain");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) ex.getResponseBody().write(bytes);
        ex.close();
    }

    static byte[] read(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        return out.toByteArray();
    }
}
