package io.ninein.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link HttpTransport} on {@code java.net.http.HttpClient} (Java 11+, not on Android). The
 * default for {@code ManagementClient}, because {@code HttpURLConnection} can't send
 * {@code PATCH}. 10 second connect and request timeouts; redirects are never followed.
 * Thread-safe; share one.
 */
public final class JavaHttpClientTransport implements HttpTransport {
    private final HttpClient client;
    private final Duration timeout;

    /** 10 second timeouts. */
    public JavaHttpClientTransport() {
        this(Duration.ofSeconds(10));
    }

    public JavaHttpClientTransport(Duration timeout) {
        this.timeout = timeout;
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Uses your own client (its redirect policy should be {@code NEVER}). */
    public JavaHttpClientTransport(HttpClient client, Duration timeout) {
        this.client = client;
        this.timeout = timeout;
    }

    @Override
    public HttpResponse send(HttpRequest request) throws IOException {
        URI uri = URI.create(request.url());
        if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) throw new IOException("unsupported URL scheme: " + uri.getScheme());
        java.net.http.HttpRequest.Builder b = java.net.http.HttpRequest.newBuilder(uri).timeout(timeout);
        for (Map.Entry<String, String> h : request.headers().entrySet()) b.header(h.getKey(), h.getValue());
        byte[] body = request.body();
        b.method(request.method(), body == null
                ? java.net.http.HttpRequest.BodyPublishers.noBody()
                : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body));
        java.net.http.HttpResponse<byte[]> response;
        try {
            response = client.send(b.build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> h : response.headers().map().entrySet()) {
            headers.put(h.getKey(), String.join(", ", h.getValue()));
        }
        return new HttpResponse(response.statusCode(), headers, response.body());
    }
}
