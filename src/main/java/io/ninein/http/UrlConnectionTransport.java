package io.ninein.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The default {@link HttpTransport}, on {@link HttpURLConnection}: no dependencies, works on the
 * JVM and on Android. 10 second connect and read timeouts; redirects are never followed (a 3xx
 * comes back as a response). Thread-safe.
 *
 * <p>The JDK's {@code HttpURLConnection} doesn't support {@code PATCH}; the server-side
 * {@code ManagementClient} therefore defaults to {@link JavaHttpClientTransport}.
 */
public final class UrlConnectionTransport implements HttpTransport {
    private static final int MAX_BODY = 8 * 1024 * 1024;

    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    /** 10 second connect and read timeouts. */
    public UrlConnectionTransport() {
        this(Duration.ofSeconds(10), Duration.ofSeconds(10));
    }

    public UrlConnectionTransport(Duration connectTimeout, Duration readTimeout) {
        this.connectTimeoutMillis = (int) Math.min(Integer.MAX_VALUE, connectTimeout.toMillis());
        this.readTimeoutMillis = (int) Math.min(Integer.MAX_VALUE, readTimeout.toMillis());
    }

    @Override
    public HttpResponse send(HttpRequest request) throws IOException {
        URL url = new URL(request.url());
        String protocol = url.getProtocol();
        if (!"https".equals(protocol) && !"http".equals(protocol)) {
            throw new IOException("unsupported URL scheme: " + protocol);
        }
        URLConnection raw = url.openConnection();
        if (!(raw instanceof HttpURLConnection)) throw new IOException("not an HTTP URL");
        HttpURLConnection conn = (HttpURLConnection) raw;
        try {
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(connectTimeoutMillis);
            conn.setReadTimeout(readTimeoutMillis);
            conn.setUseCaches(false);
            conn.setRequestMethod(request.method());
            for (Map.Entry<String, String> h : request.headers().entrySet()) {
                conn.setRequestProperty(h.getKey(), h.getValue());
            }
            byte[] body = request.body();
            if (body != null) {
                // Not in streaming mode: HttpURLConnection then keeps the body of a 401 that carries
                // an authentication challenge (9in's answer to a wrong client secret).
                conn.setDoOutput(true);
                try (OutputStream out = conn.getOutputStream()) {
                    out.write(body);
                }
            }
            int status = conn.getResponseCode();
            if (status < 0) throw new IOException("invalid HTTP response");
            Map<String, String> headers = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> h : conn.getHeaderFields().entrySet()) {
                if (h.getKey() == null || h.getValue() == null) continue;
                headers.put(h.getKey(), String.join(", ", h.getValue()));
            }
            InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            byte[] data = in == null ? new byte[0] : readAll(in);
            return new HttpResponse(status, headers, data);
        } finally {
            conn.disconnect();
        }
    }

    static byte[] readAll(InputStream in) throws IOException {
        try (InputStream input = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = input.read(buf)) != -1) {
                out.write(buf, 0, n);
                if (out.size() > MAX_BODY) throw new IOException("response body too large");
            }
            return out.toByteArray();
        }
    }
}
