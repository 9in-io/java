package io.ninein.http;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** An HTTP response returned by an {@link HttpTransport}. Immutable. */
public final class HttpResponse {
    private final int status;
    private final Map<String, String> headers;
    private final byte[] body;

    public HttpResponse(int status, Map<String, String> headers, byte[] body) {
        this.status = status;
        this.headers = headers == null ? Collections.<String, String>emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        this.body = body == null ? new byte[0] : body.clone();
    }

    /** A response with a UTF-8 text body. */
    public static HttpResponse of(int status, Map<String, String> headers, String body) {
        return new HttpResponse(status, headers, body == null ? null : body.getBytes(StandardCharsets.UTF_8));
    }

    public int status() {
        return status;
    }

    public boolean isSuccessful() {
        return status >= 200 && status < 300;
    }

    /** Response headers (one value per name; repeated headers joined with ", "). */
    public Map<String, String> headers() {
        return headers;
    }

    /** A header by case-insensitive name, or null. */
    public String header(String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    public byte[] body() {
        return body.clone();
    }

    public String bodyText() {
        return new String(body, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "HTTP " + status;
    }
}
