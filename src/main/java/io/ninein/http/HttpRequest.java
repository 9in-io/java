package io.ninein.http;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** An HTTP request the SDK sends through an {@link HttpTransport}. Immutable. */
public final class HttpRequest {
    private final String method;
    private final String url;
    private final Map<String, String> headers;
    private final byte[] body;

    private HttpRequest(Builder b) {
        this.method = b.method;
        this.url = b.url;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(b.headers));
        this.body = b.body == null ? null : b.body.clone();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Upper-case method, e.g. {@code GET}, {@code POST}. */
    public String method() {
        return method;
    }

    public String url() {
        return url;
    }

    /** Request headers (names as given). */
    public Map<String, String> headers() {
        return headers;
    }

    /** A header by case-insensitive name, or null. */
    public String header(String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    /** The body, or null for none. */
    public byte[] body() {
        return body == null ? null : body.clone();
    }

    /** The body as UTF-8 text ({@code ""} for none). */
    public String bodyText() {
        return body == null ? "" : new String(body, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return method + " " + url; // never the headers or body: they carry credentials
    }

    public static final class Builder {
        private String method = "GET";
        private String url;
        private final Map<String, String> headers = new LinkedHashMap<>();
        private byte[] body;

        private Builder() {}

        public Builder method(String method) {
            this.method = method.toUpperCase(Locale.ROOT);
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder header(String name, String value) {
            headers.put(name, value);
            return this;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers.putAll(headers);
            return this;
        }

        public Builder body(byte[] body) {
            this.body = body == null ? null : body.clone();
            return this;
        }

        public Builder body(String body) {
            this.body = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public HttpRequest build() {
            if (url == null) throw new IllegalStateException("url is required");
            return new HttpRequest(this);
        }
    }
}
