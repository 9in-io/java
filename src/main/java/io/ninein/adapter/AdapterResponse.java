package io.ninein.adapter;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** What to send back to 9in: status, headers (including the response signature) and body. Immutable. */
public final class AdapterResponse {
    private final int status;
    private final Map<String, String> headers;
    private final byte[] body;

    public AdapterResponse(int status, Map<String, String> headers, byte[] body) {
        this.status = status;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        this.body = body == null ? new byte[0] : body.clone();
    }

    public int status() {
        return status;
    }

    public Map<String, String> headers() {
        return headers;
    }

    public byte[] body() {
        return body.clone();
    }

    public String bodyText() {
        return new String(body, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "AdapterResponse{status=" + status + "}";
    }
}
