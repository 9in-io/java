package io.ninein.internal;

import io.ninein.Discovery;
import io.ninein.NineException;
import io.ninein.http.HttpRequest;
import io.ninein.http.HttpResponse;
import io.ninein.http.HttpTransport;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One tenant's issuer as seen by a client: HTTP through the transport, the cached discovery
 * document and the cached JWKS (10 minutes; one refetch for an unknown {@code kid}, then that
 * kid is ignored for a minute so junk tokens can't make us hammer the JWKS endpoint).
 * Thread-safe. Internal to the SDK.
 */
public final class Tenant {
    static final Duration DISCOVERY_TTL = Duration.ofHours(1);
    static final Duration JWKS_TTL = Duration.ofMinutes(10);
    static final Duration MISS_THROTTLE = Duration.ofSeconds(60);

    private final String issuer;
    private final HttpTransport transport;
    private final Clock clock;

    private final Object discoveryLock = new Object();
    private volatile Discovery discovery;
    private volatile Instant discoveryFetchedAt;

    private final Object jwksLock = new Object();
    private volatile List<Map<String, Object>> keys;
    private volatile Instant keysFetchedAt;
    private volatile long keysGeneration;
    private final Map<String, Instant> missingKids = new ConcurrentHashMap<>();

    public Tenant(String issuer, HttpTransport transport, Clock clock) {
        this.issuer = issuer;
        this.transport = transport;
        this.clock = clock;
    }

    public String issuer() {
        return issuer;
    }

    public Clock clock() {
        return clock;
    }

    public HttpTransport transport() {
        return transport;
    }

    // ---- HTTP ----

    /** Sends a request; a network failure becomes {@code network_error}. Never logs anything. */
    public HttpResponse send(HttpRequest request) {
        try {
            HttpResponse response = transport.send(request);
            if (response == null) throw new NineException("network_error", "no response from " + hostOf(request.url()));
            return response;
        } catch (IOException e) {
            throw new NineException("network_error", "request to " + hostOf(request.url()) + " failed: " + e.getClass().getSimpleName(), null, e);
        }
    }

    /** GET a JSON object. */
    public Map<String, Object> getJson(String url, Map<String, String> headers, String errorCode) {
        HttpRequest.Builder b = HttpRequest.builder().method("GET").url(url).header("Accept", "application/json");
        if (headers != null) b.headers(headers);
        return jsonOrThrow(send(b.build()), errorCode);
    }

    /** POST a form, read a JSON object; non-2xx answers become NineException with the server's error. */
    public Map<String, Object> postForm(String url, Map<String, String> form, Map<String, String> headers, String errorCode) {
        HttpRequest.Builder b = HttpRequest.builder()
                .method("POST")
                .url(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .body(Codec.formEncode(form));
        if (headers != null) b.headers(headers);
        return jsonOrThrow(send(b.build()), errorCode);
    }

    /** The JSON object of a 2xx response, or a NineException carrying the server's error. */
    public static Map<String, Object> jsonOrThrow(HttpResponse response, String errorCode) {
        if (!response.isSuccessful()) throw errorFrom(response, errorCode);
        String text = response.bodyText();
        if (text.trim().isEmpty()) return new LinkedHashMap<>();
        try {
            return Json.parseObject(text);
        } catch (NineException e) {
            throw new NineException(errorCode, "the response is not a JSON object (HTTP " + response.status() + ")", response.status());
        }
    }

    /** The server's {@code {error, error_description}}, or the fallback code with the HTTP status. */
    public static NineException errorFrom(HttpResponse response, String fallbackCode) {
        String error = null;
        String description = null;
        try {
            Map<String, Object> body = Json.parseObject(response.bodyText());
            error = Json.string(body, "error");
            description = Json.string(body, "error_description");
        } catch (NineException ignored) {
            // not JSON
        }
        if (response.status() >= 300 && response.status() < 400) {
            return new NineException(fallbackCode, "unexpected redirect (HTTP " + response.status() + "); redirects are never followed", response.status());
        }
        if (error == null || error.isEmpty()) error = fallbackCode;
        if (description == null || description.isEmpty()) description = "HTTP " + response.status();
        return new NineException(error, description, response.status());
    }

    private static String hostOf(String url) {
        try {
            return new java.net.URI(url).getHost();
        } catch (Exception e) {
            return "the server";
        }
    }

    // ---- discovery ----

    /** The discovery document, cached for an hour. Its {@code issuer} must be ours. */
    public Discovery discovery() {
        Discovery hit = discovery;
        Instant at = discoveryFetchedAt;
        if (hit != null && at != null && clock.instant().isBefore(at.plus(DISCOVERY_TTL))) return hit;
        synchronized (discoveryLock) {
            hit = discovery;
            at = discoveryFetchedAt;
            if (hit != null && at != null && clock.instant().isBefore(at.plus(DISCOVERY_TTL))) return hit;
            Map<String, Object> raw = getJson(issuer + "/.well-known/openid-configuration", null, "discovery_failed");
            Discovery fetched = new Discovery(raw);
            if (fetched.issuer() == null || !Issuers.same(fetched.issuer(), issuer)) {
                throw new NineException("invalid_issuer", "the discovery document is for " + fetched.issuer() + ", not " + issuer);
            }
            if (fetched.tokenEndpoint() == null || fetched.jwksUri() == null) {
                throw new NineException("discovery_failed", "incomplete discovery document");
            }
            discovery = fetched;
            discoveryFetchedAt = clock.instant();
            return fetched;
        }
    }

    /** An endpoint from discovery, or {@code issuer + fallbackPath} when the document has none. */
    public String endpoint(String value, String fallbackPath) {
        return value != null && !value.isEmpty() ? value : issuer + fallbackPath;
    }

    // ---- JWKS ----

    /** The JWK with this {@code kid}, or null (after at most one refetch, then throttled). */
    public Map<String, Object> signingKey(String kid) {
        Map<String, Object> key = find(currentKeys(false), kid);
        if (key != null) return key;
        String missKey = String.valueOf(kid);
        Instant missedAt = missingKids.get(missKey);
        Instant now = clock.instant();
        if (missedAt != null && now.isBefore(missedAt.plus(MISS_THROTTLE))) return null;
        key = find(currentKeys(true), kid);
        if (key == null) {
            if (missingKids.size() > 1000) missingKids.clear();
            missingKids.put(missKey, clock.instant());
        }
        return key;
    }

    private static Map<String, Object> find(List<Map<String, Object>> keys, String kid) {
        for (Map<String, Object> key : keys) {
            Object k = key.get("kid");
            if (kid == null ? k == null : kid.equals(k)) return key;
        }
        return null;
    }

    private List<Map<String, Object>> currentKeys(boolean force) {
        List<Map<String, Object>> hit = keys;
        Instant at = keysFetchedAt;
        long seen = keysGeneration;
        if (!force && hit != null && at != null && clock.instant().isBefore(at.plus(JWKS_TTL))) return hit;
        synchronized (jwksLock) {
            // Another thread fetched while we waited: use its keys.
            if (keys != null && keysGeneration != seen) return keys;
            if (!force && keys != null && keysFetchedAt != null && clock.instant().isBefore(keysFetchedAt.plus(JWKS_TTL))) return keys;
            Map<String, Object> body = getJson(discovery().jwksUri(), null, "jwks_unavailable");
            Object list = body.get("keys");
            if (!(list instanceof List)) throw new NineException("jwks_unavailable", "the JWKS has no keys array");
            List<Map<String, Object>> parsed = new ArrayList<>();
            for (Object item : (List<?>) list) {
                if (item instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> jwk = Json.freezeObject((Map<String, Object>) item);
                    parsed.add(jwk);
                }
            }
            keys = Collections.unmodifiableList(parsed);
            keysFetchedAt = clock.instant();
            keysGeneration = seen + 1;
            return keys;
        }
    }
}
