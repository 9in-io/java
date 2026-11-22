package io.ninein.testing;

import io.ninein.http.HttpRequest;
import io.ninein.http.HttpResponse;
import io.ninein.http.HttpTransport;
import io.ninein.internal.Codec;
import io.ninein.internal.Json;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * A fake 9in tenant behind the {@link HttpTransport} seam: discovery, JWKS and whatever routes a
 * test adds. Records every request.
 */
public final class FakeNine implements HttpTransport {
    public final String issuer;
    public final Map<String, Object> discovery = new ConcurrentHashMap<>();
    public final List<Map<String, Object>> jwks = new CopyOnWriteArrayList<>();
    public final List<HttpRequest> requests = new CopyOnWriteArrayList<>();
    private final Map<String, Function<HttpRequest, HttpResponse>> routes = new ConcurrentHashMap<>();

    public FakeNine() {
        this("https://acme.9in.io");
    }

    public FakeNine(String issuer) {
        this.issuer = issuer;
        discovery.put("issuer", issuer);
        discovery.put("authorization_endpoint", issuer + "/oauth/authorize");
        discovery.put("token_endpoint", issuer + "/oauth/token");
        discovery.put("userinfo_endpoint", issuer + "/oauth/userinfo");
        discovery.put("jwks_uri", issuer + "/.well-known/jwks.json");
        discovery.put("revocation_endpoint", issuer + "/oauth/revoke");
        discovery.put("introspection_endpoint", issuer + "/oauth/introspect");
        discovery.put("end_session_endpoint", issuer + "/oauth/logout");
        discovery.put("device_authorization_endpoint", issuer + "/oauth/device/authorize");
        discovery.put("authorization_response_iss_parameter_supported", true);
        on("GET", "/.well-known/openid-configuration", r -> json(200, new LinkedHashMap<>(discovery)));
        on("GET", "/.well-known/jwks.json", r -> {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("keys", new ArrayList<>(jwks));
            return json(200, body);
        });
        for (String alg : TestKeys.ASYMMETRIC) {
            if (alg.equals("EdDSA") && !TestKeys.ed25519Available()) continue;
            jwks.add(TestKeys.of(alg).jwk);
        }
    }

    /** Adds or replaces a route ({@code path} relative to the issuer, without query). */
    public FakeNine on(String method, String path, Function<HttpRequest, HttpResponse> handler) {
        routes.put(method + " " + path, handler);
        return this;
    }

    @Override
    public HttpResponse send(HttpRequest request) throws IOException {
        requests.add(request);
        URI uri = URI.create(request.url());
        String origin = uri.getScheme() + "://" + uri.getRawAuthority();
        String base = URI.create(issuer).getRawPath() == null ? "" : URI.create(issuer).getRawPath();
        if (!issuer.startsWith(origin)) return json(404, error("not_found", "unknown host"));
        String path = uri.getRawPath().substring(base.length());
        Function<HttpRequest, HttpResponse> handler = routes.get(request.method() + " " + path);
        if (handler == null) return json(404, error("not_found", request.method() + " " + path));
        return handler.apply(request);
    }

    /** How many requests went to a path. */
    public int count(String path) {
        int n = 0;
        for (HttpRequest r : requests) if (URI.create(r.url()).getRawPath().endsWith(path)) n++;
        return n;
    }

    /** The last request to a path, or null. */
    public HttpRequest last(String path) {
        HttpRequest found = null;
        for (HttpRequest r : requests) if (URI.create(r.url()).getRawPath().endsWith(path)) found = r;
        return found;
    }

    /** The form fields of a request body. */
    public static Map<String, String> form(HttpRequest r) {
        return Codec.parseQuery(r.bodyText());
    }

    public static HttpResponse json(int status, Object body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        return HttpResponse.of(status, headers, body == null ? "" : Json.write(body));
    }

    public static Map<String, Object> error(String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null) body.put("error_description", description);
        return body;
    }

    public static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    public static List<Object> list(Object... items) {
        List<Object> l = new ArrayList<>();
        Collections.addAll(l, items);
        return l;
    }
}
