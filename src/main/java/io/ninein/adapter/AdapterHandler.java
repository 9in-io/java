package io.ninein.adapter;

import io.ninein.NineException;
import io.ninein.Signatures;
import io.ninein.internal.Env;
import io.ninein.internal.Json;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Framework-independent handler for 9in's adapter protocol v2 ("keep users in your own
 * database"). Mount it at your adapter base URL; it serves {@code <base>/authenticate},
 * {@code <base>/user} and {@code <base>/event}:
 *
 * <pre>{@code
 * AdapterHandler handler = new AdapterHandler(System.getenv("NINE_ADAPTER_SECRET"), new MyUserAdapter());
 * AdapterResponse response = handler.handle(method, path, headers, rawBody);
 * }</pre>
 *
 * <p>Requests must carry a valid {@code 9in-signature} (HMAC-SHA256 over timestamp, method, path
 * and raw body, 5-minute window, constant-time compare; several secrets during rotation). Every
 * response is signed over {@code <path>#<9in-request-id>} with the first secret, so 9in can reject
 * a response replayed from another request.
 *
 * <table>
 *   <caption>Routes and answers</caption>
 *   <tr><td>any non-POST</td><td>405</td></tr>
 *   <tr><td>bad or missing signature</td><td>401 {@code {"error":"invalid_signature"}} (unsigned)</td></tr>
 *   <tr><td>body not a JSON object</td><td>400 {@code invalid_json}</td></tr>
 *   <tr><td>{@code /authenticate}</td><td>200 {@code {user}}, 401 {@code invalid_credentials}, 403 {@code blocked}, 400 {@code invalid_request}</td></tr>
 *   <tr><td>{@code /user}</td><td>200 {@code {user}}, 404 {@code not_found}, 400 {@code invalid_request}</td></tr>
 *   <tr><td>{@code /event}</td><td>204, 400 {@code invalid_request}</td></tr>
 *   <tr><td>anything else</td><td>404 {@code not_found}</td></tr>
 * </table>
 */
public final class AdapterHandler {
    private final List<String> secrets;
    private final Adapter adapter;
    private final Duration tolerance;
    private final Clock clock;

    /** @param secret the adapter secret from the console (Connections, User database) */
    public AdapterHandler(String secret, Adapter adapter) {
        this(Collections.singletonList(secret), adapter, Signatures.DEFAULT_TOLERANCE, Clock.systemUTC());
    }

    /**
     * @param secrets one secret, or several during rotation (responses are signed with the first)
     * @param tolerance how far a request's timestamp may be from now (default 5 minutes)
     */
    public AdapterHandler(List<String> secrets, Adapter adapter, Duration tolerance, Clock clock) {
        List<String> clean = new ArrayList<>();
        if (secrets != null) for (String s : secrets) if (s != null && !s.isEmpty()) clean.add(s);
        if (clean.isEmpty()) throw new NineException("invalid_options", "an adapter secret is required");
        if (adapter == null) throw new NineException("invalid_options", "an adapter is required");
        this.secrets = Collections.unmodifiableList(clean);
        this.adapter = adapter;
        this.tolerance = tolerance == null ? Signatures.DEFAULT_TOLERANCE : tolerance;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * A handler with the secrets from the environment: {@code NINE_ADAPTER_SECRET} (comma-separated
     * for several) and {@code NINE_ADAPTER_SECRET_PREVIOUS} during rotation.
     */
    public static AdapterHandler fromEnv(Adapter adapter) {
        Map<String, String> env = System.getenv();
        List<String> secrets = new ArrayList<>();
        for (String key : new String[] {"ADAPTER_SECRET", "ADAPTER_SECRET_PREVIOUS"}) {
            String value = Env.get(env, key);
            if (value != null) for (String s : value.split(",")) if (!s.trim().isEmpty()) secrets.add(s.trim());
        }
        return new AdapterHandler(secrets, adapter, Signatures.DEFAULT_TOLERANCE, Clock.systemUTC());
    }

    /**
     * Handles one request.
     *
     * @param path the request path exactly as 9in called it (no query string), ending in
     *     {@code /authenticate}, {@code /user} or {@code /event}
     * @param headers request headers (names in any case)
     * @param body the raw request body
     */
    public AdapterResponse handle(String method, String path, Map<String, String> headers, byte[] body) {
        if (path == null || path.isEmpty()) throw new IllegalArgumentException("the request path is required");
        String signature = header(headers, Signatures.HEADER);
        String requestId = header(headers, Signatures.REQUEST_ID_HEADER);
        if (requestId == null) requestId = "";
        byte[] raw = body == null ? new byte[0] : body;

        if (method == null || !method.toUpperCase(Locale.ROOT).equals("POST")) {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("Allow", "POST");
            h.put("Content-Type", "text/plain; charset=utf-8");
            return new AdapterResponse(405, h, "Method not allowed".getBytes(StandardCharsets.UTF_8));
        }
        if (!Signatures.check(secrets, signature, "POST", path, raw, tolerance, clock).ok()) {
            return new AdapterResponse(401, Collections.singletonMap("Content-Type", "application/json"),
                    "{\"error\":\"invalid_signature\"}".getBytes(StandardCharsets.UTF_8));
        }

        Map<String, Object> input;
        String text = new String(raw, StandardCharsets.UTF_8);
        if (text.trim().isEmpty()) {
            input = new LinkedHashMap<>();
        } else {
            try {
                input = Json.parseObject(text);
            } catch (NineException e) {
                return respond(path, requestId, 400, error("invalid_json"));
            }
        }

        String route = path.substring(path.lastIndexOf('/') + 1);
        switch (route) {
            case "authenticate": {
                Identifier identifier = identifier(input.get("identifier"));
                Object password = input.get("password");
                if (identifier == null || !(password instanceof String)) return respond(path, requestId, 400, error("invalid_request"));
                AdapterUser user = adapter.authenticate(identifier, (String) password);
                if (user == null) return respond(path, requestId, 401, error("invalid_credentials"));
                if (user.isBlocked()) return respond(path, requestId, 403, error("blocked"));
                return respond(path, requestId, 200, Collections.<String, Object>singletonMap("user", user.toMap()));
            }
            case "user": {
                UserQuery query;
                Object id = input.get("id");
                if ((id instanceof String || id instanceof Number || id instanceof Boolean) && !id.toString().isEmpty()) {
                    query = UserQuery.byId(id instanceof Number ? numberText((Number) id) : id.toString());
                } else {
                    Identifier identifier = identifier(input.get("identifier"));
                    if (identifier == null) return respond(path, requestId, 400, error("invalid_request"));
                    query = UserQuery.byIdentifier(identifier);
                }
                AdapterUser user = adapter.findUser(query);
                if (user == null) return respond(path, requestId, 404, error("not_found"));
                return respond(path, requestId, 200, Collections.<String, Object>singletonMap("user", user.toMap()));
            }
            case "event": {
                if (!(input.get("event_type") instanceof String)) return respond(path, requestId, 400, error("invalid_request"));
                if (!(input.get("data") instanceof Map)) input.put("data", new LinkedHashMap<String, Object>());
                adapter.onEvent(Collections.unmodifiableMap(input));
                return respond(path, requestId, 204, null);
            }
            default:
                return respond(path, requestId, 404, error("not_found"));
        }
    }

    /** As {@link #handle(String, String, Map, byte[])} with a UTF-8 body. */
    public AdapterResponse handle(String method, String path, Map<String, String> headers, String body) {
        return handle(method, path, headers, body == null ? null : body.getBytes(StandardCharsets.UTF_8));
    }

    private AdapterResponse respond(String path, String requestId, int status, Map<String, Object> payload) {
        String text = payload == null ? "" : Json.write(payload);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(Signatures.HEADER, Signatures.sign(secrets.get(0), "POST", path + "#" + requestId, text, clock.millis() / 1000));
        if (!text.isEmpty()) headers.put("Content-Type", "application/json");
        return new AdapterResponse(status, headers, text.getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> error(String code) {
        return Collections.<String, Object>singletonMap("error", code);
    }

    private static Identifier identifier(Object value) {
        if (!(value instanceof Map)) return null;
        Map<?, ?> map = (Map<?, ?>) value;
        Object type = map.get("type");
        Object v = map.get("value");
        if (!(type instanceof String) || !(v instanceof String) || ((String) v).isEmpty()) return null;
        if (!Arrays.asList("email", "username", "phone").contains(type)) return null;
        return new Identifier((String) type, (String) v);
    }

    private static String numberText(Number n) {
        Long l = Json.asLong(n);
        return l != null ? Long.toString(l) : n.toString();
    }

    private static String header(Map<String, String> headers, String name) {
        if (headers == null) return null;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }
}
