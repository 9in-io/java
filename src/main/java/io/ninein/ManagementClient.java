package io.ninein;

import io.ninein.http.HttpRequest;
import io.ninein.http.HttpResponse;
import io.ninein.http.HttpTransport;
import io.ninein.http.JavaHttpClientTransport;
import io.ninein.internal.Codec;
import io.ninein.internal.Env;
import io.ninein.internal.Issuers;
import io.ninein.internal.Json;
import io.ninein.internal.Tenant;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Management API ({@code /api/v1}): users and sessions of one tenant environment, with a
 * client-credentials token of a confidential application that was given management scopes. Each
 * call asks for only the scope it needs ({@code management:users:read},
 * {@code management:users:write} or {@code management:sessions:write}); tokens are cached until
 * shortly before they expire.
 *
 * <p>Wire data goes in and comes out as 9in's snake_case JSON ({@code Map<String, Object>}),
 * unchanged. Errors are {@link NineException}s with the server's {@code error},
 * {@code error_description} and HTTP status.
 *
 * <pre>{@code
 * ManagementClient nine = ManagementClient.fromEnv();   // NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET
 * Map<String, Object> user = nine.createUser(Map.of("email", "jane@acme.com", "name", "Jane"));
 * nine.blockUser((String) user.get("id"));
 * }</pre>
 *
 * <p>Thread-safe; build one and share it. Server-side only (never ship a client secret in an app).
 */
public final class ManagementClient {
    private static final String READ = "management:users:read";
    private static final String WRITE = "management:users:write";
    private static final String SESSIONS = "management:sessions:write";

    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String scopeOverride;
    private final Clock clock;
    private final Tenant tenant;
    private final Map<String, CachedToken> tokens = new ConcurrentHashMap<>();

    private static final class CachedToken {
        final String value;
        final Instant expiresAt;

        CachedToken(String value, Instant expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
    }

    private ManagementClient(Builder b) {
        boolean insecure = b.allowInsecureIssuer || Issuers.insecureAllowedByEnv();
        this.issuer = Issuers.normalize(b.issuer, insecure);
        if (b.clientId == null || b.clientId.isEmpty() || b.clientSecret == null || b.clientSecret.isEmpty()) {
            throw new NineException("invalid_options", "the Management API needs clientId and clientSecret of a confidential application");
        }
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.scopeOverride = b.scope;
        this.clock = b.clock == null ? Clock.systemUTC() : b.clock;
        HttpTransport transport = b.transport == null ? new JavaHttpClientTransport() : b.transport;
        this.tenant = new Tenant(issuer, transport, clock);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * A client from the environment: {@code NINE_ISSUER}, and {@code NINE_MANAGEMENT_CLIENT_ID} /
     * {@code NINE_MANAGEMENT_CLIENT_SECRET} or else {@code NINE_CLIENT_ID} / {@code NINE_CLIENT_SECRET}.
     */
    public static ManagementClient fromEnv() {
        return builder().env(System.getenv()).build();
    }

    /** Lists or searches users: {@code {"users": [...], "next_cursor": "..." | null, "total": n}}. */
    public Map<String, Object> listUsers(String query, String cursor, Integer limit) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query != null && !query.isEmpty()) params.put("q", query);
        if (cursor != null && !cursor.isEmpty()) params.put("cursor", cursor);
        if (limit != null) params.put("limit", Integer.toString(limit));
        return request("GET", Codec.appendQuery("/users", params), null);
    }

    /** The first page of users. */
    public Map<String, Object> listUsers() {
        return listUsers(null, null, null);
    }

    /** Every user matching {@code query} (null for all), following the cursor page by page. */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listAllUsers(String query) {
        List<Map<String, Object>> all = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        String cursor = null;
        do {
            if (cursor != null && !seen.add(cursor)) throw new NineException("request_failed", "the user list repeated a cursor");
            Map<String, Object> page = listUsers(query, cursor, 100);
            Object users = page.get("users");
            if (users instanceof List) for (Object u : (List<Object>) users) if (u instanceof Map) all.add((Map<String, Object>) u);
            cursor = Json.string(page, "next_cursor");
        } while (cursor != null && !cursor.isEmpty());
        return all;
    }

    /** The user with identities, sessions and two-factor state: {@code {user, identities, sessions, has_password, mfa}}. */
    public Map<String, Object> getUser(String userId) {
        return request("GET", "/users/" + Codec.urlEncode(require(userId, "userId")), null);
    }

    /**
     * Looks a user up by {@code email}, {@code phone_number} (E.164) or {@code username}; null when
     * there is none.
     */
    public Map<String, Object> findUser(String field, String value) {
        if (!"email".equals(field) && !"phone_number".equals(field) && !"username".equals(field)) {
            throw new IllegalArgumentException("field must be email, phone_number or username");
        }
        try {
            return Json.object(request("GET", "/users/lookup?" + Codec.urlEncode(field) + "=" + Codec.urlEncode(require(value, "value")), null), "user");
        } catch (NineException e) {
            if (e.status() != null && e.status() == 404) return null;
            throw e;
        }
    }

    public Map<String, Object> findUserByEmail(String email) {
        return findUser("email", email);
    }

    /** Creates a user from snake_case fields ({@code email}, {@code password}, {@code name}, {@code metadata} ...); returns it. */
    public Map<String, Object> createUser(Map<String, ?> user) {
        return Json.object(request("POST", "/users", user), "user");
    }

    /**
     * Imports up to 500 users per call (password hashes, social identities and original dates may
     * come along). Returns {@code {"results": [...]}}, one result per record, in order.
     *
     * @param onConflict {@code skip} (default) or {@code update}, or null
     * @param source recorded on the import events, or null
     */
    public Map<String, Object> importUsers(List<? extends Map<String, ?>> users, String onConflict, String source) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("users", users);
        if (onConflict != null && !onConflict.isEmpty()) body.put("on_conflict", onConflict);
        if (source != null && !source.isEmpty()) body.put("source", source);
        return request("POST", "/users/import", body);
    }

    public Map<String, Object> importUsers(List<? extends Map<String, ?>> users) {
        return importUsers(users, null, null);
    }

    /** Changes only the fields you send ({@code metadata} is replaced as a whole); returns the user. */
    public Map<String, Object> updateUser(String userId, Map<String, ?> changes) {
        return Json.object(request("PATCH", "/users/" + Codec.urlEncode(require(userId, "userId")), changes), "user");
    }

    public void deleteUser(String userId) {
        request("DELETE", "/users/" + Codec.urlEncode(require(userId, "userId")), null);
    }

    /** Blocks the user (sign-in refused, sessions ended); returns the user. */
    public Map<String, Object> blockUser(String userId) {
        return updateUser(userId, Collections.singletonMap("blocked", true));
    }

    public Map<String, Object> unblockUser(String userId) {
        return updateUser(userId, Collections.singletonMap("blocked", false));
    }

    /**
     * A single-use URL that signs the user in: {@code {"url": ..., "expires_at": ...}}.
     *
     * @param returnTo a registered redirect URL of one of your applications or a path on the login domain, or null
     * @param ttlSeconds how long the link works, or null for the default
     */
    public Map<String, Object> createLoginLink(String userId, String returnTo, Integer ttlSeconds) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (returnTo != null && !returnTo.isEmpty()) body.put("return_to", returnTo);
        if (ttlSeconds != null) body.put("ttl_seconds", ttlSeconds);
        return request("POST", "/users/" + Codec.urlEncode(require(userId, "userId")) + "/login-link", body);
    }

    public Map<String, Object> createLoginLink(String userId) {
        return createLoginLink(userId, null, null);
    }

    /** The user's active sessions, most recently used first. */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listUserSessions(String userId) {
        Object sessions = request("GET", "/users/" + Codec.urlEncode(require(userId, "userId")) + "/sessions", null).get("sessions");
        List<Map<String, Object>> out = new ArrayList<>();
        if (sessions instanceof List) for (Object s : (List<Object>) sessions) if (s instanceof Map) out.add((Map<String, Object>) s);
        return out;
    }

    /** Signs the user out everywhere; returns how many sessions ended. */
    public int revokeUserSessions(String userId) {
        Long revoked = Json.number(request("DELETE", "/users/" + Codec.urlEncode(require(userId, "userId")) + "/sessions", null), "revoked");
        return revoked == null ? 0 : revoked.intValue();
    }

    /** Ends one session (its {@code sid}) and every token issued under it. */
    public void revokeSession(String sid) {
        request("DELETE", "/sessions/" + Codec.urlEncode(require(sid, "sid")), null);
    }

    // ---- internals ----

    private Map<String, Object> request(String method, String path, Object body) {
        String scope = scopeFor(method, path);
        HttpRequest.Builder b = HttpRequest.builder()
                .method(method)
                .url(issuer + "/api/v1" + path)
                .header("Authorization", "Bearer " + accessToken(scope))
                .header("Accept", "application/json");
        if (body != null) b.header("Content-Type", "application/json").body(Json.write(body));
        HttpResponse response = tenant.send(b.build());
        if (response.status() == 401) tokens.remove(scope); // revoked or rotated credentials: get a new token next time
        if (response.status() == 204) return new LinkedHashMap<>();
        return Tenant.jsonOrThrow(response, "request_failed");
    }

    private String scopeFor(String method, String path) {
        if (scopeOverride != null) return scopeOverride;
        if (method.equals("GET")) return READ;
        return path.contains("/sessions") ? SESSIONS : WRITE;
    }

    private String accessToken(String scope) {
        CachedToken cached = tokens.get(scope);
        Instant now = clock.instant();
        if (cached != null && now.plusSeconds(30).isBefore(cached.expiresAt)) return cached.value;
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        form.put("scope", scope);
        Map<String, String> headers = new LinkedHashMap<>();
        String credentials = Codec.urlEncode(clientId) + ":" + Codec.urlEncode(clientSecret);
        headers.put("Authorization", "Basic " + java.util.Base64.getEncoder().encodeToString(Codec.utf8(credentials)));
        Map<String, Object> json = tenant.postForm(tenant.discovery().tokenEndpoint(), form, headers, "request_failed");
        String token = Json.string(json, "access_token");
        if (token == null || token.isEmpty()) throw new NineException("request_failed", "no access_token in the token response");
        Long expiresIn = Json.number(json, "expires_in");
        tokens.put(scope, new CachedToken(token, now.plusSeconds(expiresIn == null ? 300 : expiresIn)));
        return token;
    }

    private static String require(String value, String name) {
        if (value == null || value.isEmpty()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    @Override
    public String toString() {
        return "ManagementClient{issuer=" + issuer + ", clientId=" + clientId + "}";
    }

    /** Builds a {@link ManagementClient}; issuer, client id and secret are required. */
    public static final class Builder {
        private String issuer;
        private String clientId;
        private String clientSecret;
        private String scope;
        private HttpTransport transport;
        private Clock clock;
        private boolean allowInsecureIssuer;

        private Builder() {}

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /** Asks every call for these scopes instead of the one it needs (space-separated). */
        public Builder scope(String scope) {
            this.scope = scope == null || scope.isEmpty() ? null : scope;
            return this;
        }

        /** Default {@link JavaHttpClientTransport} (it can send PATCH; HttpURLConnection on the JDK can't). */
        public Builder transport(HttpTransport transport) {
            this.transport = transport;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public Builder allowInsecureIssuer(boolean allow) {
            this.allowInsecureIssuer = allow;
            return this;
        }

        /** Applies {@code NINE_ISSUER} and the management (or app) client credentials from an environment map. */
        public Builder env(Map<String, String> env) {
            String v;
            if ((v = Env.get(env, "ISSUER")) != null) issuer = v;
            if ((v = Env.get(env, "CLIENT_ID")) != null) clientId = v;
            if ((v = Env.get(env, "CLIENT_SECRET")) != null) clientSecret = v;
            if ((v = Env.get(env, "MANAGEMENT_CLIENT_ID")) != null) clientId = v;
            if ((v = Env.get(env, "MANAGEMENT_CLIENT_SECRET")) != null) clientSecret = v;
            if (Env.flag(Env.get(env, "ALLOW_INSECURE_ISSUER"))) allowInsecureIssuer = true;
            return this;
        }

        public ManagementClient build() {
            return new ManagementClient(this);
        }
    }
}
