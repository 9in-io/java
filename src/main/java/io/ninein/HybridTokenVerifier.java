package io.ninein;

import io.ninein.http.HttpTransport;
import io.ninein.http.UrlConnectionTransport;
import io.ninein.internal.Codec;
import io.ninein.internal.Env;
import io.ninein.internal.Json;
import io.ninein.internal.Tenant;
import io.ninein.internal.TokenChecks;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * Access-token verification with a choice between speed and revocation:
 *
 * <ul>
 *   <li>{@link Mode#HYBRID} (default with client credentials): the local check
 *       ({@link TokenVerifier}), then one introspection per token. The answer is cached (at most
 *       {@code cacheTtl}, default 5 minutes, never past the token's expiry; refusals until it
 *       expires) and dropped when a {@code token.revoked}, {@code session.revoked} or user webhook
 *       arrives: pass the events to {@link #handleEvent}.
 *   <li>{@link Mode#LOCAL} (default without client credentials): signature and claims only.
 *       Fastest; a revoked token works until it expires.
 *   <li>{@link Mode#INTROSPECT}: ask 9in on every call. Always current; one request per call.
 * </ul>
 *
 * <p>Opaque tokens ({@code 9in_at_...}) are always introspected (cached in hybrid mode; a refusal
 * for a minute). Concurrent verifications of the same token share one introspection.
 *
 * <pre>{@code
 * HybridTokenVerifier verifier = HybridTokenVerifier.builder()
 *     .issuer("https://acme.9in.io")
 *     .audience("https://api.acme.com")
 *     .clientId(System.getenv("NINE_CLIENT_ID"))          // a confidential application,
 *     .clientSecret(System.getenv("NINE_CLIENT_SECRET"))  // used for introspection
 *     .build();
 * AccessTokenClaims claims = verifier.verify(authorizationHeader, "orders:read");
 *
 * // in your webhook endpoint
 * verifier.handleEvent(Webhooks.verify(secret, body, signature, path));
 * }</pre>
 *
 * <p>Answers live in memory by default. With several servers, pass a shared {@link Cache}
 * (Redis...) so that one server's webhook evicts answers for all of them: eviction then writes a
 * marker per token id, session or user, which every server checks on a cache hit. Thread-safe.
 */
public final class HybridTokenVerifier implements AccessTokenVerifier {
    /** How tokens are checked. */
    public enum Mode {
        LOCAL, HYBRID, INTROSPECT;

        /** {@code local}, {@code hybrid} or {@code introspect} (any case). */
        public static Mode parse(String value) {
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (RuntimeException e) {
                throw new NineException("invalid_options", "unknown verification mode " + value + " (local, hybrid or introspect)");
            }
        }
    }

    /** Opaque access tokens start with this. */
    public static final String OPAQUE_PREFIX = "9in_at_";
    private static final Set<String> USER_EVENTS = new HashSet<>(Arrays.asList(
            "user.sessions_revoked", "user.deleted", "user.updated", "user.password_changed"));
    private static final Duration REFUSAL_WITHOUT_EXPIRY = Duration.ofSeconds(60);
    private static final String ANSWER_PREFIX = "nine:token:";
    private static final String MARKER_PREFIX = "nine:token-revoked:";

    private final Mode mode;
    private final TokenVerifier local;
    private final String clientId;
    private final String clientSecret;
    private final Duration ttl;
    private final Clock clock;
    private final Tenant tenant;
    private final Cache shared;
    private final Answers memory;
    private final ConcurrentHashMap<String, CompletableFuture<Map<String, Object>>> inflight = new ConcurrentHashMap<>();

    private HybridTokenVerifier(Builder b) {
        this.clientId = b.clientId == null || b.clientId.isEmpty() ? null : b.clientId;
        this.clientSecret = b.clientSecret == null || b.clientSecret.isEmpty() ? null : b.clientSecret;
        this.mode = b.mode != null ? b.mode : (clientId != null && clientSecret != null ? Mode.HYBRID : Mode.LOCAL);
        if (mode != Mode.LOCAL && (clientId == null || clientSecret == null)) {
            throw new NineException("invalid_options", mode.name().toLowerCase(Locale.ROOT)
                    + " mode needs clientId and clientSecret (a confidential application) for introspection");
        }
        this.local = b.local.build();
        this.clock = local.clock();
        this.tenant = local.tenant();
        this.ttl = b.cacheTtl == null ? Duration.ofMinutes(5) : b.cacheTtl;
        this.shared = b.cache;
        this.memory = shared == null ? new Answers(b.cacheSize) : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * A verifier from the environment: {@code NINE_ISSUER}, {@code NINE_API_AUDIENCE} (or
     * {@code NINE_AUDIENCE}), {@code NINE_CLIENT_ID} / {@code NINE_CLIENT_SECRET} (hybrid by default
     * when both are set), {@code NINE_API_SECRET}, {@code NINE_TOKEN_MODE}, {@code NINE_TOKEN_CACHE_TTL}
     * (seconds) and {@code NINE_ALLOW_INSECURE_ISSUER}.
     */
    public static HybridTokenVerifier fromEnv() {
        return builder().env(System.getenv()).build();
    }

    public Mode mode() {
        return mode;
    }

    /** The local verifier (same issuer, audience, secret and key cache). */
    public TokenVerifier localVerifier() {
        return local;
    }

    @Override
    public AccessTokenClaims verify(String tokenOrAuthorizationHeader, String... requiredScopes) {
        String token = TokenVerifier.stripBearer(tokenOrAuthorizationHeader);
        if (token == null || token.isEmpty()) throw new InvalidTokenException("missing token");
        boolean opaque = token.startsWith(OPAQUE_PREFIX);
        if (opaque && mode == Mode.LOCAL) throw new InvalidTokenException("opaque tokens need hybrid or introspect mode");
        AccessTokenClaims localClaims = opaque ? null : local.verify(token, requiredScopes);
        if (mode == Mode.LOCAL) return localClaims;
        Map<String, Object> live = lookup(token, localClaims == null ? null : localClaims.asMap());
        if (live == null) throw new InvalidTokenException("token revoked");
        if (localClaims != null) return localClaims;
        local.checkClaims(live, requiredScopes);
        return new AccessTokenClaims(live);
    }

    /**
     * Drops cached answers a webhook event makes stale: {@code token.revoked} (access tokens) by
     * {@code jti}, {@code session.revoked} by {@code sid}, and {@code user.sessions_revoked},
     * {@code user.deleted}, {@code user.updated}, {@code user.password_changed} by user. Subscribe
     * your webhook endpoint to these events. Returns true when the event was one of them.
     */
    public boolean handleEvent(Map<String, ?> event) {
        if (event == null) return false;
        Object type = event.get("event_type");
        Object rawData = event.get("data");
        @SuppressWarnings("unchecked")
        Map<String, Object> data = rawData instanceof Map ? (Map<String, Object>) rawData : Collections.<String, Object>emptyMap();
        Map<String, Object> user = Json.object(data, "user");
        String userId = Json.string(user, "id");
        String claim;
        String value;
        if ("token.revoked".equals(type) && "access_token".equals(data.get("token_type")) && notEmpty(Json.string(data, "jti"))) {
            claim = "jti";
            value = Json.string(data, "jti");
        } else if ("session.revoked".equals(type) && notEmpty(Json.string(data, "sid"))) {
            claim = "sid";
            value = Json.string(data, "sid");
        } else if (type instanceof String && USER_EVENTS.contains(type) && notEmpty(userId)) {
            claim = "sub";
            value = userId;
        } else {
            return false;
        }
        if (memory != null) {
            memory.evict(claim, value);
        } else {
            shared.set(MARKER_PREFIX + claim + ":" + value, Long.toString(clock.millis()), ttl.plusSeconds(60));
        }
        return true;
    }

    /** As {@link #handleEvent(Map)}, for a verified webhook event. */
    public boolean handleEvent(WebhookEvent event) {
        return event != null && handleEvent(event.asMap());
    }

    /** Forgets every answer cached in memory (a shared cache is left alone). */
    public void clear() {
        if (memory != null) memory.clear();
    }

    // ---- internals ----

    /** The live claims (the local ones for a JWT, once 9in confirms it is active), or null when refused. */
    private Map<String, Object> lookup(String token, Map<String, Object> localClaims) {
        String key = Codec.hex(Codec.sha256(Codec.utf8(token)));
        Instant now = clock.instant();
        if (mode == Mode.HYBRID) {
            Answer hit = memory != null ? memory.get(key, now) : readShared(key, now);
            if (hit != null) return hit.claims;
        }
        Map<String, Object> answer = introspectOnce(key, token);
        Map<String, Object> claims = answer != null && localClaims != null ? localClaims : answer;
        if (mode == Mode.HYBRID) {
            Double expSeconds = TokenChecks.numericDate(claims != null ? claims.get("exp") : localClaims != null ? localClaims.get("exp") : null);
            Instant expiry = expSeconds == null ? null : Instant.ofEpochMilli((long) (expSeconds * 1000));
            Instant until;
            if (claims != null) {
                Instant max = now.plus(ttl);
                until = expiry == null || expiry.isAfter(max) ? max : expiry;
            } else {
                until = expiry != null ? expiry : now.plus(REFUSAL_WITHOUT_EXPIRY); // a revoked token never comes back
            }
            if (until.isAfter(now)) {
                Answer entry = new Answer(claims, until, now);
                if (memory != null) memory.put(key, entry);
                else writeShared(key, entry, now);
            }
        }
        return claims;
    }

    private Map<String, Object> introspectOnce(String key, String token) {
        CompletableFuture<Map<String, Object>> mine = new CompletableFuture<>();
        CompletableFuture<Map<String, Object>> running = inflight.putIfAbsent(key, mine);
        if (running != null) {
            try {
                return running.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new NineException("interrupted", "interrupted while waiting for introspection");
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException) throw (RuntimeException) cause;
                throw new NineException("introspection_failed", "introspection failed", null, cause);
            }
        }
        try {
            Map<String, Object> answer = introspect(token);
            mine.complete(answer);
            return answer;
        } catch (RuntimeException e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inflight.remove(key, mine);
        }
    }

    private Map<String, Object> introspect(String token) {
        String endpoint = tenant.endpoint(tenant.discovery().introspectionEndpoint(), "/oauth/introspect");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        Map<String, String> headers = new LinkedHashMap<>();
        String credentials = Codec.urlEncode(clientId) + ":" + Codec.urlEncode(clientSecret);
        headers.put("Authorization", "Basic " + java.util.Base64.getEncoder().encodeToString(Codec.utf8(credentials)));
        Map<String, Object> body;
        try {
            body = tenant.postForm(endpoint, form, headers, "introspection_failed");
        } catch (NineException e) {
            // Not the token's fault (wrong client credentials, 9in unreachable): never a 401 for the caller.
            throw new NineException("introspection_failed", "introspection failed: " + e.getMessage(), 503, e);
        }
        if (!Boolean.TRUE.equals(body.get("active")) || "refresh_token".equals(body.get("token_type"))) return null;
        return body;
    }

    private Answer readShared(String key, Instant now) {
        String raw = shared.get(ANSWER_PREFIX + key);
        if (raw == null) return null;
        Map<String, Object> stored;
        try {
            stored = Json.parseObject(raw);
        } catch (NineException e) {
            return null;
        }
        Long until = Json.number(stored, "until");
        Long at = Json.number(stored, "at");
        if (until == null || at == null || until <= now.toEpochMilli()) return null;
        Map<String, Object> claims = Json.object(stored, "claims");
        if (claims != null) {
            for (String claim : new String[] {"jti", "sid", "sub"}) {
                String value = Json.string(claims, claim);
                if (value == null) continue;
                String marker = shared.get(MARKER_PREFIX + claim + ":" + value);
                if (marker != null) {
                    try {
                        if (Long.parseLong(marker) >= at) return null; // evicted after this answer was cached
                    } catch (NumberFormatException ignored) {
                        return null;
                    }
                }
            }
        }
        return new Answer(claims, Instant.ofEpochMilli(until), Instant.ofEpochMilli(at));
    }

    private void writeShared(String key, Answer entry, Instant now) {
        Map<String, Object> stored = new LinkedHashMap<>();
        stored.put("claims", entry.claims);
        stored.put("until", entry.until.toEpochMilli());
        stored.put("at", entry.at.toEpochMilli());
        Duration life = Duration.between(now, entry.until);
        shared.set(ANSWER_PREFIX + key, Json.write(stored), life.isNegative() || life.isZero() ? Duration.ofSeconds(1) : life);
    }

    private static boolean notEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    private static final class Answer {
        final Map<String, Object> claims; // null: refused
        final Instant until;
        final Instant at;

        Answer(Map<String, Object> claims, Instant until, Instant at) {
            this.claims = claims;
            this.until = until;
            this.at = at;
        }
    }

    /** In-memory answers, least recently used first out. */
    private static final class Answers {
        private final int size;
        private final LinkedHashMap<String, Answer> map = new LinkedHashMap<>(64, 0.75f, true);

        Answers(int size) {
            this.size = size;
        }

        synchronized Answer get(String key, Instant now) {
            Answer a = map.get(key);
            if (a == null) return null;
            if (!a.until.isAfter(now)) {
                map.remove(key);
                return null;
            }
            return a;
        }

        synchronized void put(String key, Answer answer) {
            map.put(key, answer);
            Iterator<String> it = map.keySet().iterator();
            while (map.size() > size && it.hasNext()) {
                it.next();
                it.remove();
            }
        }

        synchronized int evict(String claim, String value) {
            int n = 0;
            for (Iterator<Answer> it = map.values().iterator(); it.hasNext(); ) {
                Answer a = it.next();
                if (a.claims != null && value.equals(a.claims.get(claim))) {
                    it.remove();
                    n++;
                }
            }
            return n;
        }

        synchronized void clear() {
            map.clear();
        }
    }

    /** Builds a {@link HybridTokenVerifier}; {@code issuer} is required, and client credentials for hybrid/introspect. */
    public static final class Builder {
        private final TokenVerifier.Builder local = TokenVerifier.builder();
        private String clientId;
        private String clientSecret;
        private Mode mode;
        private Cache cache;
        private Duration cacheTtl;
        private int cacheSize = 10_000;

        private Builder() {}

        public Builder issuer(String issuer) {
            local.issuer(issuer);
            return this;
        }

        /** The API identifier(s) a token must be issued for. */
        public Builder audience(String... audiences) {
            local.audience(audiences);
            return this;
        }

        /** A confidential application's client id, used for introspection. */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /** Default: hybrid with client credentials, else local. */
        public Builder mode(Mode mode) {
            this.mode = mode;
            return this;
        }

        /** A cache shared by your servers (default: in memory, this instance only). */
        public Builder cache(Cache cache) {
            this.cache = cache;
            return this;
        }

        /** Longest time a hybrid answer is trusted without hearing from 9in (default 5 minutes). */
        public Builder cacheTtl(Duration ttl) {
            this.cacheTtl = ttl;
            return this;
        }

        /** Most answers kept in memory (default 10 000; least recently used go first). */
        public Builder cacheSize(int size) {
            if (size < 1) throw new IllegalArgumentException("cacheSize must be positive");
            this.cacheSize = size;
            return this;
        }

        /** The shared secret of an HMAC key your API uses. */
        public Builder secret(String secret) {
            local.secret(secret);
            return this;
        }

        public Builder transport(HttpTransport transport) {
            local.transport(transport == null ? new UrlConnectionTransport() : transport);
            return this;
        }

        public Builder clock(Clock clock) {
            local.clock(clock);
            return this;
        }

        public Builder leeway(Duration leeway) {
            local.leeway(leeway);
            return this;
        }

        public Builder allowInsecureIssuer(boolean allow) {
            local.allowInsecureIssuer(allow);
            return this;
        }

        /** Applies the {@code NINE_*} variables listed on {@link HybridTokenVerifier#fromEnv()}. */
        public Builder env(Map<String, String> env) {
            local.env(env);
            String v;
            if ((v = Env.get(env, "CLIENT_ID")) != null) clientId = v;
            if ((v = Env.get(env, "CLIENT_SECRET")) != null) clientSecret = v;
            String m = Env.get(env, "TOKEN_MODE") != null ? Env.get(env, "TOKEN_MODE") : Env.get(env, "TOKEN_VERIFICATION");
            if (m != null) mode = Mode.parse(m);
            if ((v = Env.get(env, "TOKEN_CACHE_TTL")) != null) {
                try {
                    cacheTtl = Duration.ofSeconds(Long.parseLong(v));
                } catch (NumberFormatException e) {
                    throw new NineException("invalid_options", "NINE_TOKEN_CACHE_TTL must be a number of seconds");
                }
            }
            return this;
        }

        public HybridTokenVerifier build() {
            return new HybridTokenVerifier(this);
        }
    }
}
