package io.ninein;

import static io.ninein.testing.FakeNine.error;
import static io.ninein.testing.FakeNine.json;
import static io.ninein.testing.FakeNine.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.http.HttpRequest;
import io.ninein.http.HttpResponse;
import io.ninein.testing.FakeNine;
import io.ninein.testing.Jwts;
import io.ninein.testing.TestClock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HybridTokenVerifierTest {
    static final String API = "https://api.example.com";
    static final String OPAQUE = "9in_at_abcdefghijklmnop";

    FakeNine nine;
    TestClock clock;
    /** token -> introspection answer (null: inactive). */
    Map<String, Map<String, Object>> live;
    AtomicReference<Function<HttpRequest, HttpResponse>> introspection = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        nine = new FakeNine();
        clock = new TestClock();
        live = new HashMap<>();
        introspection.set(r -> {
            Map<String, Object> answer = live.get(FakeNine.form(r).get("token"));
            if (answer == null) return json(200, map("active", false));
            Map<String, Object> body = new HashMap<>(answer);
            body.put("active", true);
            return json(200, body);
        });
        nine.on("POST", "/oauth/introspect", r -> introspection.get().apply(r));
    }

    HybridTokenVerifier.Builder builder() {
        return HybridTokenVerifier.builder().issuer(nine.issuer).audience(API).clientId("app_api").clientSecret("api secret")
                .transport(nine).clock(clock);
    }

    Jwts.Claims claims(String sub, String jti, String sid) {
        long now = clock.epochSecond();
        return Jwts.claims().with("iss", nine.issuer).with("sub", sub).with("aud", API).with("client_id", "app_1")
                .with("scope", "orders:read").with("iat", now).with("exp", now + 3600).with("jti", jti).with("sid", sid);
    }

    /** A JWT 9in still considers active. */
    String activeJwt(String sub, String jti, String sid) {
        Jwts.Claims c = claims(sub, jti, sid);
        String token = Jwts.sign("RS256", "at+jwt", c);
        Map<String, Object> answer = new HashMap<>(c);
        answer.put("token_type", "access_token");
        live.put(token, answer);
        return token;
    }

    int introspections() {
        return nine.count("/oauth/introspect");
    }

    @Test
    void defaultModes() {
        assertEquals(HybridTokenVerifier.Mode.HYBRID, builder().build().mode());
        assertEquals(HybridTokenVerifier.Mode.LOCAL, HybridTokenVerifier.builder().issuer(nine.issuer).build().mode());
        NineException e = assertThrows(NineException.class, () -> HybridTokenVerifier.builder().issuer(nine.issuer).mode(HybridTokenVerifier.Mode.HYBRID).build());
        assertEquals("invalid_options", e.error());
        assertEquals(HybridTokenVerifier.Mode.INTROSPECT, HybridTokenVerifier.Mode.parse(" Introspect "));
        assertThrows(NineException.class, () -> HybridTokenVerifier.Mode.parse("fast"));
    }

    @Test
    void hybridIntrospectsOncePerTokenAndCaches() {
        HybridTokenVerifier v = builder().build();
        String token = activeJwt("usr_1", "j1", "s1");
        for (int i = 0; i < 5; i++) assertEquals("usr_1", v.verify("Bearer " + token, "orders:read").subject());
        assertEquals(1, introspections());
        HttpRequest req = nine.last("/oauth/introspect");
        assertTrue(req.header("Authorization").startsWith("Basic "));
        assertEquals(token, FakeNine.form(req).get("token"));
        // after cacheTtl, ask again
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        v.verify(token);
        assertEquals(2, introspections());
    }

    @Test
    void cacheNeverOutlivesTheToken() {
        HybridTokenVerifier v = builder().cacheTtl(Duration.ofHours(2)).build();
        long now = clock.epochSecond();
        Jwts.Claims c = claims("usr_1", "j1", "s1").with("exp", now + 120);
        String token = Jwts.sign("ES256", "at+jwt", c);
        live.put(token, new HashMap<>(c));
        v.verify(token);
        clock.advance(Duration.ofSeconds(100));
        v.verify(token);
        assertEquals(1, introspections());
        clock.advance(Duration.ofSeconds(60)); // past exp (and leeway)
        assertThrows(InvalidTokenException.class, () -> v.verify(token));
    }

    @Test
    void revokedTokenIsRefusedAndTheRefusalCached() {
        HybridTokenVerifier v = builder().build();
        String token = Jwts.sign("RS256", "at+jwt", claims("usr_1", "j1", "s1")); // not in `live`: inactive
        InvalidTokenException e = assertThrows(InvalidTokenException.class, () -> v.verify(token));
        assertEquals("token revoked", e.description());
        clock.advance(Duration.ofMinutes(30));
        assertThrows(InvalidTokenException.class, () -> v.verify(token));
        assertEquals(1, introspections(), "a revoked token never comes back: refusal cached until exp");
    }

    @Test
    void localChecksRunFirst() {
        HybridTokenVerifier v = builder().build();
        assertThrows(InvalidTokenException.class, () -> v.verify(Jwts.sign("RS256", "JWT", claims("u", "j", "s"))));
        String token = activeJwt("usr_1", "j1", "s1");
        assertThrows(InsufficientScopeException.class, () -> v.verify(token, "admin"));
        assertEquals(0, introspections());
    }

    @Test
    void refreshTokensAreNeverAccepted() {
        HybridTokenVerifier v = builder().build();
        String token = activeJwt("usr_1", "j1", "s1");
        live.get(token).put("token_type", "refresh_token");
        assertThrows(InvalidTokenException.class, () -> v.verify(token));
    }

    @Test
    void opaqueTokens() {
        HybridTokenVerifier v = builder().build();
        long now = clock.epochSecond();
        live.put(OPAQUE, map("token_type", "access_token", "iss", nine.issuer, "sub", "usr_o", "aud", API, "scope", "orders:read", "exp", now + 600, "jti", "jo"));
        AccessTokenClaims c = v.verify(OPAQUE, "orders:read");
        assertEquals("usr_o", c.subject());
        v.verify(OPAQUE);
        assertEquals(1, introspections());
        assertThrows(InsufficientScopeException.class, () -> v.verify(OPAQUE, "admin"));
        // introspection answer for another API
        live.put("9in_at_other", map("iss", nine.issuer, "sub", "u", "aud", "https://other", "exp", now + 600));
        assertThrows(InvalidTokenException.class, () -> v.verify("9in_at_other"));
        live.put("9in_at_expired", map("iss", nine.issuer, "sub", "u", "aud", API, "exp", now - 100));
        assertThrows(InvalidTokenException.class, () -> v.verify("9in_at_expired"));
        // unknown opaque token: refused, refusal cached for a minute
        assertThrows(InvalidTokenException.class, () -> v.verify("9in_at_unknown"));
        int before = introspections();
        assertThrows(InvalidTokenException.class, () -> v.verify("9in_at_unknown"));
        assertEquals(before, introspections());
        clock.advance(Duration.ofSeconds(61));
        assertThrows(InvalidTokenException.class, () -> v.verify("9in_at_unknown"));
        assertEquals(before + 1, introspections());
    }

    @Test
    void localModeRefusesOpaqueTokensAndNeverCallsNine() {
        HybridTokenVerifier v = builder().mode(HybridTokenVerifier.Mode.LOCAL).build();
        assertThrows(InvalidTokenException.class, () -> v.verify(OPAQUE));
        String revoked = Jwts.sign("RS256", "at+jwt", claims("usr_1", "j1", "s1"));
        assertEquals("usr_1", v.verify(revoked).subject());
        assertEquals(0, introspections());
    }

    @Test
    void introspectModeAsksEveryTime() {
        HybridTokenVerifier v = builder().mode(HybridTokenVerifier.Mode.INTROSPECT).build();
        String token = activeJwt("usr_1", "j1", "s1");
        v.verify(token);
        v.verify(token);
        v.verify(token);
        assertEquals(3, introspections());
        live.remove(token);
        assertThrows(InvalidTokenException.class, () -> v.verify(token));
    }

    @Test
    void webhookEventsEvictCachedAnswers() {
        HybridTokenVerifier v = builder().build();
        String a = activeJwt("usr_1", "j1", "s1");
        String b = activeJwt("usr_1", "j2", "s2");
        String c = activeJwt("usr_2", "j3", "s3");
        v.verify(a);
        v.verify(b);
        v.verify(c);
        assertEquals(3, introspections());

        // token.revoked for an access token: by jti
        live.remove(a);
        assertTrue(v.handleEvent(event("token.revoked", map("token_type", "access_token", "jti", "j1"))));
        assertThrows(InvalidTokenException.class, () -> v.verify(a));
        v.verify(b);
        assertEquals(4, introspections());

        // session.revoked: by sid
        live.remove(b);
        assertTrue(v.handleEvent(new WebhookEvent(event("session.revoked", map("sid", "s2")))));
        assertThrows(InvalidTokenException.class, () -> v.verify(b));

        // user events: by user
        for (String type : new String[] {"user.sessions_revoked", "user.deleted", "user.updated", "user.password_changed"}) {
            v.verify(c);
            int before = introspections();
            v.verify(c);
            assertEquals(before, introspections(), "cached");
            assertTrue(v.handleEvent(event(type, map("user", map("id", "usr_2")))));
            v.verify(c);
            assertEquals(before + 1, introspections(), type + " evicts");
        }
    }

    @Test
    void unrelatedEventsAreIgnored() {
        HybridTokenVerifier v = builder().build();
        String a = activeJwt("usr_1", "j1", "s1");
        v.verify(a);
        assertFalse(v.handleEvent(event("token.revoked", map("token_type", "refresh_token", "jti", "j1"))));
        assertFalse(v.handleEvent(event("user.login", map("user", map("id", "usr_1")))));
        assertFalse(v.handleEvent(event("session.revoked", map())));
        assertFalse(v.handleEvent(map("event_type", "user.deleted")));
        assertFalse(v.handleEvent((Map<String, Object>) null));
        v.verify(a);
        assertEquals(1, introspections());
    }

    @Test
    void sharedCacheEvictsAcrossServers() {
        MemoryCache shared = new MemoryCache(1000, clock);
        HybridTokenVerifier one = builder().cache(shared).build();
        HybridTokenVerifier two = builder().cache(shared).build();
        String token = activeJwt("usr_1", "j1", "s1");
        one.verify(token);
        two.verify(token);
        assertEquals(1, introspections(), "the second server reuses the first one's answer");
        live.remove(token);
        one.handleEvent(event("token.revoked", map("token_type", "access_token", "jti", "j1")));
        assertThrows(InvalidTokenException.class, () -> two.verify(token));
        assertEquals(2, introspections());
        // a newer answer after the marker is trusted again
        String other = activeJwt("usr_1", "j9", "s9");
        two.handleEvent(event("user.updated", map("user", map("id", "usr_1"))));
        clock.advance(Duration.ofMillis(5));
        one.verify(other);
        two.verify(other);
        assertEquals(3, introspections());
    }

    @Test
    void concurrentVerificationsShareOneIntrospection() throws Exception {
        String token = activeJwt("usr_1", "j1", "s1");
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        Function<HttpRequest, HttpResponse> normal = introspection.get();
        introspection.set(r -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return normal.apply(r);
        });
        HybridTokenVerifier v = builder().build();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<AccessTokenClaims>> results = new ArrayList<>();
            results.add(pool.submit(() -> v.verify(token)));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            for (int i = 0; i < 7; i++) results.add(pool.submit(() -> v.verify(token)));
            Thread.sleep(200);
            release.countDown();
            for (Future<AccessTokenClaims> f : results) assertEquals("usr_1", f.get(5, TimeUnit.SECONDS).subject());
            assertEquals(1, calls.get());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void introspectionFailuresAreNotTokenErrors() {
        HybridTokenVerifier v = builder().build();
        String token = activeJwt("usr_1", "j1", "s1");
        introspection.set(r -> json(401, error("invalid_client", "bad credentials")));
        NineException e = assertThrows(NineException.class, () -> v.verify(token));
        assertEquals("introspection_failed", e.error());
        assertEquals(503, e.status());
        assertFalse(e instanceof InvalidTokenException);
        assertTrue(e.getMessage().contains("invalid_client"));
        // not cached: the next call asks again
        introspection.set(r -> json(200, map("active", true)));
        v.verify(token);
    }

    @Test
    void memoryCacheIsBounded() {
        HybridTokenVerifier v = builder().cacheSize(2).build();
        String a = activeJwt("u", "a", "s");
        String b = activeJwt("u", "b", "s");
        String c = activeJwt("u", "c", "s");
        v.verify(a);
        v.verify(b);
        v.verify(c);
        v.verify(a); // evicted (least recently used): introspected again
        assertEquals(4, introspections());
        v.clear();
        v.verify(c);
        assertEquals(5, introspections());
    }

    @Test
    void fromEnv() {
        Map<String, String> env = new HashMap<>();
        env.put("NINE_ISSUER", nine.issuer);
        env.put("NINE_API_AUDIENCE", API);
        env.put("NINE_CLIENT_ID", "app_api");
        env.put("NINE_CLIENT_SECRET", "s");
        env.put("NINE_TOKEN_MODE", "introspect");
        env.put("NINE_TOKEN_CACHE_TTL", "60");
        HybridTokenVerifier v = HybridTokenVerifier.builder().env(env).transport(nine).clock(clock).build();
        assertEquals(HybridTokenVerifier.Mode.INTROSPECT, v.mode());
        env.remove("NINE_TOKEN_MODE");
        assertEquals(HybridTokenVerifier.Mode.HYBRID, HybridTokenVerifier.builder().env(env).build().mode());
        env.put("NINE_TOKEN_CACHE_TTL", "soon");
        assertThrows(NineException.class, () -> HybridTokenVerifier.builder().env(env));
    }

    static Map<String, Object> event(String type, Map<String, Object> data) {
        return map("id", "evt_1", "event_type", type, "created_at", "2026-11-22T10:00:00.000Z", "tenant", "tnt_1", "environment", "production", "data", data);
    }
}
