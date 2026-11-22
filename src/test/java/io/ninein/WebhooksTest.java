package io.ninein;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.testing.TestClock;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class WebhooksTest {
    static final String SECRET = "whsec_test";
    static final String PATH = "/nine/webhook";
    static final String BODY = "{\"id\":\"evt_1\",\"event_type\":\"user.created\",\"created_at\":\"2026-11-22T10:00:00.000Z\","
            + "\"tenant\":\"tnt_1\",\"environment\":\"sandbox\",\"data\":{\"user\":{\"id\":\"usr_1\",\"email\":\"jane@example.com\"}}}";

    @Test
    void verifiesAndParsesTheEvent() {
        String sig = Signatures.sign(SECRET, "POST", PATH, BODY);
        WebhookEvent event = Webhooks.verify(SECRET, BODY.getBytes(StandardCharsets.UTF_8), sig, PATH);
        assertEquals("evt_1", event.id());
        assertEquals("user.created", event.eventType());
        assertEquals("2026-11-22T10:00:00.000Z", event.createdAt());
        assertEquals("tnt_1", event.tenant());
        assertEquals("sandbox", event.environment());
        assertEquals("usr_1", event.user().get("id"));
        assertEquals("jane@example.com", event.user().get("email"));
        assertEquals(BODY, io.ninein.internal.Json.write(event.asMap()));
        assertEquals(event.id(), Webhooks.verify(SECRET, BODY, sig, PATH).id());
    }

    @Test
    void rejectsBadSignatures() {
        String sig = Signatures.sign(SECRET, "POST", PATH, BODY);
        assertEquals("mismatch", assertThrows(SignatureException.class, () -> Webhooks.verify(SECRET, BODY.replace("usr_1", "usr_2"), sig, PATH)).reason());
        assertEquals("mismatch", assertThrows(SignatureException.class, () -> Webhooks.verify(SECRET, BODY, sig, "/other")).reason());
        assertEquals("mismatch", assertThrows(SignatureException.class, () -> Webhooks.verify("other", BODY, sig, PATH)).reason());
        assertEquals("missing", assertThrows(SignatureException.class, () -> Webhooks.verify(SECRET, BODY, null, PATH)).reason());
        assertEquals("malformed", assertThrows(SignatureException.class, () -> Webhooks.verify(SECRET, BODY, "v1=zz", PATH)).reason());
        String old = Signatures.sign(SECRET, "POST", PATH, BODY, System.currentTimeMillis() / 1000 - 600);
        SignatureException expired = assertThrows(SignatureException.class, () -> Webhooks.verify(SECRET, BODY, old, PATH));
        assertEquals("expired", expired.reason());
        assertEquals(401, expired.status());
        assertEquals("invalid_signature", expired.error());
        // a GET carrying a valid POST signature
        assertThrows(SignatureException.class, () -> Webhooks.verify(Collections.singletonList(SECRET), "GET", BODY.getBytes(StandardCharsets.UTF_8), sig, PATH, null, Clock.systemUTC()));
        // a longer tolerance accepts the old one (replaying recorded deliveries)
        assertEquals("evt_1", Webhooks.verify(Collections.singletonList(SECRET), BODY.getBytes(StandardCharsets.UTF_8), old, PATH, Duration.ofHours(1)).id());
    }

    @Test
    void rotation() {
        String sig = Signatures.sign("new", "POST", PATH, BODY);
        assertEquals("evt_1", Webhooks.verify(Arrays.asList("old", "new"), BODY.getBytes(StandardCharsets.UTF_8), sig, PATH, null).id());
        assertThrows(NineException.class, () -> Webhooks.verify(Collections.<String>emptyList(), BODY.getBytes(StandardCharsets.UTF_8), sig, PATH, null));
        assertThrows(NineException.class, () -> Webhooks.verify("", BODY, sig, PATH));
    }

    @Test
    void invalidPayloads() {
        for (String body : new String[] {"not json", "[1]", "{\"id\":\"x\"}", "{\"event_type\":\"user.created\"}", ""}) {
            String sig = Signatures.sign(SECRET, "POST", PATH, body);
            NineException e = assertThrows(NineException.class, () -> Webhooks.verify(SECRET, body, sig, PATH), body);
            assertEquals("invalid_payload", e.error());
            assertEquals(400, e.status());
        }
    }

    @Test
    void secretsFromEnv() {
        Map<String, String> env = new HashMap<>();
        env.put("NINE_WEBHOOK_SECRET", "a, b");
        env.put("NINE_WEBHOOK_SECRET_PREVIOUS", "c");
        assertEquals(Arrays.asList("a", "b", "c"), Webhooks.secretsFromEnv(env, "WEBHOOK_SECRET"));
        assertTrue(Webhooks.secretsFromEnv(new HashMap<>(), "WEBHOOK_SECRET").isEmpty());
    }

    // ---- process once ----

    @Test
    void processesEachEventOnce() {
        MemoryCache cache = new MemoryCache();
        EventDeduplicator dedupe = new EventDeduplicator(cache);
        AtomicInteger runs = new AtomicInteger();
        assertEquals(EventDeduplicator.Outcome.PROCESSED, dedupe.process("evt_1", runs::incrementAndGet));
        assertEquals(EventDeduplicator.Outcome.DUPLICATE, dedupe.process("evt_1", runs::incrementAndGet));
        assertEquals(1, runs.get());
        assertEquals(204, EventDeduplicator.Outcome.DUPLICATE.httpStatus());
        assertEquals("duplicate", EventDeduplicator.Outcome.DUPLICATE.status());
        assertEquals(EventDeduplicator.Outcome.PROCESSED, dedupe.process("evt_2", runs::incrementAndGet));
        assertEquals("done", cache.get("nine:event:evt_1"));
    }

    @Test
    void failedHandlerReleasesTheEventForTheRetry() {
        EventDeduplicator dedupe = new EventDeduplicator(new MemoryCache());
        IllegalStateException boom = new IllegalStateException("db down");
        assertEquals(boom, assertThrows(IllegalStateException.class, () -> dedupe.process("evt_1", () -> {
            throw boom;
        })));
        AtomicInteger runs = new AtomicInteger();
        assertEquals(EventDeduplicator.Outcome.PROCESSED, dedupe.process("evt_1", runs::incrementAndGet));
        assertEquals(1, runs.get());
    }

    @Test
    void concurrentDuplicateIsInProgress() throws Exception {
        EventDeduplicator dedupe = new EventDeduplicator(new MemoryCache());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<EventDeduplicator.Outcome> first = pool.submit(() -> dedupe.process("evt_1", () -> {
                started.countDown();
                try {
                    finish.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            EventDeduplicator.Outcome second = dedupe.process("evt_1", () -> {
                throw new AssertionError("must not run");
            });
            assertEquals(EventDeduplicator.Outcome.IN_PROGRESS, second);
            assertEquals(409, second.httpStatus());
            finish.countDown();
            assertEquals(EventDeduplicator.Outcome.PROCESSED, first.get(5, TimeUnit.SECONDS));
            assertEquals(EventDeduplicator.Outcome.DUPLICATE, dedupe.process("evt_1", () -> {}));
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void manyConcurrentDeliveriesRunTheHandlerOnce() throws Exception {
        EventDeduplicator dedupe = new EventDeduplicator(new MemoryCache());
        AtomicInteger runs = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        try {
            List<Future<EventDeduplicator.Outcome>> results = new ArrayList<>();
            for (int i = 0; i < 64; i++) results.add(pool.submit(() -> dedupe.process("evt_x", runs::incrementAndGet)));
            int processed = 0;
            for (Future<EventDeduplicator.Outcome> f : results) if (f.get(5, TimeUnit.SECONDS) == EventDeduplicator.Outcome.PROCESSED) processed++;
            assertEquals(1, processed);
            assertEquals(1, runs.get());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void staleClaimCanBeTakenOver() {
        TestClock clock = new TestClock();
        MemoryCache cache = new MemoryCache(100, clock);
        cache.add("nine:event:evt_1", "processing", Duration.ofMinutes(5)); // a crashed worker's claim
        EventDeduplicator dedupe = new EventDeduplicator(cache);
        assertEquals(EventDeduplicator.Outcome.IN_PROGRESS, dedupe.process("evt_1", () -> {}));
        clock.advance(Duration.ofMinutes(6));
        assertEquals(EventDeduplicator.Outcome.PROCESSED, dedupe.process("evt_1", () -> {}));
        assertThrows(NineException.class, () -> dedupe.process("", () -> {}));
    }

    @Test
    void memoryCache() {
        TestClock clock = new TestClock();
        MemoryCache cache = new MemoryCache(3, clock);
        cache.set("a", "1", Duration.ofSeconds(10));
        cache.set("b", "2", null);
        assertEquals("1", cache.get("a"));
        assertTrue(!cache.add("a", "x", null));
        clock.advance(Duration.ofSeconds(11));
        assertNull(cache.get("a"));
        assertTrue(cache.add("a", "x", null));
        cache.set("c", "3", null);
        cache.set("d", "4", null);
        assertEquals(3, cache.size());
        cache.delete("d");
        assertNull(cache.get("d"));
        cache.clear();
        assertEquals(0, cache.size());
    }
}
