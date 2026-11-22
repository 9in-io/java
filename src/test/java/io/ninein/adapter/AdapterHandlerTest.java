package io.ninein.adapter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.NineException;
import io.ninein.Signatures;
import io.ninein.internal.Json;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AdapterHandlerTest {
    static final String SECRET = "adapter_secret_test";
    static final String BASE = "/nine";

    /** alice signs in with "hunter2", bob is blocked, 42 is alice's id. */
    static final class TestAdapter implements Adapter {
        final List<Map<String, Object>> events = new ArrayList<>();
        final List<UserQuery> queries = new ArrayList<>();

        static AdapterUser alice() {
            Map<String, Object> meta = new HashMap<>();
            meta.put("plan", "pro");
            return AdapterUser.builder("42").email("alice@acme.com").emailVerified(true).name("Alice").metadata(meta).build();
        }

        @Override
        public AdapterUser authenticate(Identifier identifier, String password) {
            if (identifier.value().equals("bob@acme.com")) return AdapterUser.builder("43").email("bob@acme.com").blocked(true).build();
            if (identifier.isEmail() && identifier.value().equals("alice@acme.com") && password.equals("hunter2")) return alice();
            return null;
        }

        @Override
        public AdapterUser findUser(UserQuery query) {
            queries.add(query);
            if (query.isById()) return "42".equals(query.id()) ? alice() : null;
            return query.identifier().value().equals("alice@acme.com") ? alice() : null;
        }

        @Override
        public void onEvent(Map<String, Object> event) {
            events.add(event);
        }
    }

    TestAdapter adapter;
    AdapterHandler handler;

    @BeforeEach
    void setUp() {
        adapter = new TestAdapter();
        handler = new AdapterHandler(SECRET, adapter);
    }

    static Map<String, String> headers(String path, String body, String secret) {
        Map<String, String> h = new HashMap<>();
        h.put("9In-Signature", Signatures.sign(secret, "POST", path, body));
        h.put("9in-request-id", "req_123");
        h.put("content-type", "application/json");
        return h;
    }

    AdapterResponse post(String route, String body) {
        String path = BASE + "/" + route;
        return handler.handle("POST", path, headers(path, body, SECRET), body);
    }

    /** The response is signed over path#request-id, as 9in checks it. */
    static void assertSigned(String path, AdapterResponse r) {
        assertTrue(Signatures.verify(SECRET, r.headers().get("9in-signature"), "POST", path + "#req_123", r.body()), "response signature");
        assertFalse(Signatures.verify(SECRET, r.headers().get("9in-signature"), "POST", path + "#req_other", r.body()), "bound to the request id");
    }

    @Test
    void authenticate() {
        AdapterResponse ok = post("authenticate", "{\"identifier\":{\"type\":\"email\",\"value\":\"alice@acme.com\"},\"password\":\"hunter2\"}");
        assertEquals(200, ok.status());
        assertEquals("application/json", ok.headers().get("Content-Type"));
        Map<String, Object> user = Json.object(Json.parseObject(ok.bodyText()), "user");
        assertEquals("42", user.get("id"));
        assertEquals(true, user.get("email_verified"));
        assertEquals(Collections.singletonMap("plan", "pro"), user.get("metadata"));
        assertSigned("/nine/authenticate", ok);

        AdapterResponse wrong = post("authenticate", "{\"identifier\":{\"type\":\"email\",\"value\":\"alice@acme.com\"},\"password\":\"nope\"}");
        assertEquals(401, wrong.status());
        assertEquals("{\"error\":\"invalid_credentials\"}", wrong.bodyText());
        assertSigned("/nine/authenticate", wrong);

        AdapterResponse blocked = post("authenticate", "{\"identifier\":{\"type\":\"email\",\"value\":\"bob@acme.com\"},\"password\":\"x\"}");
        assertEquals(403, blocked.status());
        assertEquals("{\"error\":\"blocked\"}", blocked.bodyText());

        for (String bad : new String[] {"{}", "{\"identifier\":{\"type\":\"email\",\"value\":\"a\"}}", "{\"identifier\":{\"type\":\"fax\",\"value\":\"a\"},\"password\":\"x\"}",
                "{\"identifier\":{\"type\":\"email\",\"value\":\"\"},\"password\":\"x\"}", "{\"identifier\":\"alice\",\"password\":\"x\"}",
                "{\"identifier\":{\"type\":\"email\",\"value\":\"a\"},\"password\":5}"}) {
            AdapterResponse r = post("authenticate", bad);
            assertEquals(400, r.status(), bad);
            assertEquals("{\"error\":\"invalid_request\"}", r.bodyText());
            assertSigned("/nine/authenticate", r);
        }
    }

    @Test
    void user() {
        AdapterResponse byId = post("user", "{\"id\":\"42\"}");
        assertEquals(200, byId.status());
        assertEquals("42", Json.object(Json.parseObject(byId.bodyText()), "user").get("id"));
        assertSigned("/nine/user", byId);
        assertEquals(200, post("user", "{\"id\":42}").status());
        assertEquals("42", adapter.queries.get(1).id());
        AdapterResponse byIdentifier = post("user", "{\"identifier\":{\"type\":\"phone\",\"value\":\"+447700900123\"}}");
        assertEquals(404, byIdentifier.status());
        assertEquals("{\"error\":\"not_found\"}", byIdentifier.bodyText());
        assertTrue(adapter.queries.get(2).identifier().isPhone());
        assertEquals(200, post("user", "{\"identifier\":{\"type\":\"email\",\"value\":\"alice@acme.com\"}}").status());
        assertEquals(400, post("user", "{}").status());
        assertEquals(400, post("user", "{\"id\":\"\"}").status());
    }

    @Test
    void event() {
        AdapterResponse r = post("event", "{\"id\":\"evt_1\",\"event_type\":\"otp.requested\",\"created_at\":\"2026-11-22T10:00:00.000Z\","
                + "\"data\":{\"user_id\":\"42\",\"channel\":\"email\",\"to\":\"alice@acme.com\",\"code\":\"123456\",\"purpose\":\"login\"}}");
        assertEquals(204, r.status());
        assertEquals(0, r.body().length);
        assertNull(r.headers().get("Content-Type"));
        assertSigned("/nine/event", r);
        assertEquals("otp.requested", adapter.events.get(0).get("event_type"));
        assertEquals("123456", Json.object(adapter.events.get(0), "data").get("code"));
        assertEquals(204, post("event", "{\"event_type\":\"user.updated\"}").status());
        assertEquals(Collections.emptyMap(), adapter.events.get(1).get("data"));
        assertEquals(400, post("event", "{\"data\":{}}").status());
    }

    @Test
    void requestChecks() {
        String path = "/nine/user";
        String body = "{\"id\":\"42\"}";
        AdapterResponse get = handler.handle("GET", path, headers(path, body, SECRET), body);
        assertEquals(405, get.status());
        assertEquals("POST", get.headers().get("Allow"));

        AdapterResponse unsigned = handler.handle("POST", path, new HashMap<>(), body);
        assertEquals(401, unsigned.status());
        assertEquals("{\"error\":\"invalid_signature\"}", unsigned.bodyText());
        assertNull(unsigned.headers().get("9in-signature"), "refusals of unsigned requests aren't signed");

        assertEquals(401, handler.handle("POST", path, headers(path, body, "wrong"), body).status());
        assertEquals(401, handler.handle("POST", "/nine/authenticate", headers(path, body, SECRET), body).status(), "signed for another path");
        assertEquals(401, handler.handle("POST", path, headers(path, body, SECRET), "{\"id\":\"43\"}").status(), "body changed");
        Map<String, String> old = headers(path, body, SECRET);
        old.put("9In-Signature", Signatures.sign(SECRET, "POST", path, body, System.currentTimeMillis() / 1000 - 301));
        assertEquals(401, handler.handle("POST", path, old, body).status(), "too old");

        AdapterResponse badJson = post("user", "{\"id\":");
        assertEquals(400, badJson.status());
        assertEquals("{\"error\":\"invalid_json\"}", badJson.bodyText());
        assertSigned("/nine/user", badJson);
        assertEquals(400, post("user", "[1,2]").status());
        assertEquals(400, post("user", "").status(), "an empty body is {} (then invalid_request)");

        AdapterResponse unknown = post("unknown", "{}");
        assertEquals(404, unknown.status());
        assertSigned("/nine/unknown", unknown);
    }

    @Test
    void rotationSignsResponsesWithTheFirstSecret() {
        AdapterHandler rotating = new AdapterHandler(Arrays.asList("new", "old"), adapter, Duration.ofMinutes(5), Clock.systemUTC());
        String path = "/nine/user";
        String body = "{\"id\":\"42\"}";
        AdapterResponse r = rotating.handle("POST", path, headers(path, body, "old"), body);
        assertEquals(200, r.status());
        assertTrue(Signatures.verify("new", r.headers().get("9in-signature"), "POST", path + "#req_123", r.body()));
    }

    @Test
    void missingRequestIdSignsAnEmptyOne() {
        String path = "/nine/user";
        String body = "{\"id\":\"42\"}";
        Map<String, String> h = headers(path, body, SECRET);
        h.remove("9in-request-id");
        AdapterResponse r = handler.handle("POST", path, h, body.getBytes(StandardCharsets.UTF_8));
        assertTrue(Signatures.verify(SECRET, r.headers().get("9in-signature"), "POST", path + "#", r.body()));
    }

    @Test
    void adapterUser() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("id", 7);
        raw.put("email", "x@y.z");
        raw.put("blocked", 1);
        raw.put("email_verified", "true");
        raw.put("metadata", "not an object");
        raw.put("password_hash", "never sent");
        AdapterUser u = AdapterUser.of(raw);
        assertEquals("7", u.id());
        assertTrue(u.isBlocked());
        assertEquals(true, u.get("email_verified"));
        assertNull(u.get("metadata"));
        assertFalse(u.toMap().containsKey("password_hash"));
        assertThrows(IllegalArgumentException.class, () -> AdapterUser.builder("").build());
        assertThrows(NineException.class, () -> new AdapterHandler("", adapter));
        assertThrows(NineException.class, () -> new AdapterHandler(SECRET, null));
    }
}
