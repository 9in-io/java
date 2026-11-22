package io.ninein;

import static io.ninein.testing.FakeNine.error;
import static io.ninein.testing.FakeNine.json;
import static io.ninein.testing.FakeNine.list;
import static io.ninein.testing.FakeNine.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.http.HttpRequest;
import io.ninein.internal.Json;
import io.ninein.testing.FakeNine;
import io.ninein.testing.TestClock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ManagementClientTest {
    FakeNine nine;
    TestClock clock;
    ManagementClient client;
    AtomicInteger tokens = new AtomicInteger();
    List<String> scopes = new ArrayList<>();

    @BeforeEach
    void setUp() {
        nine = new FakeNine();
        clock = new TestClock();
        nine.on("POST", "/oauth/token", r -> {
            Map<String, String> form = FakeNine.form(r);
            assertEquals("client_credentials", form.get("grant_type"));
            assertTrue(r.header("Authorization").startsWith("Basic "));
            scopes.add(form.get("scope"));
            return json(200, map("access_token", "mgmt_" + tokens.incrementAndGet(), "token_type", "Bearer", "expires_in", 300, "scope", form.get("scope")));
        });
        client = ManagementClient.builder().issuer(nine.issuer).clientId("app_m").clientSecret("sec").transport(nine).clock(clock).build();
    }

    Map<String, Object> user(String id) {
        return map("id", id, "email", id + "@example.com", "email_verified", true, "metadata", map("plan", "pro", "fields", map("company", "Acme")),
                "created_at", "2026-11-09T08:00:00.000Z", "login_count", 12);
    }

    @Test
    void listUsersAndPaging() {
        nine.on("GET", "/api/v1/users", r -> {
            String q = r.url().contains("?") ? r.url().substring(r.url().indexOf('?') + 1) : "";
            if (q.contains("cursor=c2")) return json(200, map("users", list(user("u3")), "next_cursor", null, "total", 3));
            return json(200, map("users", list(user("u1"), user("u2")), "next_cursor", "c2", "total", 3));
        });
        Map<String, Object> page = client.listUsers("jane", null, 2);
        assertTrue(nine.last("/api/v1/users").url().endsWith("/api/v1/users?q=jane&limit=2"));
        assertEquals("c2", page.get("next_cursor"));
        assertEquals(3L, page.get("total"));
        client.listUsers();
        assertTrue(nine.last("/api/v1/users").url().endsWith("/api/v1/users"));
        List<Map<String, Object>> all = client.listAllUsers(null);
        assertEquals(3, all.size());
        assertEquals("u3", all.get(2).get("id"));
        assertEquals(Collections.singletonList("management:users:read"), new ArrayList<>(new java.util.LinkedHashSet<>(scopes)));
    }

    @Test
    void wireDataPassesThroughUnchanged() {
        nine.on("GET", "/api/v1/users/usr_1", r -> json(200, map("user", user("usr_1"), "identities", list(), "sessions", list(), "has_password", true, "mfa", map("enabled", false))));
        Map<String, Object> detail = client.getUser("usr_1");
        @SuppressWarnings("unchecked")
        Map<String, Object> u = (Map<String, Object>) detail.get("user");
        assertEquals(true, u.get("email_verified"));
        assertEquals("2026-11-09T08:00:00.000Z", u.get("created_at"));
        assertEquals(map("plan", "pro", "fields", map("company", "Acme")), u.get("metadata"));
        assertEquals(true, detail.get("has_password"));
    }

    @Test
    void idsAreUrlEncoded() {
        nine.on("GET", "/api/v1/users/a%2Fb%3Fc", r -> json(200, map("user", user("a/b?c"))));
        client.getUser("a/b?c");
        assertTrue(nine.last("/api/v1/users/a%2Fb%3Fc").url().endsWith("/users/a%2Fb%3Fc"));
    }

    @Test
    void findUser() {
        nine.on("GET", "/api/v1/users/lookup", r -> r.url().contains("missing")
                ? json(404, error("not_found", "no such user"))
                : json(200, map("user", user("usr_1"))));
        assertEquals("usr_1", client.findUserByEmail("jane+x@example.com").get("id"));
        assertTrue(nine.last("/lookup").url().endsWith("/users/lookup?email=jane%2Bx%40example.com"));
        assertEquals("usr_1", client.findUser("phone_number", "+447700900123").get("id"));
        assertTrue(nine.last("/lookup").url().endsWith("phone_number=%2B447700900123"));
        assertNull(client.findUser("username", "missing"));
        assertThrows(IllegalArgumentException.class, () -> client.findUser("id", "x"));
    }

    @Test
    void createImportUpdateDeleteBlock() {
        List<HttpRequest> writes = new ArrayList<>();
        nine.on("POST", "/api/v1/users", r -> {
            writes.add(r);
            return json(201, map("user", user("usr_new")));
        });
        nine.on("POST", "/api/v1/users/import", r -> {
            writes.add(r);
            return json(200, map("results", list(map("index", 0, "ok", true, "status", "created", "id", "old_1"))));
        });
        nine.on("PATCH", "/api/v1/users/usr_new", r -> {
            writes.add(r);
            Map<String, Object> body = Json.parseObject(r.bodyText());
            Map<String, Object> u = user("usr_new");
            u.putAll(body);
            return json(200, map("user", u));
        });
        nine.on("DELETE", "/api/v1/users/usr_new", r -> {
            writes.add(r);
            return json(204, null);
        });

        Map<String, Object> created = client.createUser(map("email", "new@example.com", "password", "correct horse", "metadata", map("plan", "free")));
        assertEquals("usr_new", created.get("id"));
        assertEquals("application/json", writes.get(0).header("Content-Type"));
        assertEquals(map("email", "new@example.com", "password", "correct horse", "metadata", map("plan", "free")), Json.parseObject(writes.get(0).bodyText()));

        Map<String, Object> imported = client.importUsers(Collections.singletonList(map("id", "old_1", "email", "o@example.com", "password_hash", "$2b$10$abc")), "update", "legacy");
        assertEquals(Boolean.TRUE, ((Map<?, ?>) ((List<?>) imported.get("results")).get(0)).get("ok"));
        Map<String, Object> importBody = Json.parseObject(writes.get(1).bodyText());
        assertEquals("update", importBody.get("on_conflict"));
        assertEquals("legacy", importBody.get("source"));

        assertEquals("Jane", client.updateUser("usr_new", map("name", "Jane")).get("name"));
        assertEquals("PATCH", writes.get(2).method());
        assertEquals(true, client.blockUser("usr_new").get("blocked"));
        assertEquals("{\"blocked\":true}", writes.get(3).bodyText());
        assertEquals(false, client.unblockUser("usr_new").get("blocked"));
        client.deleteUser("usr_new");
        assertEquals("DELETE", writes.get(5).method());
        assertTrue(scopes.stream().allMatch("management:users:write"::equals));
        assertEquals(1, tokens.get(), "one cached token for the write scope");
    }

    @Test
    void loginLinksAndSessions() {
        nine.on("POST", "/api/v1/users/usr_1/login-link", r -> json(200, map("url", nine.issuer + "/link/abc", "expires_at", "2026-11-22T10:15:00.000Z")));
        nine.on("GET", "/api/v1/users/usr_1/sessions", r -> json(200, map("sessions", list(map("sid", "s1", "user_id", "usr_1", "amr", list("pwd"))))));
        nine.on("DELETE", "/api/v1/users/usr_1/sessions", r -> json(200, map("revoked", 2)));
        nine.on("DELETE", "/api/v1/sessions/s1", r -> json(204, null));

        Map<String, Object> link = client.createLoginLink("usr_1", "/welcome", 600);
        assertEquals(nine.issuer + "/link/abc", link.get("url"));
        assertEquals(map("return_to", "/welcome", "ttl_seconds", 600L), Json.parseObject(nine.last("/login-link").bodyText()));
        client.createLoginLink("usr_1");
        assertEquals("{}", nine.last("/login-link").bodyText());

        assertEquals("s1", client.listUserSessions("usr_1").get(0).get("sid"));
        assertEquals(2, client.revokeUserSessions("usr_1"));
        client.revokeSession("s1");
        assertTrue(scopes.contains("management:users:read"));
        assertTrue(scopes.contains("management:users:write"));
        assertTrue(scopes.contains("management:sessions:write"));
    }

    @Test
    void tokensAreCachedPerScopeUntilShortlyBeforeExpiry() {
        nine.on("GET", "/api/v1/users", r -> json(200, map("users", list(), "next_cursor", null, "total", 0)));
        client.listUsers();
        client.listUsers();
        assertEquals(1, tokens.get());
        assertEquals("Bearer mgmt_1", nine.last("/api/v1/users").header("Authorization"));
        clock.advance(Duration.ofSeconds(271)); // within 30 s of expiry
        client.listUsers();
        assertEquals(2, tokens.get());
        assertEquals("Bearer mgmt_2", nine.last("/api/v1/users").header("Authorization"));
    }

    @Test
    void unauthorizedDropsTheCachedToken() {
        AtomicInteger calls = new AtomicInteger();
        nine.on("GET", "/api/v1/users", r -> calls.incrementAndGet() == 1
                ? json(401, error("invalid_token", "token revoked"))
                : json(200, map("users", list())));
        NineException e = assertThrows(NineException.class, () -> client.listUsers());
        assertEquals("invalid_token", e.error());
        assertEquals(401, e.status());
        client.listUsers();
        assertEquals(2, tokens.get());
    }

    @Test
    void errorsCarryTheServersCodeAndStatus() {
        nine.on("POST", "/api/v1/users", r -> json(422, map("error", "invalid_user", "error_description", "unknown field: nickname2", "details", map("field", "nickname2"))));
        NineException e = assertThrows(NineException.class, () -> client.createUser(map("nickname2", "x")));
        assertEquals("invalid_user", e.error());
        assertEquals("unknown field: nickname2", e.description());
        assertEquals(422, e.status());
        nine.on("POST", "/oauth/token", r -> json(400, error("invalid_scope", "management scopes not granted")));
        ManagementClient fresh = ManagementClient.builder().issuer(nine.issuer).clientId("app_m").clientSecret("sec").transport(nine).build();
        NineException t = assertThrows(NineException.class, () -> fresh.listUsers());
        assertEquals("invalid_scope", t.error());
    }

    @Test
    void configuration() {
        assertEquals("invalid_options", assertThrows(NineException.class, () -> ManagementClient.builder().issuer(nine.issuer).clientId("x").build()).error());
        assertEquals("insecure_issuer", assertThrows(NineException.class, () -> ManagementClient.builder().issuer("http://acme.example").clientId("x").clientSecret("y").build()).error());
        Map<String, String> env = new HashMap<>();
        env.put("NINE_ISSUER", nine.issuer);
        env.put("NINE_CLIENT_ID", "app_web");
        env.put("NINE_CLIENT_SECRET", "web");
        env.put("NINE_MANAGEMENT_CLIENT_ID", "app_m2");
        env.put("NINE_MANAGEMENT_CLIENT_SECRET", "m2");
        ManagementClient fromEnv = ManagementClient.builder().env(env).transport(nine).build();
        assertTrue(fromEnv.toString().contains("app_m2"));
        ManagementClient scoped = ManagementClient.builder().issuer(nine.issuer).clientId("a").clientSecret("b").scope("management:users:read management:users:write").transport(nine).build();
        nine.on("GET", "/api/v1/users", r -> json(200, map("users", list())));
        scoped.listUsers();
        assertEquals("management:users:read management:users:write", scopes.get(scopes.size() - 1));
    }
}
