package io.ninein.e2e;

import static io.ninein.e2e.Live.env;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.ninein.AccessTokenClaims;
import io.ninein.AuthClient;
import io.ninein.Discovery;
import io.ninein.EventDeduplicator;
import io.ninein.HybridTokenVerifier;
import io.ninein.InsufficientScopeException;
import io.ninein.InvalidTokenException;
import io.ninein.Login;
import io.ninein.LoginOptions;
import io.ninein.ManagementClient;
import io.ninein.MemoryCache;
import io.ninein.NineException;
import io.ninein.PendingLogin;
import io.ninein.SignatureException;
import io.ninein.Signatures;
import io.ninein.TokenSet;
import io.ninein.TokenVerifier;
import io.ninein.WebhookEvent;
import io.ninein.Webhooks;
import io.ninein.adapter.Adapter;
import io.ninein.adapter.AdapterHandler;
import io.ninein.adapter.AdapterResponse;
import io.ninein.adapter.AdapterUser;
import io.ninein.adapter.Identifier;
import io.ninein.adapter.UserQuery;
import io.ninein.internal.Json;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * The Java SDK against live 9in (the {@code sdk-e2e} production test tenants): sandbox sign-in
 * through the hosted pages with the public client, token verification, refresh rotation,
 * revocation, real webhook deliveries and real adapter calls, then the confidential client on
 * production (Management API, server-side sign-in, client credentials, login links, sessions,
 * hybrid and introspection verification, opaque tokens). Opt-in: {@code ./gradlew test -Pe2e}.
 */
@Tag("e2e")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LiveTest {
    String sandboxIssuer;
    String spaClient;
    String spaRedirect;
    String api;
    String sandboxEmail;
    AuthClient sandbox;
    TokenSet session;

    String issuer;
    String serverClient;
    String serverSecret;
    String serverRedirect;
    String managedEmail;
    String managedPassword;
    ManagementClient management;
    String managedUserId;

    @BeforeAll
    void setUp() {
        assumeTrue(Live.has("SANDBOX_ISSUER"), "no E2E settings (NINE_E2E_ENV)");
        sandboxIssuer = env("SANDBOX_ISSUER");
        spaClient = env("SPA_CLIENT_ID");
        spaRedirect = env("SPA_REDIRECT_URI");
        api = env("API_AUDIENCE");
        sandboxEmail = "java-" + Live.RUN + "@sandbox.e2e.test";
        sandbox = AuthClient.builder().issuer(sandboxIssuer).clientId(spaClient).redirectUri(spaRedirect).audience(api)
                .scopes("openid", "profile", "email", "offline_access", "read:things").build();
        issuer = env("ISSUER");
        serverClient = env("SERVER_CLIENT_ID");
        serverRedirect = env("SERVER_REDIRECT_URI");
        serverSecret = Live.has("SERVER_CLIENT_SECRET") ? env("SERVER_CLIENT_SECRET") : null;
        managedEmail = "managed-java-" + Live.RUN + "@e2e.9in.test";
        managedPassword = "E2e-" + Live.RUN + "-Password!";
        if (serverSecret != null) management = ManagementClient.builder().issuer(issuer).clientId(serverClient).clientSecret(serverSecret).build();
        System.out.println("e2e run " + Live.RUN);
    }

    @AfterAll
    void cleanUp() {
        if (serverSecret == null) return;
        if (managedUserId != null) {
            try {
                management.deleteUser(managedUserId);
                System.out.println("deleted the managed user");
            } catch (NineException e) {
                System.out.println("could not delete the managed user: " + e.error());
            }
        }
        // The sandbox accepts any password, so this run's sign-ins created users there: delete them.
        ManagementClient sandboxManagement = ManagementClient.builder().issuer(sandboxIssuer).clientId(serverClient).clientSecret(serverSecret).build();
        int deleted = 0;
        for (Map<String, Object> user : sandboxManagement.listAllUsers(Live.RUN)) {
            Object email = user.get("email");
            if (email instanceof String && ((String) email).endsWith(Live.RUN + "@sandbox.e2e.test") && ((String) email).startsWith("java-")) {
                sandboxManagement.deleteUser((String) user.get("id"));
                deleted++;
            }
        }
        System.out.println("deleted " + deleted + " sandbox user(s)");
    }

    TokenSet sandboxSignIn(AuthClient client, String returnTo) throws Exception {
        Login login = client.createLogin(LoginOptions.builder().returnTo(returnTo).build());
        Live.Result result = Live.signIn(login.url(), spaRedirect, sandboxEmail, "any-password");
        assertNull(result.text(), "sign-in reached a page instead of the callback");
        return client.handleCallback(result.callback(), PendingLogin.fromJson(login.pending().toJson()));
    }

    // ---- sandbox, public client ----

    @Test
    @Order(1)
    void discovery() {
        Discovery d = sandbox.discovery();
        assertEquals(sandboxIssuer, d.issuer());
        assertEquals(sandboxIssuer + "/oauth/token", d.tokenEndpoint());
        assertNotNull(d.jwksUri());
        assertNotNull(d.revocationEndpoint());
        assertNotNull(d.deviceAuthorizationEndpoint());
        assertTrue(d.authorizationResponseIssParameterSupported());
    }

    @Test
    @Order(2)
    void signsInWithPkceThroughTheHostedPage() throws Exception {
        session = sandboxSignIn(sandbox, "/java-after");
        assertEquals("/java-after", session.returnTo());
        assertNotNull(session.refreshToken());
        assertFalse(session.isExpired(Duration.ofSeconds(60)));
        assertEquals(sandboxEmail, session.claim("email"));
        assertEquals(spaClient, session.claim("aud"));
        assertEquals(sandboxIssuer, session.claim("iss"));
        Map<String, Object> info = sandbox.userInfo(session.accessToken());
        assertEquals(session.subject(), info.get("sub"));
        assertEquals(sandboxEmail, info.get("email"));
        TokenSet restored = TokenSet.fromJson(session.toJson());
        assertEquals(session.accessToken(), restored.accessToken());
        assertEquals(session.refreshToken(), restored.refreshToken());
        assertEquals(session.subject(), restored.subject());
        assertEquals(session.expiresAt().getEpochSecond(), restored.expiresAt().getEpochSecond());
    }

    @Test
    @Order(3)
    void verifiesTheAccessTokenLocally() {
        TokenVerifier verifier = TokenVerifier.builder().issuer(sandboxIssuer).audience(api).build();
        AccessTokenClaims claims = verifier.verify("Bearer " + session.accessToken(), "read:things");
        assertEquals(session.subject(), claims.subject());
        assertEquals(spaClient, claims.clientId());
        InsufficientScopeException scope = assertThrows(InsufficientScopeException.class, () -> verifier.verify(session.accessToken(), "write:things"));
        assertEquals(403, scope.status());
        TokenVerifier other = TokenVerifier.builder().issuer(sandboxIssuer).audience("https://other.e2e.9in.test").build();
        assertThrows(InvalidTokenException.class, () -> other.verify(session.accessToken()));
        String t = session.accessToken();
        assertThrows(InvalidTokenException.class, () -> verifier.verify(t.substring(0, t.length() - 4) + "AAAA"));
        assertThrows(InvalidTokenException.class, () -> verifier.verify(session.idToken()), "an ID token is not an access token");
    }

    @Test
    @Order(4)
    void refreshRotatesAndRevocationSticks() throws Exception {
        TokenSet rotated = sandbox.refresh(session);
        assertNotEquals(session.refreshToken(), rotated.refreshToken());
        assertNotEquals(session.accessToken(), rotated.accessToken());
        assertEquals(session.subject(), rotated.subject());
        assertSame(rotated, sandbox.ensureFresh(rotated, Duration.ofSeconds(60)), "a fresh set is returned as is, without a request");
        // Within 30 seconds a repeat is a race, not reuse: the same new refresh token comes back.
        assertEquals(rotated.refreshToken(), sandbox.refresh(session).refreshToken());

        TokenSet other = sandboxSignIn(sandbox, null);
        sandbox.revoke(other.refreshToken(), "refresh_token");
        NineException e = assertThrows(NineException.class, () -> sandbox.refresh(other));
        assertEquals("invalid_grant", e.error());
        String logout = sandbox.logoutUrl(other.idToken(), "http://127.0.0.1:8931/", null);
        assertTrue(logout.startsWith(sandboxIssuer + "/oauth/logout?"));
        assertEquals(other.idToken(), Live.query(logout).get("id_token_hint"));
    }

    @Test
    @Order(5)
    void refusesBadCallbacks() throws Exception {
        AuthClient client = AuthClient.builder().issuer(sandboxIssuer).clientId(spaClient).redirectUri(spaRedirect).build();
        Login login = client.createLogin();
        Live.Result result = Live.signIn(login.url(), spaRedirect, sandboxEmail, "x");
        String callback = result.callback();
        assertNotNull(callback);
        Map<String, String> q = Live.query(callback);
        assertEquals(sandboxIssuer, q.get("iss"));
        assertEquals("invalid_state", assertThrows(NineException.class, () -> client.handleCallback(callback.replace("state=", "state=forged"), login.pending())).error());
        assertEquals("invalid_issuer", assertThrows(NineException.class, () -> client.handleCallback(callback.replace("iss=", "iss=https%3A%2F%2Fevil.example&x="), login.pending())).error());
        assertEquals("access_denied", assertThrows(NineException.class, () -> client.handleCallback(spaRedirect + "?error=access_denied&state=" + login.pending().state(), login.pending())).error());
        assertEquals("invalid_state", assertThrows(NineException.class, () -> client.handleCallback(callback, null)).error());
        // The code was not spent by the refused attempts: the real callback still works.
        assertNotNull(client.handleCallback(callback, login.pending()).accessToken());
    }

    @Test
    @Order(6)
    void verifiesRealWebhookDeliveries() throws Exception {
        String sub = session.subject();
        String secret = env("WEBHOOK_SECRET");
        Map<String, Object> created = Live.waitFor("webhooks", r -> "user.created".equals(r.get("type")) && sub.equals(r.get("userId")));
        Map<String, Object> login = Live.waitFor("webhooks", r -> "user.login".equals(r.get("type")) && sub.equals(r.get("userId")));
        Duration window = Duration.ofMinutes(30); // recorded deliveries are replayed a little later
        WebhookEvent event = Webhooks.verify(Collections.singletonList(secret), bytes(created.get("raw")), (String) created.get("signature"), (String) created.get("path"), window);
        assertEquals("user.created", event.eventType());
        assertTrue(event.createdAt().matches("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"), event.createdAt());
        assertEquals(sub, event.user().get("id"));
        assertEquals(sandboxEmail, event.user().get("email"));
        assertEquals(env("TENANT_ID"), event.tenant());
        assertEquals("sandbox", event.environment());
        String raw = (String) login.get("raw");
        String sig = (String) login.get("signature");
        String path = (String) login.get("path");
        assertEquals(login.get("id"), Webhooks.verify(Arrays.asList("whsec_old", secret), bytes(raw), sig, path, window).id());
        assertThrows(SignatureException.class, () -> Webhooks.verify(Collections.singletonList("whsec_wrong"), bytes(raw), sig, path, window));
        assertThrows(SignatureException.class, () -> Webhooks.verify(Collections.singletonList(secret), bytes(raw.replace("user.login", "user.deleted")), sig, path, window));
        assertThrows(SignatureException.class, () -> Webhooks.verify(Collections.singletonList(secret), bytes(raw), sig, "/elsewhere", window));
        assertThrows(SignatureException.class, () -> Webhooks.verify(Collections.singletonList(secret), bytes(raw), null, path, window));
        assertThrows(SignatureException.class, () -> Webhooks.verify(Collections.singletonList(secret), "PUT", bytes(raw), sig, path, window, Clock.systemUTC()));
        // Too old: refused once the tolerance has passed (a clock moved forward).
        long t = Long.parseLong(sig.split(",")[0].substring(2));
        Clock late = Clock.fixed(Instant.ofEpochSecond(t + 301), ZoneOffset.UTC);
        Clock inTime = Clock.fixed(Instant.ofEpochSecond(t + 299), ZoneOffset.UTC);
        assertEquals(Signatures.Reason.EXPIRED, Signatures.check(Collections.singletonList(secret), sig, "POST", path, bytes(raw), null, late).reason());
        assertTrue(Signatures.check(Collections.singletonList(secret), sig, "POST", path, bytes(raw), null, inTime).ok());

        EventDeduplicator dedupe = new EventDeduplicator(new MemoryCache());
        int[] runs = {0};
        assertEquals(EventDeduplicator.Outcome.PROCESSED, dedupe.process(event.id(), () -> runs[0]++));
        assertEquals(EventDeduplicator.Outcome.DUPLICATE, dedupe.process(event.id(), () -> runs[0]++));
        assertEquals(1, runs[0]);
    }

    @Test
    @Order(7)
    void adapterSignInAndRealAdapterRequests() throws Exception {
        long since = System.currentTimeMillis();
        String redirect = env("ADAPTER_SPA_REDIRECT_URI");
        AuthClient client = AuthClient.builder().issuer(env("ADAPTER_ISSUER")).clientId(env("ADAPTER_SPA_CLIENT_ID")).redirectUri(redirect).build();
        Login login = client.createLogin();
        Live.Result result = Live.signIn(login.url(), redirect, "alice@adapter.e2e.test", "Alice-Password-1");
        assertNull(result.text());
        TokenSet tokens = client.handleCallback(result.callback(), login.pending());
        assertEquals("alice@adapter.e2e.test", tokens.claim("email"));
        assertEquals("Alice Adapter", tokens.claim("name"));
        Live.Result wrong = Live.signIn(client.createLogin().url(), redirect, "alice@adapter.e2e.test", "java-wrong-password");
        assertNull(wrong.callback());
        assertEquals(401, wrong.status);

        Map<String, Object> ok = Live.waitFor("adapter-raw", r -> ((Number) r.get("at")).longValue() >= since && ((String) r.get("path")).endsWith("/authenticate") && ((String) r.get("body")).contains("Alice-Password-1"));
        Map<String, Object> refused = Live.waitFor("adapter-raw", r -> ((Number) r.get("at")).longValue() >= since && ((String) r.get("path")).endsWith("/authenticate") && ((String) r.get("body")).contains("java-wrong-password"));
        String secret = env("ADAPTER_SECRET");
        AdapterHandler handler = new AdapterHandler(Collections.singletonList(secret), new Adapter() {
            @Override
            public AdapterUser authenticate(Identifier identifier, String password) {
                if (!identifier.value().equalsIgnoreCase("alice@adapter.e2e.test") || !"Alice-Password-1".equals(password)) return null;
                return AdapterUser.builder("ext_alice").email("alice@adapter.e2e.test").name("Alice Adapter").build();
            }

            @Override
            public AdapterUser findUser(UserQuery query) {
                return null;
            }
        }, Duration.ofMinutes(30), Clock.systemUTC());
        AdapterResponse response = handler.handle("POST", (String) ok.get("path"), headers(ok), (String) ok.get("body"));
        assertEquals(200, response.status());
        assertEquals("ext_alice", Json.object(Json.parseObject(response.bodyText()), "user").get("id"));
        assertTrue(Signatures.verify(secret, response.headers().get("9in-signature"), "POST", ok.get("path") + "#" + ok.get("requestId"), response.body()),
                "the response is signed over the request id");
        assertEquals(401, handler.handle("POST", (String) refused.get("path"), headers(refused), (String) refused.get("body")).status());
        assertEquals(401, handler.handle("POST", (String) ok.get("path"), headers(ok), ((String) ok.get("body")).replace("alice@", "bob@")).status());
        assertEquals(401, handler.handle("POST", "/elsewhere/authenticate", headers(ok), (String) ok.get("body")).status());
        assertEquals(405, handler.handle("GET", (String) ok.get("path"), headers(ok), (String) ok.get("body")).status());
        // With the default 5-minute window, a fresh recording is accepted too.
        AdapterHandler strict = new AdapterHandler(secret, new Adapter() {
            @Override
            public AdapterUser authenticate(Identifier identifier, String password) {
                return AdapterUser.builder("ext_alice").build();
            }

            @Override
            public AdapterUser findUser(UserQuery query) {
                return null;
            }
        });
        assertEquals(200, strict.handle("POST", (String) ok.get("path"), headers(ok), (String) ok.get("body")).status());
    }

    static Map<String, String> headers(Map<String, Object> record) {
        Map<String, String> h = new HashMap<>();
        h.put("9in-Signature", (String) record.get("signature"));
        h.put("9in-Request-Id", (String) record.get("requestId"));
        return h;
    }

    static byte[] bytes(Object s) {
        return ((String) s).getBytes(StandardCharsets.UTF_8);
    }

    // ---- production, confidential client ----

    AuthClient server(String audience, String... scopes) {
        AuthClient.Builder b = AuthClient.builder().issuer(issuer).clientId(serverClient).clientSecret(serverSecret).redirectUri(serverRedirect).audience(audience);
        if (scopes.length > 0) b.scopes(scopes);
        return b.build();
    }

    TokenSet serverSignIn(AuthClient auth, Live.Browser browser) throws Exception {
        Login login = auth.createLogin(LoginOptions.builder().returnTo("/account").build());
        Live.Result result = Live.signIn(browser, login.url(), serverRedirect, managedEmail, managedPassword);
        assertNull(result.text() == null ? null : result.text().substring(0, Math.min(300, result.text().length())));
        return auth.handleCallback(result.callback(), login.pending());
    }

    @Test
    @Order(10)
    void managesUsersThroughTheManagementApi() {
        assumeTrue(serverSecret != null, "SERVER_CLIENT_SECRET not set");
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("run", Live.RUN);
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("email", managedEmail);
        input.put("password", managedPassword);
        input.put("name", "Managed Java E2E");
        input.put("email_verified", true);
        input.put("metadata", meta);
        Map<String, Object> user = management.createUser(input);
        managedUserId = (String) user.get("id");
        assertEquals(managedEmail, user.get("email"));
        assertEquals(true, user.get("email_verified"));
        assertEquals(false, user.get("blocked"));
        assertEquals(meta, user.get("metadata"));
        assertEquals(managedEmail, Json.object(management.getUser(managedUserId), "user").get("email"));
        assertEquals(managedUserId, management.findUserByEmail(managedEmail.toUpperCase()).get("id"));
        List<String> ids = new ArrayList<>();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> page = (List<Map<String, Object>>) management.listUsers(Live.RUN, null, 5).get("users");
        for (Map<String, Object> u : page) ids.add((String) u.get("id"));
        assertTrue(ids.contains(managedUserId));
        Map<String, Object> rename = new HashMap<>();
        rename.put("name", "Renamed Java E2E");
        assertEquals("Renamed Java E2E", management.updateUser(managedUserId, rename).get("name"));
        assertEquals(Integer.valueOf(409), assertThrows(NineException.class, () -> management.createUser(input)).status());
        assertEquals(Integer.valueOf(404), assertThrows(NineException.class, () -> management.getUser("usr_doesnotexist000000")).status());
        assertNull(management.findUserByEmail("nobody-" + Live.RUN + "@e2e.9in.test"));
        assertNull(management.findUser("username", "nobody_" + Live.RUN));
    }

    @Test
    @Order(11)
    void blocksAndUnblocksSignIn() throws Exception {
        assumeTrue(managedUserId != null);
        assertEquals(true, management.blockUser(managedUserId).get("blocked"));
        Live.Result refused = Live.signIn(server(null).createLogin().url(), serverRedirect, managedEmail, managedPassword);
        assertNull(refused.callback());
        assertTrue(refused.text().toLowerCase().contains("blocked"), refused.text());
        assertEquals(false, management.unblockUser(managedUserId).get("blocked"));
    }

    @Test
    @Order(12)
    void signsInServerSideRefreshesAndRevokes() throws Exception {
        assumeTrue(managedUserId != null);
        AuthClient auth = server(api, "openid", "profile", "email", "offline_access", "read:things");
        TokenSet tokens = serverSignIn(auth, new Live.Browser());
        assertEquals("/account", tokens.returnTo());
        assertEquals(managedUserId, tokens.subject());
        assertEquals(managedEmail, tokens.claim("email"));
        assertEquals(serverClient, tokens.claim("aud"));
        assertEquals(managedEmail, auth.userInfo(tokens.accessToken()).get("email"));
        assertEquals(managedUserId, TokenVerifier.builder().issuer(issuer).audience(api).build().verify(tokens.accessToken(), "read:things").subject());

        assertSame(tokens, auth.ensureFresh(tokens, Duration.ofSeconds(60)));
        TokenSet refreshed = auth.ensureFresh(tokens.toBuilder().expiresAt(Instant.now()).build(), Duration.ofSeconds(60));
        assertNotEquals(tokens.refreshToken(), refreshed.refreshToken());
        assertEquals(refreshed.refreshToken(), auth.refresh(tokens).refreshToken());
        auth.revoke(refreshed.refreshToken(), "refresh_token");
        assertEquals("invalid_grant", assertThrows(NineException.class, () -> auth.refresh(refreshed)).error());
        assertEquals("invalid_grant", assertThrows(NineException.class, () -> auth.refresh(tokens)).error(), "revoking the family ends the grace too");
        assertTrue(auth.logoutUrl(refreshed.idToken(), null, null).startsWith(issuer + "/oauth/logout?"));
    }

    @Test
    @Order(13)
    void refusesForgedServerCallbacks() throws Exception {
        assumeTrue(managedUserId != null);
        AuthClient auth = server(null);
        Login login = auth.createLogin();
        Live.Result result = Live.signIn(login.url(), serverRedirect, managedEmail, managedPassword);
        String callback = result.callback();
        PendingLogin p = login.pending();
        PendingLogin otherState = new PendingLogin("other", p.nonce(), p.codeVerifier(), p.redirectUri(), null, p.createdAt());
        assertEquals("invalid_state", assertThrows(NineException.class, () -> auth.handleCallback(callback, otherState)).error());
        PendingLogin wrongNonce = new PendingLogin(p.state(), "wrong-nonce", p.codeVerifier(), p.redirectUri(), null, p.createdAt());
        // a second client instance, so the state isn't already marked as used
        assertEquals("invalid_id_token", assertThrows(NineException.class, () -> server(null).handleCallback(callback, wrongNonce)).error());
        // The code was spent by that exchange: replaying fails at the token endpoint.
        assertEquals("invalid_grant", assertThrows(NineException.class, () -> server(null).handleCallback(callback, p)).error());
    }

    @Test
    @Order(14)
    void clientCredentials() {
        assumeTrue(serverSecret != null);
        TokenSet set = server(null).clientCredentials(api, "read:things");
        assertNull(set.refreshToken());
        AccessTokenClaims claims = TokenVerifier.builder().issuer(issuer).audience(api).build().verify(set.accessToken(), "read:things");
        assertEquals(serverClient, claims.clientId());
    }

    @Test
    @Order(15)
    void loginLinksAndSilentSignIn() throws Exception {
        assumeTrue(managedUserId != null);
        Map<String, Object> link = management.createLoginLink(managedUserId, serverRedirect, 300);
        String url = (String) link.get("url");
        assertTrue(url.startsWith(issuer + "/"));
        assertTrue(Instant.parse((String) link.get("expires_at")).isAfter(Instant.now()));
        assertEquals(200, new Live.Browser().get(url).statusCode(), "a GET alone (a mail scanner) does not use the link up");
        Live.Browser browser = new Live.Browser();
        Live.Result landed = Live.openLoginLink(browser, url, serverRedirect);
        assertNull(landed.text());
        assertTrue(landed.callback().startsWith(serverRedirect));
        Live.Result reused = Live.openLoginLink(new Live.Browser(), url, serverRedirect);
        assertNull(reused.callback());
        assertEquals(400, reused.status);

        AuthClient auth = server(null);
        Login silent = auth.createLogin(LoginOptions.builder().prompt("none").build());
        Live.Result code = browser.follow(silent.url(), serverRedirect);
        assertNotNull(Live.query(code.callback()).get("code"));
        assertEquals(managedUserId, auth.handleCallback(code.callback(), silent.pending()).subject());

        assertTrue(management.revokeUserSessions(managedUserId) >= 1);
        Login after = auth.createLogin(LoginOptions.builder().prompt("none").build());
        Live.Result denied = browser.follow(after.url(), serverRedirect);
        assertEquals("login_required", Live.query(denied.callback()).get("error"));
        assertEquals("login_required", assertThrows(NineException.class, () -> auth.handleCallback(denied.callback(), after.pending())).error());
    }

    @Test
    @Order(16)
    void sessionsAndIntrospection() throws Exception {
        assumeTrue(managedUserId != null);
        AuthClient auth = server(api, "openid", "email", "offline_access", "read:things");
        TokenSet tokens = serverSignIn(auth, new Live.Browser());
        String sid = (String) tokens.claim("sid");
        Map<String, Object> mine = null;
        for (Map<String, Object> s : management.listUserSessions(managedUserId)) if (sid.equals(s.get("sid"))) mine = s;
        assertNotNull(mine);
        assertEquals(managedUserId, mine.get("user_id"));
        assertEquals(Collections.singletonList("pwd"), mine.get("amr"));
        assertTrue(((String) mine.get("auth_time")).endsWith("Z"));
        HybridTokenVerifier introspect = HybridTokenVerifier.builder().issuer(issuer).audience(api).clientId(serverClient).clientSecret(serverSecret)
                .mode(HybridTokenVerifier.Mode.INTROSPECT).build();
        assertEquals(sid, introspect.verify(tokens.accessToken()).sessionId());
        management.revokeSession(sid);
        for (Map<String, Object> s : management.listUserSessions(managedUserId)) assertNotEquals(sid, s.get("sid"));
        assertThrows(InvalidTokenException.class, () -> introspect.verify(tokens.accessToken()));
        assertEquals("invalid_grant", assertThrows(NineException.class, () -> auth.refresh(tokens)).error());
        assertEquals(Integer.valueOf(404), assertThrows(NineException.class, () -> management.revokeSession(sid)).status());
        assertEquals(managedUserId, management.findUser("email", managedEmail.toUpperCase()).get("id"));
    }

    @Test
    @Order(17)
    void hybridDropsARevokedTokenWhenTheWebhookArrives() throws Exception {
        assumeTrue(managedUserId != null);
        AuthClient auth = server(api, "openid", "email", "offline_access", "read:things");
        TokenSet tokens = serverSignIn(auth, new Live.Browser());
        HybridTokenVerifier hybrid = HybridTokenVerifier.builder().issuer(issuer).audience(api).clientId(serverClient).clientSecret(serverSecret).build();
        HybridTokenVerifier introspect = HybridTokenVerifier.builder().issuer(issuer).audience(api).clientId(serverClient).clientSecret(serverSecret)
                .mode(HybridTokenVerifier.Mode.INTROSPECT).build();
        TokenVerifier local = TokenVerifier.builder().issuer(issuer).audience(api).build();
        AccessTokenClaims claims = hybrid.verify(tokens.accessToken(), "read:things");
        assertEquals(managedUserId, claims.subject());
        assertThrows(InsufficientScopeException.class, () -> hybrid.verify(tokens.accessToken(), "write:things"));

        auth.revoke(tokens.accessToken(), "access_token");
        assertThrows(InvalidTokenException.class, () -> introspect.verify(tokens.accessToken()));
        assertEquals(managedUserId, local.verify(tokens.accessToken()).subject(), "local mode: valid until it expires");
        assertEquals(managedUserId, hybrid.verify(tokens.accessToken()).subject(), "cached answer until 9in tells us");

        String jti = claims.tokenId();
        Map<String, Object> revoked = Live.waitFor("webhooks", r -> "token.revoked".equals(r.get("type")) && "production".equals(r.get("environment"))
                && r.get("raw") instanceof String && ((String) r.get("raw")).contains(jti));
        WebhookEvent event = Webhooks.verify(Collections.singletonList(env("WEBHOOK_SECRET")), bytes(revoked.get("raw")), (String) revoked.get("signature"),
                (String) revoked.get("path"), Duration.ofMinutes(30));
        assertTrue(hybrid.handleEvent(event));
        assertThrows(InvalidTokenException.class, () -> hybrid.verify(tokens.accessToken()));
    }

    @Test
    @Order(18)
    void opaqueAccessTokensAreIntrospected() throws Exception {
        assumeTrue(managedUserId != null);
        String opaque = env("OPAQUE_API_AUDIENCE");
        AuthClient auth = server(opaque, "openid", "offline_access");
        TokenSet tokens = serverSignIn(auth, new Live.Browser());
        assertTrue(tokens.accessToken().startsWith("9in_at_"));
        HybridTokenVerifier hybrid = HybridTokenVerifier.builder().issuer(issuer).audience(opaque).clientId(serverClient).clientSecret(serverSecret).build();
        assertEquals(managedUserId, hybrid.verify(tokens.accessToken()).subject());
        assertThrows(InvalidTokenException.class, () -> HybridTokenVerifier.builder().issuer(issuer).audience(opaque).mode(HybridTokenVerifier.Mode.LOCAL).build().verify(tokens.accessToken()));
        assertThrows(InvalidTokenException.class, () -> HybridTokenVerifier.builder().issuer(issuer).audience(api).clientId(serverClient).clientSecret(serverSecret).build().verify(tokens.accessToken()));
        assertThrows(InvalidTokenException.class, () -> TokenVerifier.builder().issuer(issuer).build().verify(tokens.accessToken()));
    }

    @Test
    @Order(19)
    void refusesAWrongClientSecret() {
        assumeTrue(serverSecret != null);
        ManagementClient wrong = ManagementClient.builder().issuer(issuer).clientId(serverClient).clientSecret("not-the-secret").build();
        assertEquals("invalid_client", assertThrows(NineException.class, wrong::listUsers).error());
        AuthClient wrongAuth = AuthClient.builder().issuer(issuer).clientId(serverClient).clientSecret("not-the-secret").build();
        assertEquals("invalid_client", assertThrows(NineException.class, () -> wrongAuth.clientCredentials(null, null)).error());
    }
}
