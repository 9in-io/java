package io.ninein.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.AccessTokenClaims;
import io.ninein.HybridTokenVerifier;
import io.ninein.MemoryCache;
import io.ninein.Signatures;
import io.ninein.TokenVerifier;
import io.ninein.WebhookEvent;
import io.ninein.adapter.Adapter;
import io.ninein.adapter.AdapterHandler;
import io.ninein.adapter.AdapterUser;
import io.ninein.adapter.Identifier;
import io.ninein.adapter.UserQuery;
import io.ninein.testing.FakeNine;
import io.ninein.testing.Jwts;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The servlet helpers in a real servlet container (embedded Tomcat). */
class ServletTest {
    static final String API = "https://api.example.com";
    static final String ADAPTER_SECRET = "adapter-secret";
    static final String WEBHOOK_SECRET = "webhook-secret";

    static Tomcat tomcat;
    static String base;
    static FakeNine nine;
    static final List<WebhookEvent> received = new CopyOnWriteArrayList<>();
    static final AtomicBoolean failNext = new AtomicBoolean();
    static final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    @SuppressWarnings("deprecation")
    static void start() throws Exception {
        nine = new FakeNine();
        TokenVerifier verifier = TokenVerifier.builder().issuer(nine.issuer).audience(API).transport(nine).build();
        HybridTokenVerifier hybrid = HybridTokenVerifier.builder().issuer(nine.issuer).transport(nine).build();

        File dir = Files.createTempDirectory("nine-tomcat").toFile();
        tomcat = new Tomcat();
        tomcat.setBaseDir(dir.getAbsolutePath());
        tomcat.setPort(0);
        Context ctx = tomcat.addContext("/app", dir.getAbsolutePath());

        Tomcat.addServlet(ctx, "api", new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
                AccessTokenClaims claims = BearerTokenFilter.claims(req);
                res.setContentType("text/plain");
                res.getWriter().write(claims.subject() + "|" + req.getUserPrincipal().getName() + "|" + req.isUserInRole("orders:read") + "|" + req.isUserInRole("admin"));
            }
        });
        ctx.addServletMappingDecoded("/api/*", "api");
        FilterDef def = new FilterDef();
        def.setFilterName("nine");
        def.setFilter(new BearerTokenFilter(verifier, "orders:read"));
        ctx.addFilterDef(def);
        FilterMap map = new FilterMap();
        map.setFilterName("nine");
        map.addURLPattern("/api/*");
        ctx.addFilterMap(map);

        // An API whose issuer is down: the filter answers 503, not 401.
        FakeNine down = new FakeNine("https://down.9in.io");
        down.on("GET", "/.well-known/jwks.json", r -> FakeNine.json(500, null));
        Tomcat.addServlet(ctx, "down", new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse res) {
                res.setStatus(200);
            }
        });
        ctx.addServletMappingDecoded("/down/*", "down");
        FilterDef downDef = new FilterDef();
        downDef.setFilterName("nine-down");
        downDef.setFilter(new BearerTokenFilter(TokenVerifier.builder().issuer(down.issuer).transport(down).build()));
        ctx.addFilterDef(downDef);
        FilterMap downMap = new FilterMap();
        downMap.setFilterName("nine-down");
        downMap.addURLPattern("/down/*");
        ctx.addFilterMap(downMap);

        Tomcat.addServlet(ctx, "adapter", new AdapterServlet(new AdapterHandler(ADAPTER_SECRET, new Adapter() {
            @Override
            public AdapterUser authenticate(Identifier identifier, String password) {
                return "hunter2".equals(password) ? AdapterUser.builder("42").email(identifier.value()).build() : null;
            }

            @Override
            public AdapterUser findUser(UserQuery query) {
                return null;
            }
        })));
        ctx.addServletMappingDecoded("/nine/*", "adapter");

        Tomcat.addServlet(ctx, "webhook", WebhookServlet.builder(WEBHOOK_SECRET)
                .dedupe(new MemoryCache())
                .verifier(hybrid)
                .handler(event -> {
                    if (failNext.getAndSet(false)) throw new IllegalStateException("handler failed");
                    received.add(event);
                })
                .build());
        ctx.addServletMappingDecoded("/hooks/nine", "webhook");

        tomcat.getConnector();
        tomcat.start();
        base = "http://127.0.0.1:" + tomcat.getConnector().getLocalPort() + "/app";
    }

    @AfterAll
    static void stop() throws Exception {
        tomcat.stop();
        tomcat.destroy();
    }

    static String token(String scope) {
        long now = System.currentTimeMillis() / 1000;
        return Jwts.sign("ES256", "at+jwt", Jwts.claims().with("iss", nine.issuer).with("sub", "usr_7").with("aud", API)
                .with("scope", scope).with("iat", now).with("exp", now + 300));
    }

    static HttpResponse<String> get(String path, String authorization) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
        if (authorization != null) b.header("Authorization", authorization);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static HttpResponse<String> post(String path, String body, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).POST(HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void bearerFilter() throws Exception {
        HttpResponse<String> ok = get("/api/orders", "Bearer " + token("orders:read"));
        assertEquals(200, ok.statusCode());
        assertEquals("usr_7|usr_7|true|false", ok.body());

        HttpResponse<String> missing = get("/api/orders", null);
        assertEquals(401, missing.statusCode());
        assertEquals("Bearer realm=\"9in\"", missing.headers().firstValue("WWW-Authenticate").orElse(""));
        assertTrue(missing.body().contains("\"error\":\"invalid_token\""));

        HttpResponse<String> basic = get("/api/orders", "Basic dXNlcjpwdw==");
        assertEquals(400, basic.statusCode());

        HttpResponse<String> invalid = get("/api/orders", "Bearer not.a.jwt");
        assertEquals(401, invalid.statusCode());
        assertTrue(invalid.headers().firstValue("WWW-Authenticate").orElse("").contains("error=\"invalid_token\""));
        assertEquals("no-store", invalid.headers().firstValue("Cache-Control").orElse(""));

        HttpResponse<String> scope = get("/api/orders", "Bearer " + token("profile"));
        assertEquals(403, scope.statusCode());
        String challenge = scope.headers().firstValue("WWW-Authenticate").orElse("");
        assertTrue(challenge.contains("error=\"insufficient_scope\"") && challenge.contains("scope=\"orders:read\""), challenge);
    }

    @Test
    void bearerFilterAnswers503WhenKeysCannotBeFetched() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String t = Jwts.sign("RS256", "at+jwt", Jwts.claims().with("iss", "https://down.9in.io").with("sub", "u").with("exp", now + 60));
        HttpResponse<String> r = get("/down/x", "Bearer " + t);
        assertEquals(503, r.statusCode());
        assertTrue(r.body().contains("temporarily_unavailable"));
    }

    @Test
    void adapterServletUsesTheRawRequestPath() throws Exception {
        String path = "/app/nine/authenticate";
        String body = "{\"identifier\":{\"type\":\"email\",\"value\":\"alice@acme.com\"},\"password\":\"hunter2\"}";
        HttpResponse<String> r = post("/nine/authenticate", body, "9in-signature", Signatures.sign(ADAPTER_SECRET, "POST", path, body), "9in-request-id", "req_9");
        assertEquals(200, r.statusCode());
        assertTrue(r.body().contains("\"id\":\"42\""));
        String sig = r.headers().firstValue("9in-signature").orElse(null);
        assertTrue(Signatures.verify(ADAPTER_SECRET, sig, "POST", path + "#req_9", r.body()));
        HttpResponse<String> unsigned = post("/nine/authenticate", body);
        assertEquals(401, unsigned.statusCode());
        HttpResponse<String> getIt = get("/nine/authenticate", null);
        assertEquals(405, getIt.statusCode());
    }

    @Test
    void webhookServlet() throws Exception {
        String path = "/app/hooks/nine";
        String body = "{\"id\":\"evt_s1\",\"event_type\":\"user.created\",\"created_at\":\"2026-11-22T10:00:00.000Z\",\"tenant\":\"t\",\"environment\":\"sandbox\",\"data\":{\"user\":{\"id\":\"u\"}}}";
        String sig = Signatures.sign(WEBHOOK_SECRET, "POST", path, body);
        assertEquals(204, post("/hooks/nine", body, "9in-signature", sig).statusCode());
        assertEquals(204, post("/hooks/nine", body, "9in-signature", sig).statusCode(), "duplicate");
        assertEquals(1, received.stream().filter(e -> e.id().equals("evt_s1")).count());

        assertEquals(401, post("/hooks/nine", body, "9in-signature", Signatures.sign("wrong", "POST", path, body)).statusCode());
        assertEquals(401, post("/hooks/nine", body).statusCode());
        String notEvent = "{\"hello\":1}";
        assertEquals(400, post("/hooks/nine", notEvent, "9in-signature", Signatures.sign(WEBHOOK_SECRET, "POST", path, notEvent)).statusCode());
        assertEquals(405, get("/hooks/nine", null).statusCode());

        // a failing handler answers 500 and releases the event, so the retry is processed
        String body2 = body.replace("evt_s1", "evt_s2");
        String sig2 = Signatures.sign(WEBHOOK_SECRET, "POST", path, body2);
        failNext.set(true);
        assertEquals(500, post("/hooks/nine", body2, "9in-signature", sig2).statusCode());
        assertEquals(204, post("/hooks/nine", body2, "9in-signature", sig2).statusCode());
        assertEquals(1, received.stream().filter(e -> e.id().equals("evt_s2")).count());
    }
}
