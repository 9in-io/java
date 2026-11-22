package example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.ninein.AccessTokenClaims;
import io.ninein.AuthClient;
import io.ninein.EventDeduplicator;
import io.ninein.HybridTokenVerifier;
import io.ninein.InsufficientScopeException;
import io.ninein.Login;
import io.ninein.LoginOptions;
import io.ninein.MemoryCache;
import io.ninein.NineException;
import io.ninein.PendingLogin;
import io.ninein.TokenSet;
import io.ninein.WebhookEvent;
import io.ninein.Webhooks;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Sign-in, sign-out, a protected API and webhooks with the 9in Java SDK on the JDK's HTTP server. */
public final class WebApp {
    private final AuthClient auth = AuthClient.fromEnv();   // NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_REDIRECT_URI
    private final HybridTokenVerifier api = System.getenv("NINE_API_AUDIENCE") == null ? null : HybridTokenVerifier.fromEnv();
    private final List<String> webhookSecrets = Webhooks.secretsFromEnv();
    private final EventDeduplicator dedupe = new EventDeduplicator(new MemoryCache());
    private final Sessions sessions = new Sessions();

    public static void main(String[] args) throws IOException {
        new WebApp().start();
    }

    void start() throws IOException {
        URI redirect = URI.create(auth.redirectUri());
        HttpServer server = HttpServer.create(new InetSocketAddress(redirect.getHost(), redirect.getPort()), 0);
        server.createContext("/", this::home);
        server.createContext("/nine/login", ex -> login(ex, null));
        server.createContext("/nine/signup", ex -> login(ex, "signup"));
        server.createContext(redirect.getPath(), this::callback);
        server.createContext("/nine/logout", this::logout);
        server.createContext("/api/me", this::apiMe);
        server.createContext("/nine/webhook", this::webhook);
        server.start();
        System.out.println("Listening on http://" + redirect.getHost() + ":" + redirect.getPort() + "/");
    }

    void home(HttpExchange ex) throws IOException {
        if (!ex.getRequestURI().getPath().equals("/")) {
            send(ex, 404, "text/plain", "Not found");
            return;
        }
        Map<String, String> session = sessions.get(ex);
        String stored = session.get("tokens");
        if (stored == null) {
            send(ex, 200, "text/html", "<h1>9in example</h1><p><a href=\"/nine/login\">Sign in</a> or <a href=\"/nine/signup\">sign up</a></p>");
            return;
        }
        TokenSet tokens = TokenSet.fromJson(stored);
        try {
            TokenSet fresh = auth.ensureFresh(tokens, Duration.ofSeconds(60));   // refreshed (and rotated) near expiry
            if (fresh != tokens) session.put("tokens", fresh.toJson());
            tokens = fresh;
        } catch (NineException e) {                                          // e.g. invalid_grant: revoked
            session.clear();
            redirect(ex, "/");
            return;
        }
        send(ex, 200, "text/html", "<h1>Signed in</h1><p>User <code>" + html(tokens.subject()) + "</code>, email <code>"
                + html(String.valueOf(tokens.claim("email"))) + "</code></p><p><a href=\"/nine/logout\">Sign out</a></p>");
    }

    void login(HttpExchange ex, String screen) throws IOException {
        Login login = auth.createLogin(LoginOptions.builder().returnTo("/").screen(screen).build());
        sessions.get(ex).put("pending", login.pending().toJson());
        redirect(ex, login.url());
    }

    void callback(HttpExchange ex) throws IOException {
        Map<String, String> session = sessions.get(ex);
        String pending = session.remove("pending");                   // each sign-in is used once
        try {
            TokenSet tokens = auth.handleCallback(ex.getRequestURI().toString(), pending == null ? null : PendingLogin.fromJson(pending));
            sessions.renew(ex).put("tokens", tokens.toJson());        // a new session id after sign-in
            redirect(ex, tokens.returnTo() != null ? tokens.returnTo() : "/");
        } catch (NineException e) {
            send(ex, 400, "text/html", "<h1>Sign-in failed</h1><p>" + html(e.error()) + ": " + html(e.description()) + "</p><p><a href=\"/\">Back</a></p>");
        }
    }

    void logout(HttpExchange ex) throws IOException {
        Map<String, String> session = sessions.get(ex);
        String stored = session.get("tokens");
        session.clear();
        if (stored == null) {
            redirect(ex, "/");
            return;
        }
        TokenSet tokens = TokenSet.fromJson(stored);
        try {
            auth.revoke(tokens.refreshToken(), "refresh_token");
        } catch (NineException e) {
            System.err.println("revocation failed: " + e.error());
        }
        URI redirect = URI.create(auth.redirectUri());
        redirect(ex, auth.logoutUrl(tokens.idToken(), redirect.getScheme() + "://" + redirect.getRawAuthority() + "/", null));
    }

    void apiMe(HttpExchange ex) throws IOException {
        if (api == null) {
            send(ex, 404, "application/json", "{\"error\":\"set NINE_API_AUDIENCE\"}");
            return;
        }
        try {
            AccessTokenClaims claims = api.verify(ex.getRequestHeaders().getFirst("Authorization"));
            send(ex, 200, "application/json", "{\"sub\":\"" + json(claims.subject()) + "\",\"client_id\":\"" + json(claims.clientId()) + "\"}");
        } catch (InsufficientScopeException e) {
            send(ex, 403, "application/json", "{\"error\":\"insufficient_scope\"}");
        } catch (NineException e) {
            boolean tokenProblem = e.status() != null && e.status() == 401;
            if (tokenProblem) ex.getResponseHeaders().set("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            send(ex, tokenProblem ? 401 : 503, "application/json", "{\"error\":\"" + json(e.error()) + "\"}");
        }
    }

    void webhook(HttpExchange ex) throws IOException {
        if (webhookSecrets.isEmpty()) {
            send(ex, 404, "text/plain", "set NINE_WEBHOOK_SECRET");
            return;
        }
        byte[] body = readAll(ex.getRequestBody());
        WebhookEvent event;
        try {
            event = Webhooks.verify(webhookSecrets, ex.getRequestMethod(), body, ex.getRequestHeaders().getFirst("9in-signature"),
                    ex.getRequestURI().getRawPath(), null, java.time.Clock.systemUTC());
        } catch (NineException e) {
            send(ex, e.status() == null ? 400 : e.status(), "application/json", "{\"error\":\"" + json(e.error()) + "\"}");
            return;
        }
        EventDeduplicator.Outcome outcome = dedupe.process(event.id(), () -> {
            if (api != null) api.handleEvent(event);           // revoked tokens stop working at once
            System.out.println("webhook " + event.eventType() + " " + event.id());
        });
        send(ex, outcome.httpStatus(), "text/plain", "");
    }

    // ---- small helpers ----

    static void redirect(HttpExchange ex, String location) throws IOException {
        ex.getResponseHeaders().set("Location", location);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    static void send(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (!type.isEmpty()) ex.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) ex.getResponseBody().write(bytes);
        ex.close();
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        for (int n; (n = in.read(buf)) != -1; ) out.write(buf, 0, n);
        return out.toByteArray();
    }

    static String html(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String json(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** In-memory sessions behind an HttpOnly, SameSite=Lax cookie. */
    static final class Sessions {
        private final Map<String, Map<String, String>> store = new ConcurrentHashMap<>();
        private final SecureRandom random = new SecureRandom();

        Map<String, String> get(HttpExchange ex) {
            String id = cookie(ex);
            Map<String, String> session = id == null ? null : store.get(id);
            return session != null ? session : renew(ex);
        }

        Map<String, String> renew(HttpExchange ex) {
            String old = cookie(ex);
            Map<String, String> session = new ConcurrentHashMap<>();
            if (old != null) {
                Map<String, String> previous = store.remove(old);
                if (previous != null) session.putAll(previous);
            }
            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            String id = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            store.put(id, session);
            ex.getResponseHeaders().add("Set-Cookie", "sid=" + id + "; Path=/; HttpOnly; SameSite=Lax");
            return session;
        }

        private static String cookie(HttpExchange ex) {
            List<String> headers = ex.getRequestHeaders().get("Cookie");
            if (headers == null) return null;
            for (String header : headers) {
                for (String part : header.split(";")) {
                    String p = part.trim();
                    if (p.startsWith("sid=")) return p.substring(4);
                }
            }
            return null;
        }
    }
}
