package io.ninein;

import io.ninein.http.HttpRequest;
import io.ninein.http.HttpResponse;
import io.ninein.http.HttpTransport;
import io.ninein.http.UrlConnectionTransport;
import io.ninein.internal.Codec;
import io.ninein.internal.Env;
import io.ninein.internal.Issuers;
import io.ninein.internal.Json;
import io.ninein.internal.Jwt;
import io.ninein.internal.Tenant;
import io.ninein.internal.TokenChecks;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Sign-in with 9in for any OAuth client: confidential (server-side apps, with a client secret
 * sent as HTTP Basic) or public (mobile, desktop and CLI apps: PKCE only). Authorization code
 * flow with PKCE S256 and endpoints from OIDC discovery; single-use {@code state} compared in
 * constant time; {@code nonce}; the RFC 9207 {@code iss} callback parameter; ID tokens verified
 * against the tenant's JWKS (signature, {@code iss}, {@code aud}/{@code azp}, {@code exp}/{@code iat},
 * {@code nonce}); refresh-token rotation; revocation, RP-initiated logout, userinfo, client
 * credentials and the device authorization flow (RFC 8628).
 *
 * <pre>{@code
 * AuthClient auth = AuthClient.builder()
 *     .issuer("https://acme.9in.io")
 *     .clientId("app_...")
 *     .clientSecret(System.getenv("NINE_CLIENT_SECRET"))   // omit for public clients
 *     .redirectUri("https://app.acme.com/nine/callback")
 *     .build();
 *
 * Login login = auth.createLogin(LoginOptions.builder().returnTo("/dashboard").build());
 * session.put("nine.pending", login.pending().toJson());     // keep it until the callback
 * response.sendRedirect(login.url());
 *
 * // on /nine/callback
 * TokenSet tokens = auth.handleCallback(requestUrl, PendingLogin.fromJson(session.remove("nine.pending")));
 * }</pre>
 *
 * <p><b>ID token signatures and public clients.</b> ID tokens are always checked for {@code iss},
 * {@code aud} ({@code azp} with several audiences), {@code exp}, {@code iat} and {@code nonce}, and
 * their signature is verified against the JWKS for every algorithm the runtime supports. A public
 * client receives the ID token straight from the token endpoint over TLS, so when the runtime
 * cannot verify the algorithm (EdDSA before Java 15, or on older Android) the claim checks alone
 * are accepted, as OpenID Connect Core 3.1.3.7 permits; for a confidential client that is an
 * {@code unsupported_algorithm} error.
 *
 * <p>Immutable and thread-safe; build one per application and share it. Discovery and the JWKS
 * are cached. Errors are {@link NineException}s.
 */
public final class AuthClient {
    static final Duration DEFAULT_LEEWAY = Duration.ofSeconds(30);
    static final Duration DEFAULT_LOGIN_TIMEOUT = Duration.ofMinutes(15);
    private static final Set<String> RESERVED = new HashSet<>(Arrays.asList(
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"));
    private static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /** Waits between device-flow polls (replaced in tests). */
    interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final List<String> scopes;
    private final String audience;
    private final Clock clock;
    private final Duration leeway;
    private final Duration loginTimeout;
    private final Tenant tenant;
    private final Sleeper sleeper;
    private final Map<String, Instant> usedStates = new LinkedHashMap<String, Instant>(64, 0.75f, false) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Instant> eldest) {
            return size() > 10_000;
        }
    };

    private AuthClient(Builder b) {
        if (b.clientId == null || b.clientId.isEmpty()) throw new NineException("invalid_options", "clientId is required");
        boolean insecure = b.allowInsecureIssuer || Issuers.insecureAllowedByEnv();
        this.issuer = Issuers.normalize(b.issuer, insecure);
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret == null || b.clientSecret.isEmpty() ? null : b.clientSecret;
        this.redirectUri = b.redirectUri == null || b.redirectUri.isEmpty() ? null : b.redirectUri;
        List<String> s = TokenChecks.scopes(b.scopes);
        if (s.isEmpty()) throw new NineException("invalid_options", "at least one scope is required");
        this.scopes = Collections.unmodifiableList(s);
        this.audience = b.audience == null || b.audience.isEmpty() ? null : b.audience;
        this.clock = b.clock == null ? Clock.systemUTC() : b.clock;
        this.leeway = b.leeway == null ? DEFAULT_LEEWAY : b.leeway;
        this.loginTimeout = b.loginTimeout == null ? DEFAULT_LOGIN_TIMEOUT : b.loginTimeout;
        HttpTransport transport = b.transport == null ? new UrlConnectionTransport() : b.transport;
        this.tenant = new Tenant(issuer, transport, clock);
        this.sleeper = b.sleeper == null ? new Sleeper() {
            @Override
            public void sleep(Duration duration) throws InterruptedException {
                Thread.sleep(duration.toMillis());
            }
        } : b.sleeper;
    }

    /** A builder; {@code issuer} and {@code clientId} are required. */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A client from the environment: {@code NINE_ISSUER}, {@code NINE_CLIENT_ID},
     * {@code NINE_CLIENT_SECRET}, {@code NINE_REDIRECT_URI}, {@code NINE_AUDIENCE}, and optionally
     * {@code NINE_SCOPES} and {@code NINE_ALLOW_INSECURE_ISSUER}.
     */
    public static AuthClient fromEnv() {
        return fromEnv(System.getenv());
    }

    /** As {@link #fromEnv()}, from the given map (e.g. a test environment or your own settings). */
    public static AuthClient fromEnv(Map<String, String> env) {
        return builder().env(env).build();
    }

    /** The issuer, normalised (no trailing slash). */
    public String issuer() {
        return issuer;
    }

    public String clientId() {
        return clientId;
    }

    /** True with a client secret (confidential client), false for a public client. */
    public boolean isConfidential() {
        return clientSecret != null;
    }

    /** The configured redirect URI, or null. */
    public String redirectUri() {
        return redirectUri;
    }

    /** The scopes asked for at sign-in. */
    public List<String> scopes() {
        return scopes;
    }

    /** The tenant's OpenID Connect metadata (fetched once and cached for an hour). */
    public Discovery discovery() {
        return tenant.discovery();
    }

    /** Starts a sign-in with the default options. */
    public Login createLogin() {
        return createLogin(LoginOptions.defaults());
    }

    /**
     * Starts a sign-in: the authorization URL to send the browser to, and the pending login to
     * keep until the callback. {@code screen("signup")} opens the sign-up form.
     */
    public Login createLogin(LoginOptions options) {
        LoginOptions o = options == null ? LoginOptions.defaults() : options;
        String redirect = o.redirectUri() != null ? o.redirectUri() : redirectUri;
        if (redirect == null) throw new NineException("invalid_options", "redirectUri is required (on the builder or in LoginOptions)");
        Discovery config = tenant.discovery();
        String authorize = config.authorizationEndpoint();
        if (authorize == null) throw new NineException("discovery_failed", "the discovery document has no authorization_endpoint");

        PendingLogin pending = new PendingLogin(
                Codec.randomString(32), Codec.randomString(32), Codec.randomString(48), redirect, safeReturnTo(o.returnTo()), clock.instant());

        Map<String, String> params = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : o.extra().entrySet()) {
            if (e.getKey() != null && e.getValue() != null && !RESERVED.contains(e.getKey())) params.put(e.getKey(), e.getValue());
        }
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("redirect_uri", redirect);
        params.put("scope", String.join(" ", scopes));
        params.put("state", pending.state());
        params.put("nonce", pending.nonce());
        params.put("code_challenge", codeChallenge(pending.codeVerifier()));
        params.put("code_challenge_method", "S256");
        if (audience != null) params.put("audience", audience);
        String prompt = "signup".equals(o.screen()) ? "create" : o.prompt();
        if (prompt != null && !prompt.isEmpty()) params.put("prompt", prompt);
        if (o.loginHint() != null && !o.loginHint().isEmpty()) params.put("login_hint", o.loginHint());
        if (o.locale() != null && !o.locale().isEmpty()) params.put("ui_locales", o.locale());
        return new Login(Codec.appendQuery(authorize, params), pending);
    }

    /**
     * Finishes a sign-in on the callback URL: rejects an {@code error} answer (as a
     * {@link NineException} with the server's code, e.g. {@code access_denied}), checks the
     * {@code state} against the pending login (constant time; {@code invalid_state} when it is
     * missing, different or older than the login timeout), checks the RFC 9207 {@code iss}
     * parameter, exchanges the code with the PKCE verifier and verifies the ID token.
     *
     * <p>Use each pending login once: remove it from the session before calling this.
     *
     * @param callbackUrl the full callback URL (or just its query string)
     * @param pending what {@link #createLogin} returned, or null when there is none
     */
    public TokenSet handleCallback(String callbackUrl, PendingLogin pending) {
        Map<String, String> query = Codec.parseQuery(queryOf(callbackUrl));
        String error = query.get("error");
        if (error != null && !error.isEmpty()) {
            String description = query.get("error_description");
            throw new NineException(error, description == null ? error : description, 400);
        }
        if (pending == null) throw new NineException("invalid_state", "no sign-in in progress (it expired, or started in another browser)", 400);
        if (clock.instant().isAfter(pending.createdAt().plus(loginTimeout))) {
            throw new NineException("invalid_state", "the sign-in took too long; start again", 400);
        }
        String state = query.get("state");
        if (state == null || !Codec.constantTimeEquals(state, pending.state())) throw new NineException("invalid_state", "state mismatch", 400);

        Discovery config = tenant.discovery();
        String iss = query.get("iss");
        if (iss != null) {
            if (!Issuers.same(iss, issuer)) throw new NineException("invalid_issuer", "unexpected issuer " + iss, 400);
        } else if (config.authorizationResponseIssParameterSupported()) {
            throw new NineException("invalid_issuer", "the callback has no iss parameter", 400);
        }
        String code = query.get("code");
        if (code == null || code.isEmpty()) throw new NineException("missing_code", "no authorization code in the callback", 400);

        rememberState(pending); // only now: a callback refused above doesn't use the sign-in up
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", pending.redirectUri() != null ? pending.redirectUri() : redirectUri);
        form.put("code_verifier", pending.codeVerifier());
        Map<String, Object> json = tokenRequest(form);

        String idToken = Json.string(json, "id_token");
        Map<String, Object> claims = Collections.emptyMap();
        if (idToken != null) {
            claims = verifyIdToken(idToken, pending.nonce(), null);
        } else if (scopes.contains("openid")) {
            throw new NineException("invalid_id_token", "no ID token in the token response", 401);
        }
        return tokenSet(json, null, claims, safeReturnTo(pending.returnTo()));
    }

    /**
     * New tokens from the refresh token in {@code tokens}. 9in rotates refresh tokens: keep the
     * returned set (it holds the new refresh token; the old one is kept only when none is
     * returned). Throws {@code login_required} without a refresh token and {@code invalid_grant}
     * when it was revoked or reused.
     */
    public TokenSet refresh(TokenSet tokens) {
        if (tokens == null || tokens.refreshToken() == null) throw new NineException("login_required", "no refresh token");
        return refreshWith(tokens.refreshToken(), tokens);
    }

    /** New tokens from a refresh token (see {@link #refresh(TokenSet)}). */
    public TokenSet refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) throw new NineException("login_required", "no refresh token");
        return refreshWith(refreshToken, null);
    }

    /** {@code tokens} itself while the access token is valid for longer than {@code leeway}, else refreshed tokens. */
    public TokenSet ensureFresh(TokenSet tokens, Duration leeway) {
        if (tokens == null) throw new NineException("login_required", "not signed in");
        if (!tokens.isExpired(leeway == null ? Duration.ofSeconds(60) : leeway, clock)) return tokens;
        return refresh(tokens);
    }

    /** The user's current claims from the userinfo endpoint ({@code invalid_token} when the token is refused). */
    public Map<String, Object> userInfo(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) throw new NineException("invalid_token", "missing access token", 401);
        String endpoint = tenant.endpoint(tenant.discovery().userinfoEndpoint(), "/oauth/userinfo");
        HttpResponse response = tenant.send(HttpRequest.builder()
                .method("GET")
                .url(endpoint)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .build());
        if (response.status() == 401) throw new NineException("invalid_token", "the access token was refused", 401);
        return Collections.unmodifiableMap(Tenant.jsonOrThrow(response, "userinfo_failed"));
    }

    /**
     * Revokes a refresh token (and its rotation family) or an access token. 9in answers 200 for
     * unknown or already revoked tokens, so an error here (e.g. {@code invalid_client}) is real.
     *
     * @param tokenTypeHint {@code "refresh_token"} (default when null) or {@code "access_token"}
     */
    public void revoke(String token, String tokenTypeHint) {
        if (token == null || token.isEmpty()) return;
        String endpoint = tenant.discovery().revocationEndpoint();
        if (endpoint == null) return;
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        form.put("token_type_hint", tokenTypeHint == null ? "refresh_token" : tokenTypeHint);
        Map<String, String> headers = clientAuth(form);
        tenant.postForm(endpoint, form, headers, "revocation_failed");
    }

    /**
     * The URL that ends the 9in session (RP-initiated logout) and comes back to
     * {@code postLogoutRedirectUri}, which must be one of the application's logout URLs.
     */
    public String logoutUrl(String idTokenHint, String postLogoutRedirectUri, String state) {
        String endpoint = tenant.endpoint(tenant.discovery().endSessionEndpoint(), "/oauth/logout");
        Map<String, String> params = new LinkedHashMap<>();
        params.put("client_id", clientId);
        if (idTokenHint != null && !idTokenHint.isEmpty()) params.put("id_token_hint", idTokenHint);
        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isEmpty()) params.put("post_logout_redirect_uri", postLogoutRedirectUri);
        if (state != null && !state.isEmpty()) params.put("state", state);
        return Codec.appendQuery(endpoint, params);
    }

    /**
     * An access token for your own back end (client credentials grant; confidential clients only).
     *
     * @param audience the API identifier, or null for the default
     * @param scope space-separated scopes, or null
     */
    public TokenSet clientCredentials(String audience, String scope) {
        if (clientSecret == null) throw new NineException("invalid_options", "client credentials need a confidential client (a client secret)");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        if (audience != null && !audience.isEmpty()) form.put("audience", audience);
        if (scope != null && !scope.isEmpty()) form.put("scope", scope);
        return tokenSet(tokenRequest(form), null, Collections.<String, Object>emptyMap(), null);
    }

    /**
     * Starts the device authorization flow (RFC 8628) for TVs, CLIs and devices without a browser.
     * Show the user code and verification URI, then call {@link #pollDeviceAuthorization}.
     *
     * @param scope space-separated scopes, or null for the client's scopes
     */
    public DeviceAuthorization startDeviceAuthorization(String scope) {
        String endpoint = tenant.endpoint(tenant.discovery().deviceAuthorizationEndpoint(), "/oauth/device/authorize");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("scope", scope != null && !scope.isEmpty() ? scope : String.join(" ", scopes));
        if (audience != null) form.put("audience", audience);
        Map<String, String> headers = clientAuth(form);
        Map<String, Object> json = tenant.postForm(endpoint, form, headers, "device_authorization_failed");
        String deviceCode = Json.string(json, "device_code");
        if (deviceCode == null || deviceCode.isEmpty()) throw new NineException("device_authorization_failed", "no device_code in the response");
        Long expiresIn = Json.number(json, "expires_in");
        Long interval = Json.number(json, "interval");
        Instant now = clock.instant();
        return new DeviceAuthorization(
                deviceCode,
                Json.string(json, "user_code"),
                Json.string(json, "verification_uri"),
                Json.string(json, "verification_uri_complete"),
                now.plusSeconds(expiresIn == null || expiresIn <= 0 ? 600 : expiresIn),
                Duration.ofSeconds(interval == null || interval <= 0 ? 5 : interval));
    }

    /**
     * Polls the token endpoint until the user approves the device (returns the tokens), denies it
     * ({@code access_denied}) or the code expires ({@code expired_token}). Blocks the calling
     * thread; waits {@code interval} between polls and 5 seconds longer after each
     * {@code slow_down}. Interrupting the thread stops it ({@code interrupted}).
     */
    public TokenSet pollDeviceAuthorization(DeviceAuthorization authorization) {
        if (authorization == null) throw new NineException("invalid_options", "no device authorization");
        Duration interval = authorization.interval();
        while (true) {
            if (authorization.expiresAt() != null && !clock.instant().isBefore(authorization.expiresAt())) {
                throw new NineException("expired_token", "the device code expired; start again", 400);
            }
            try {
                sleeper.sleep(interval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new NineException("interrupted", "stopped waiting for the device to be approved", null, e);
            }
            Map<String, String> form = new LinkedHashMap<>();
            form.put("grant_type", DEVICE_GRANT);
            form.put("device_code", authorization.deviceCode());
            try {
                Map<String, Object> json = tokenRequest(form);
                String idToken = Json.string(json, "id_token");
                Map<String, Object> claims = idToken == null ? Collections.<String, Object>emptyMap() : verifyIdToken(idToken, null, null);
                return tokenSet(json, null, claims, null);
            } catch (NineException e) {
                if ("authorization_pending".equals(e.error())) continue;
                if ("slow_down".equals(e.error())) {
                    interval = interval.plusSeconds(5);
                    continue;
                }
                throw e;
            }
        }
    }

    /** The PKCE S256 code challenge of a verifier (RFC 7636): base64url(SHA-256(verifier)). */
    public static String codeChallenge(String codeVerifier) {
        return Codec.base64Url(Codec.sha256(Codec.utf8(codeVerifier)));
    }

    /**
     * {@code returnTo} when it is a same-site relative path ({@code /dashboard?tab=1}), else null:
     * no scheme, no host, no {@code //} or backslash, no control characters.
     */
    public static String safeReturnTo(String returnTo) {
        if (returnTo == null || returnTo.isEmpty() || returnTo.length() > 2048) return null;
        if (returnTo.charAt(0) != '/') return null;
        if (returnTo.length() > 1 && (returnTo.charAt(1) == '/' || returnTo.charAt(1) == '\\')) return null;
        for (int i = 0; i < returnTo.length(); i++) {
            char c = returnTo.charAt(i);
            if (c < 0x20 || c == 0x7f || c == '\\') return null;
        }
        return returnTo;
    }

    // ---- internals ----

    /**
     * Each state is accepted once per client instance, on top of the application removing the
     * pending login from its session: a replayed callback fails with {@code invalid_state}.
     */
    private void rememberState(PendingLogin pending) {
        String key = Codec.hex(Codec.sha256(Codec.utf8(pending.state())));
        Instant now = clock.instant();
        synchronized (usedStates) {
            Instant seen = usedStates.get(key);
            if (seen != null && now.isBefore(seen.plus(loginTimeout))) {
                throw new NineException("invalid_state", "this sign-in was already completed", 400);
            }
            usedStates.put(key, now);
        }
    }

    private TokenSet refreshWith(String refreshToken, TokenSet previous) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        Map<String, Object> json = tokenRequest(form);
        Map<String, Object> previousClaims = previous == null ? Collections.<String, Object>emptyMap() : previous.claims();
        String idToken = Json.string(json, "id_token");
        Map<String, Object> claims = idToken == null ? previousClaims : verifyIdToken(idToken, null, previousClaims);
        TokenSet next = tokenSet(json, previous, claims, previous == null ? null : previous.returnTo());
        if (next.refreshToken() == null) next = next.toBuilder().refreshToken(refreshToken).build();
        return next;
    }

    private Map<String, Object> tokenRequest(Map<String, String> form) {
        String endpoint = tenant.discovery().tokenEndpoint();
        Map<String, String> headers = clientAuth(form);
        Map<String, Object> json = tenant.postForm(endpoint, form, headers, "request_failed");
        String access = Json.string(json, "access_token");
        if (access == null || access.isEmpty()) throw new NineException("request_failed", "no access_token in the token response");
        return json;
    }

    /** client_secret_basic for confidential clients, {@code client_id} in the form for public ones. */
    private Map<String, String> clientAuth(Map<String, String> form) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (clientSecret != null) {
            String credentials = Codec.urlEncode(clientId) + ":" + Codec.urlEncode(clientSecret);
            headers.put("Authorization", "Basic " + java.util.Base64.getEncoder().encodeToString(Codec.utf8(credentials)));
        } else {
            form.put("client_id", clientId);
        }
        return headers;
    }

    private TokenSet tokenSet(Map<String, Object> json, TokenSet previous, Map<String, Object> claims, String returnTo) {
        Long expiresIn = Json.number(json, "expires_in");
        String refresh = Json.string(json, "refresh_token");
        String idToken = Json.string(json, "id_token");
        String scope = Json.string(json, "scope");
        return TokenSet.builder()
                .accessToken(Json.string(json, "access_token"))
                .tokenType(Json.string(json, "token_type") != null ? Json.string(json, "token_type") : "Bearer")
                .expiresAt(expiresIn == null ? null : clock.instant().plusSeconds(expiresIn))
                .refreshToken(refresh != null ? refresh : previous == null ? null : previous.refreshToken())
                .idToken(idToken != null ? idToken : previous == null ? null : previous.idToken())
                .scope(scope != null ? scope : previous == null ? null : previous.scope())
                .claims(claims)
                .returnTo(returnTo)
                .build();
    }

    /**
     * Verifies an ID token: signature (JWKS), not an access token, {@code iss}, {@code exp},
     * {@code iat}, {@code aud} contains the client id, {@code azp} when there are several
     * audiences (or when present), {@code nonce}, a non-empty {@code sub} that matches the
     * previous one on refresh.
     */
    Map<String, Object> verifyIdToken(String idToken, String nonce, Map<String, Object> previousClaims) {
        String code = "invalid_id_token";
        Jwt jwt;
        try {
            jwt = Jwt.decode(idToken, "ID token");
        } catch (NineException e) {
            throw new NineException(code, "malformed ID token", 401);
        }
        if (TokenChecks.isAccessTokenType(jwt.typ())) throw new NineException(code, "not an ID token", 401);
        TokenChecks.verifySignature(jwt, tenant, null, clientSecret == null, code, "ID token");
        Map<String, Object> claims = jwt.payload;
        TokenChecks.checkIssuer(claims, issuer, code);
        TokenChecks.checkTimes(claims, clock, leeway, true, code);
        List<String> aud = TokenChecks.audiences(claims.get("aud"));
        if (!aud.contains(clientId)) throw new NineException(code, "audience mismatch", 401);
        Object azp = claims.get("azp");
        if ((aud.size() > 1 || azp != null) && !clientId.equals(azp)) throw new NineException(code, "authorized party mismatch", 401);
        if (nonce != null) {
            Object got = claims.get("nonce");
            if (!(got instanceof String) || !Codec.constantTimeEquals((String) got, nonce)) throw new NineException(code, "nonce mismatch", 401);
        }
        Object sub = claims.get("sub");
        if (!(sub instanceof String) || ((String) sub).isEmpty()) throw new NineException(code, "missing subject", 401);
        if (previousClaims != null) {
            Object before = previousClaims.get("sub");
            if (before instanceof String && !before.equals(sub)) throw new NineException(code, "the subject changed", 401);
        }
        return claims;
    }

    private static String queryOf(String callbackUrl) {
        if (callbackUrl == null) throw new NineException("invalid_request", "no callback URL", 400);
        String s = callbackUrl.trim();
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash);
        int q = s.indexOf('?');
        if (q >= 0) return s.substring(q + 1);
        if (s.contains("://")) {
            try {
                return new URI(s).getRawQuery();
            } catch (URISyntaxException e) {
                throw new NineException("invalid_request", "malformed callback URL", 400);
            }
        }
        return s; // a bare query string
    }

    @Override
    public String toString() {
        return "AuthClient{issuer=" + issuer + ", clientId=" + clientId + ", confidential=" + isConfidential() + "}";
    }

    /** Builds an {@link AuthClient}. {@code issuer} and {@code clientId} are required. */
    public static final class Builder {
        private String issuer;
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private String[] scopes = {"openid", "profile", "email", "offline_access"};
        private String audience;
        private HttpTransport transport;
        private Clock clock;
        private boolean allowInsecureIssuer;
        private Duration leeway;
        private Duration loginTimeout;
        private Sleeper sleeper;

        private Builder() {}

        /** Your tenant's issuer, e.g. {@code https://acme.9in.io} or your custom login domain. */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder clientId(String id) {
            this.clientId = id;
            return this;
        }

        /** The client secret of a confidential application; null (or empty) for a public client. */
        public Builder clientSecret(String secretOrNull) {
            this.clientSecret = secretOrNull;
            return this;
        }

        /** Your callback URL, exactly as registered on the application. */
        public Builder redirectUri(String uri) {
            this.redirectUri = uri;
            return this;
        }

        /** Default {@code openid profile email offline_access} ({@code offline_access} gives a refresh token). */
        public Builder scopes(String... scopes) {
            this.scopes = scopes == null ? new String[0] : scopes.clone();
            return this;
        }

        /** An API identifier, to get access tokens for that API. */
        public Builder audience(String audienceOrNull) {
            this.audience = audienceOrNull;
            return this;
        }

        /** HTTP transport (default {@link UrlConnectionTransport}: 10 s timeouts, no redirects). */
        public Builder transport(HttpTransport t) {
            this.transport = t;
            return this;
        }

        /** Clock for expiry checks (default the system UTC clock). */
        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        /** Accepts a plain-http issuer other than localhost (development only, never in production). */
        public Builder allowInsecureIssuer(boolean allow) {
            this.allowInsecureIssuer = allow;
            return this;
        }

        /** Allowed clock skew for ID token times (default 30 seconds). */
        public Builder leeway(Duration leeway) {
            this.leeway = leeway;
            return this;
        }

        /** How long a started sign-in stays valid (default 15 minutes). */
        public Builder loginTimeout(Duration timeout) {
            this.loginTimeout = timeout;
            return this;
        }

        /**
         * Applies {@code NINE_ISSUER}, {@code NINE_CLIENT_ID}, {@code NINE_CLIENT_SECRET},
         * {@code NINE_REDIRECT_URI}, {@code NINE_AUDIENCE}, {@code NINE_SCOPES} and
         * {@code NINE_ALLOW_INSECURE_ISSUER} from an environment map (set values only).
         */
        public Builder env(Map<String, String> env) {
            String v;
            if ((v = Env.get(env, "ISSUER")) != null) issuer = v;
            if ((v = Env.get(env, "CLIENT_ID")) != null) clientId = v;
            if ((v = Env.get(env, "CLIENT_SECRET")) != null) clientSecret = v;
            if ((v = Env.get(env, "REDIRECT_URI")) != null) redirectUri = v;
            if ((v = Env.get(env, "AUDIENCE")) != null) audience = v;
            if ((v = Env.get(env, "SCOPES")) != null) scopes = Env.list(v);
            if (Env.flag(Env.get(env, "ALLOW_INSECURE_ISSUER"))) allowInsecureIssuer = true;
            return this;
        }

        Builder sleeper(Sleeper sleeper) {
            this.sleeper = sleeper;
            return this;
        }

        /** Validates the settings (issuer rules, required fields) and builds the client. */
        public AuthClient build() {
            return new AuthClient(this);
        }
    }
}
