package io.ninein;

import static io.ninein.testing.FakeNine.error;
import static io.ninein.testing.FakeNine.json;
import static io.ninein.testing.FakeNine.list;
import static io.ninein.testing.FakeNine.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.ninein.http.HttpRequest;
import io.ninein.internal.Codec;
import io.ninein.testing.FakeNine;
import io.ninein.testing.Jwts;
import io.ninein.testing.TestClock;
import io.ninein.testing.TestKeys;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AuthClientTest {
    static final String CLIENT = "app_test";
    static final String SECRET = "s3cret value/+=";
    static final String REDIRECT = "https://app.example.com/nine/callback";

    FakeNine nine;
    TestClock clock;
    /** What the token endpoint answers for the next exchange. */
    AtomicReference<Function<HttpRequest, io.ninein.http.HttpResponse>> token = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        nine = new FakeNine();
        clock = new TestClock();
        nine.on("POST", "/oauth/token", r -> token.get().apply(r));
    }

    AuthClient.Builder builder() {
        return AuthClient.builder().issuer(nine.issuer).clientId(CLIENT).redirectUri(REDIRECT).transport(nine).clock(clock);
    }

    AuthClient confidential() {
        return builder().clientSecret(SECRET).build();
    }

    AuthClient publicClient() {
        return builder().build();
    }

    Jwts.Claims idClaims(String nonce) {
        long now = clock.epochSecond();
        return Jwts.claims()
                .with("iss", nine.issuer)
                .with("sub", "usr_123")
                .with("aud", CLIENT)
                .with("azp", CLIENT)
                .with("iat", now)
                .with("exp", now + 3600)
                .with("nonce", nonce)
                .with("email", "jane@example.com");
    }

    /** Token endpoint answering a code exchange with an ID token built from the request's nonce. */
    void answerWithIdToken(String alg, Function<Jwts.Claims, Jwts.Claims> tweak, PendingLogin pending) {
        token.set(r -> json(200, map(
                "access_token", "at_1",
                "token_type", "Bearer",
                "expires_in", 3600,
                "refresh_token", "rt_1",
                "scope", "openid profile email offline_access",
                "id_token", Jwts.sign(alg, "JWT", tweak.apply(idClaims(pending.nonce()))))));
    }

    String callback(PendingLogin pending) {
        return REDIRECT + "?code=c_1&state=" + Codec.urlEncode(pending.state()) + "&iss=" + Codec.urlEncode(nine.issuer);
    }

    // ---- createLogin ----

    @Test
    void createLoginBuildsTheAuthorizationUrl() {
        AuthClient auth = builder().audience("https://api.example.com").build();
        Login login = auth.createLogin(LoginOptions.builder().returnTo("/dashboard?tab=1").loginHint("jane@example.com").locale("de").build());
        assertTrue(login.url().startsWith(nine.issuer + "/oauth/authorize?"));
        Map<String, String> q = Codec.parseQuery(login.url().substring(login.url().indexOf('?') + 1));
        PendingLogin p = login.pending();
        assertEquals("code", q.get("response_type"));
        assertEquals(CLIENT, q.get("client_id"));
        assertEquals(REDIRECT, q.get("redirect_uri"));
        assertEquals("openid profile email offline_access", q.get("scope"));
        assertEquals(p.state(), q.get("state"));
        assertEquals(p.nonce(), q.get("nonce"));
        assertEquals(AuthClient.codeChallenge(p.codeVerifier()), q.get("code_challenge"));
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals("https://api.example.com", q.get("audience"));
        assertEquals("jane@example.com", q.get("login_hint"));
        assertEquals("de", q.get("ui_locales"));
        assertNull(q.get("prompt"));
        assertEquals("/dashboard?tab=1", p.returnTo());
        assertEquals(REDIRECT, p.redirectUri());
        assertTrue(p.state().length() >= 43);
        assertTrue(p.codeVerifier().length() >= 43 && p.codeVerifier().length() <= 128);
        assertTrue(login.url().contains("scope=openid%20profile%20email%20offline_access"));
    }

    @Test
    void eachLoginHasFreshSecrets() {
        AuthClient auth = publicClient();
        PendingLogin a = auth.createLogin().pending();
        PendingLogin b = auth.createLogin().pending();
        assertNotEquals(a.state(), b.state());
        assertNotEquals(a.nonce(), b.nonce());
        assertNotEquals(a.codeVerifier(), b.codeVerifier());
    }

    @Test
    void signupScreenOpensTheSignUpForm() {
        Login login = publicClient().createLogin(LoginOptions.builder().screen("signup").prompt("login").build());
        assertTrue(login.url().contains("prompt=create"));
        Login prompt = publicClient().createLogin(LoginOptions.builder().prompt("login").build());
        assertTrue(prompt.url().contains("prompt=login"));
    }

    @Test
    void extraParametersNeverReplaceProtocolOnes() {
        Map<String, String> extra = new HashMap<>();
        extra.put("state", "attacker");
        extra.put("redirect_uri", "https://evil.example");
        extra.put("code_challenge_method", "plain");
        extra.put("max_age", "300");
        Login login = publicClient().createLogin(LoginOptions.builder().extra(extra).build());
        Map<String, String> q = Codec.parseQuery(login.url().substring(login.url().indexOf('?') + 1));
        assertEquals(login.pending().state(), q.get("state"));
        assertEquals(REDIRECT, q.get("redirect_uri"));
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals("300", q.get("max_age"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://evil.example/x", "//evil.example", "/\\evil.example", "dashboard", "/\tx", "/a\\b", "javascript:alert(1)"})
    void unsafeReturnToIsDropped(String returnTo) {
        Login login = publicClient().createLogin(LoginOptions.builder().returnTo(returnTo).build());
        assertNull(login.pending().returnTo());
    }

    @Test
    void redirectUriIsRequiredForSignIn() {
        AuthClient auth = AuthClient.builder().issuer(nine.issuer).clientId(CLIENT).transport(nine).build();
        NineException e = assertThrows(NineException.class, auth::createLogin);
        assertEquals("invalid_options", e.error());
        Login login = auth.createLogin(LoginOptions.builder().redirectUri("myapp://callback").build());
        assertEquals("myapp://callback", login.pending().redirectUri());
        assertTrue(login.url().contains("redirect_uri=myapp%3A%2F%2Fcallback"));
    }

    @Test
    void authorizationEndpointWithAQueryKeepsIt() {
        nine.discovery.put("authorization_endpoint", nine.issuer + "/oauth/authorize?tenant=x");
        Login login = publicClient().createLogin();
        assertTrue(login.url().startsWith(nine.issuer + "/oauth/authorize?tenant=x&response_type=code"));
    }

    @Test
    void pkceMatchesTheRfc7636Example() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", AuthClient.codeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    @Test
    void discoveryIsCached() {
        AuthClient auth = publicClient();
        auth.createLogin();
        auth.createLogin();
        auth.discovery();
        assertEquals(1, nine.count("/.well-known/openid-configuration"));
        clock.advance(Duration.ofHours(2));
        auth.discovery();
        assertEquals(2, nine.count("/.well-known/openid-configuration"));
    }

    @Test
    void discoveryMustBeForOurIssuer() {
        nine.discovery.put("issuer", "https://other.9in.io");
        NineException e = assertThrows(NineException.class, () -> publicClient().discovery());
        assertEquals("invalid_issuer", e.error());
    }

    @Test
    void discoveryFailureIsReported() {
        nine.on("GET", "/.well-known/openid-configuration", r -> json(503, null));
        NineException e = assertThrows(NineException.class, () -> publicClient().createLogin());
        assertEquals("discovery_failed", e.error());
        assertEquals(503, e.status());
    }

    // ---- handleCallback: success with every algorithm ----

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"})
    void confidentialSignInWithEveryAlgorithm(String alg) {
        assumeTrue(!alg.equals("EdDSA") || TestKeys.ed25519Available(), "Ed25519 needs Java 15+");
        AuthClient auth = confidential();
        Login login = auth.createLogin(LoginOptions.builder().returnTo("/after").build());
        answerWithIdToken(alg, c -> c, login.pending());

        TokenSet tokens = auth.handleCallback(callback(login.pending()), PendingLogin.fromJson(login.pending().toJson()));

        assertEquals("at_1", tokens.accessToken());
        assertEquals("rt_1", tokens.refreshToken());
        assertEquals("Bearer", tokens.tokenType());
        assertEquals(clock.instant().plusSeconds(3600), tokens.expiresAt());
        assertEquals("usr_123", tokens.subject());
        assertEquals("jane@example.com", tokens.claim("email"));
        assertEquals("/after", tokens.returnTo());

        HttpRequest req = nine.last("/oauth/token");
        Map<String, String> form = FakeNine.form(req);
        assertEquals("authorization_code", form.get("grant_type"));
        assertEquals("c_1", form.get("code"));
        assertEquals(REDIRECT, form.get("redirect_uri"));
        assertEquals(login.pending().codeVerifier(), form.get("code_verifier"));
        assertNull(form.get("client_id"), "confidential clients authenticate with HTTP Basic");
        assertNull(form.get("client_secret"));
        String basic = new String(java.util.Base64.getDecoder().decode(req.header("Authorization").substring(6)), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(CLIENT + ":" + Codec.urlEncode(SECRET), basic);
    }

    @Test
    void publicClientSendsClientIdAndNoSecret() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        answerWithIdToken("ES256", c -> c, login.pending());
        auth.handleCallback(callback(login.pending()), login.pending());
        HttpRequest req = nine.last("/oauth/token");
        assertNull(req.header("Authorization"));
        assertEquals(CLIENT, FakeNine.form(req).get("client_id"));
    }

    @Test
    void callbackAcceptsABareQueryString() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        answerWithIdToken("RS256", c -> c, login.pending());
        String q = "code=c_1&state=" + Codec.urlEncode(login.pending().state()) + "&iss=" + Codec.urlEncode(nine.issuer);
        assertEquals("at_1", auth.handleCallback(q, login.pending()).accessToken());
    }

    // ---- handleCallback: rejections ----

    @Test
    void errorAnswerIsRaisedWithTheServersCode() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(
                REDIRECT + "?error=access_denied&error_description=The+user+declined&state=" + login.pending().state(), login.pending()));
        assertEquals("access_denied", e.error());
        assertEquals("The user declined", e.description());
        assertEquals(400, e.status());
        assertEquals(0, nine.count("/oauth/token"));
    }

    @Test
    void missingPendingLoginIsInvalidState() {
        NineException e = assertThrows(NineException.class, () -> publicClient().handleCallback(REDIRECT + "?code=c&state=s", null));
        assertEquals("invalid_state", e.error());
    }

    @Test
    void wrongOrMissingStateIsInvalidState() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        assertEquals("invalid_state", assertThrows(NineException.class,
                () -> auth.handleCallback(REDIRECT + "?code=c&iss=" + nine.issuer + "&state=" + login.pending().state() + "x", login.pending())).error());
        assertEquals("invalid_state", assertThrows(NineException.class,
                () -> auth.handleCallback(REDIRECT + "?code=c&iss=" + nine.issuer, login.pending())).error());
        assertEquals(0, nine.count("/oauth/token"));
    }

    @Test
    void stateFromAnotherLoginIsRefused() {
        AuthClient auth = publicClient();
        Login first = auth.createLogin();
        Login second = auth.createLogin();
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(first.pending()), second.pending()));
        assertEquals("invalid_state", e.error());
    }

    @Test
    void replayedCallbackIsRefused() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        answerWithIdToken("RS256", c -> c, login.pending());
        auth.handleCallback(callback(login.pending()), login.pending());
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()));
        assertEquals("invalid_state", e.error());
        assertEquals(1, nine.count("/oauth/token"));
    }

    @Test
    void refusedCallbacksDoNotUseTheSignInUp() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        String evil = REDIRECT + "?code=c_1&state=" + Codec.urlEncode(login.pending().state()) + "&iss=" + Codec.urlEncode("https://evil.9in.io");
        assertEquals("invalid_issuer", assertThrows(NineException.class, () -> auth.handleCallback(evil, login.pending())).error());
        String noCode = REDIRECT + "?state=" + Codec.urlEncode(login.pending().state()) + "&iss=" + Codec.urlEncode(nine.issuer);
        assertEquals("missing_code", assertThrows(NineException.class, () -> auth.handleCallback(noCode, login.pending())).error());
        answerWithIdToken("RS256", c -> c, login.pending());
        assertEquals("at_1", auth.handleCallback(callback(login.pending()), login.pending()).accessToken());
    }

    @Test
    void expiredPendingLoginIsRefused() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        clock.advance(Duration.ofMinutes(16));
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()));
        assertEquals("invalid_state", e.error());
    }

    @Test
    void issuerParameterMustBeOurs() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        String url = REDIRECT + "?code=c&state=" + login.pending().state() + "&iss=" + Codec.urlEncode("https://evil.9in.io");
        assertEquals("invalid_issuer", assertThrows(NineException.class, () -> auth.handleCallback(url, login.pending())).error());
    }

    @Test
    void missingIssuerParameterIsRefusedWhenAdvertised() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        String url = REDIRECT + "?code=c&state=" + login.pending().state();
        assertEquals("invalid_issuer", assertThrows(NineException.class, () -> auth.handleCallback(url, login.pending())).error());
    }

    @Test
    void missingIssuerParameterIsFineWhenNotAdvertised() {
        nine.discovery.put("authorization_response_iss_parameter_supported", false);
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        answerWithIdToken("RS256", c -> c, login.pending());
        String url = REDIRECT + "?code=c&state=" + login.pending().state();
        assertEquals("at_1", auth.handleCallback(url, login.pending()).accessToken());
    }

    @Test
    void missingCodeIsReported() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        String url = REDIRECT + "?state=" + login.pending().state() + "&iss=" + nine.issuer;
        assertEquals("missing_code", assertThrows(NineException.class, () -> auth.handleCallback(url, login.pending())).error());
    }

    @Test
    void duplicateParametersAreRefused() {
        AuthClient auth = publicClient();
        Login login = auth.createLogin();
        String url = callback(login.pending()) + "&state=other";
        assertEquals("invalid_request", assertThrows(NineException.class, () -> auth.handleCallback(url, login.pending())).error());
    }

    @Test
    void tokenEndpointErrorsPassThrough() {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        token.set(r -> json(400, error("invalid_grant", "the code was already used")));
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()));
        assertEquals("invalid_grant", e.error());
        assertEquals("the code was already used", e.description());
        assertEquals(400, e.status());
    }

    @Test
    void tokenEndpointWithoutJsonIsRequestFailed() {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        token.set(r -> io.ninein.http.HttpResponse.of(502, null, "<html>bad gateway</html>"));
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()));
        assertEquals("request_failed", e.error());
        assertEquals(502, e.status());
    }

    @Test
    void redirectsAreNeverFollowed() {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        token.set(r -> io.ninein.http.HttpResponse.of(302, Collections.singletonMap("Location", "https://evil.example/token"), ""));
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()));
        assertEquals(302, e.status());
        assertTrue(e.description().contains("redirect"));
    }

    @Test
    void missingIdTokenWithOpenidScopeIsRefused() {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        token.set(r -> json(200, map("access_token", "at", "token_type", "Bearer", "expires_in", 60)));
        assertEquals("invalid_id_token", assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending())).error());
    }

    @Test
    void withoutOpenidScopeNoIdTokenIsNeeded() {
        AuthClient auth = builder().scopes("offline_access", "orders:read").build();
        Login login = auth.createLogin();
        token.set(r -> json(200, map("access_token", "at", "token_type", "Bearer")));
        TokenSet tokens = auth.handleCallback(callback(login.pending()), login.pending());
        assertTrue(tokens.claims().isEmpty());
        assertNull(tokens.expiresAt(), "unknown without expires_in");
        assertFalse(tokens.isExpired(Duration.ofHours(1)));
    }

    // ---- ID token checks ----

    void assertIdTokenRefused(String alg, Function<Jwts.Claims, Jwts.Claims> tweak, String why) {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        answerWithIdToken(alg, tweak, login.pending());
        NineException e = assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()), why);
        assertEquals("invalid_id_token", e.error(), why + ": " + e.getMessage());
    }

    @Test
    void idTokenClaimChecks() {
        assertIdTokenRefused("RS256", c -> c.with("nonce", "other"), "bad nonce");
        assertIdTokenRefused("RS256", c -> c.without("nonce"), "missing nonce");
        assertIdTokenRefused("RS256", c -> c.with("aud", "app_other"), "wrong audience");
        assertIdTokenRefused("RS256", c -> c.with("aud", list(CLIENT, "app_other")).without("azp"), "several audiences without azp");
        assertIdTokenRefused("RS256", c -> c.with("aud", list(CLIENT, "app_other")).with("azp", "app_other"), "azp mismatch");
        assertIdTokenRefused("RS256", c -> c.with("azp", "app_other"), "azp present and wrong");
        assertIdTokenRefused("RS256", c -> c.with("iss", "https://evil.9in.io"), "wrong issuer");
        assertIdTokenRefused("RS256", c -> c.with("exp", clock.epochSecond() - 31), "expired");
        assertIdTokenRefused("RS256", c -> c.without("exp"), "no expiry");
        assertIdTokenRefused("RS256", c -> c.with("iat", clock.epochSecond() + 120), "issued in the future");
        assertIdTokenRefused("RS256", c -> c.without("iat"), "no iat");
        assertIdTokenRefused("RS256", c -> c.with("nbf", clock.epochSecond() + 120), "not yet valid");
        assertIdTokenRefused("RS256", c -> c.with("sub", ""), "empty subject");
        assertIdTokenRefused("RS256", c -> c.with("exp", "soon"), "non-numeric exp");
    }

    @Test
    void severalAudiencesWithMatchingAzpAreAccepted() {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        answerWithIdToken("RS256", c -> c.with("aud", list(CLIENT, "https://api.example.com")), login.pending());
        assertEquals("usr_123", auth.handleCallback(callback(login.pending()), login.pending()).subject());
    }

    @Test
    void smallClockSkewIsAllowed() {
        AuthClient auth = confidential();
        Login login = auth.createLogin();
        answerWithIdToken("RS256", c -> c.with("exp", clock.epochSecond() - 20).with("iat", clock.epochSecond() + 20), login.pending());
        assertEquals("usr_123", auth.handleCallback(callback(login.pending()), login.pending()).subject());
    }

    void answerRaw(String idToken) {
        token.set(r -> json(200, map("access_token", "at", "token_type", "Bearer", "expires_in", 60, "id_token", idToken)));
    }

    NineException refuseRaw(AuthClient auth, Function<PendingLogin, String> idToken) {
        Login login = auth.createLogin();
        answerRaw(idToken.apply(login.pending()));
        return assertThrows(NineException.class, () -> auth.handleCallback(callback(login.pending()), login.pending()));
    }

    @Test
    void idTokenSignatureChecks() {
        AuthClient auth = confidential();
        // tampered payload
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.tamper(Jwts.sign("RS256", "JWT", idClaims(p.nonce())), idClaims(p.nonce()).with("sub", "usr_admin"))).error());
        // alg none
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.none(idClaims(p.nonce()), "JWT")).error());
        // HMAC without a secret (ID tokens are always asymmetric)
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign("HS256", "JWT", idClaims(p.nonce()))).error());
        // an access token is not an ID token
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign("RS256", "at+jwt", idClaims(p.nonce()))).error());
        // ES256 token claiming the RSA key's kid
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign(TestKeys.of("ES256"), "ES256", Jwts.header("ES256", "k_rs256", "JWT"), idClaims(p.nonce()))).error());
        // RS384 signature with the RS256 key (the JWK names RS256)
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign(TestKeys.of("RS256"), "RS384", Jwts.header("RS384", "k_rs256", "JWT"), idClaims(p.nonce()))).error());
        // signed by a key that isn't in the JWKS under that kid
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign(TestKeys.fresh("RS256", "k_rs256"), "RS256", Jwts.header("RS256", "k_rs256", "JWT"), idClaims(p.nonce()))).error());
        // malformed
        assertEquals("invalid_id_token", refuseRaw(auth, p -> "not.a.jwt").error());
        assertEquals("invalid_id_token", refuseRaw(auth, p -> "onlyonepart").error());
        // crit header
        Map<String, Object> crit = Jwts.header("RS256", "k_rs256", "JWT");
        crit.put("crit", list("exp"));
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign(TestKeys.of("RS256"), "RS256", crit, idClaims(p.nonce()))).error());
    }

    @Test
    void keyTypeMustFitWhenTheJwkNamesNoAlg() {
        nine.jwks.clear();
        nine.jwks.add(TestKeys.of("RS256").jwkWithoutAlg());
        nine.jwks.add(TestKeys.of("ES256").jwkWithoutAlg());
        AuthClient auth = confidential();
        // PS256 with the RSA key works (no alg member: any RSA algorithm fits)
        Login ok = auth.createLogin();
        answerRaw(Jwts.sign(TestKeys.of("RS256"), "PS256", Jwts.header("PS256", "k_rs256", "JWT"), idClaims(ok.pending().nonce())));
        assertEquals("usr_123", auth.handleCallback(callback(ok.pending()), ok.pending()).subject());
        // ES384 header with the P-256 key: wrong curve
        assertEquals("invalid_id_token", refuseRaw(auth, p -> Jwts.sign(TestKeys.of("ES256"), "ES256", Jwts.header("ES384", "k_es256", "JWT"), idClaims(p.nonce()))).error());
    }

    @Test
    void encryptionKeysAreNotUsedForSignatures() {
        nine.jwks.clear();
        nine.jwks.add(TestKeys.of("RS256").jwkWith("use", "enc"));
        assertEquals("invalid_id_token", refuseRaw(confidential(), p -> Jwts.sign("RS256", "JWT", idClaims(p.nonce()))).error());
    }

    @Test
    void unknownKidRefetchesOnceThenIsThrottled() {
        AuthClient auth = confidential();
        TestKeys rotated = TestKeys.fresh("ES256", "k_new");
        // A token from a key the cached JWKS doesn't have yet: one refetch finds it.
        Login first = auth.createLogin();
        answerWithIdToken("RS256", c -> c, first.pending());
        auth.handleCallback(callback(first.pending()), first.pending());
        assertEquals(1, nine.count("/jwks.json"));
        nine.jwks.add(rotated.jwk);
        Login second = auth.createLogin();
        answerRaw(Jwts.sign(rotated, "ES256", Jwts.header("ES256", "k_new", "JWT"), idClaims(second.pending().nonce())));
        assertEquals("usr_123", auth.handleCallback(callback(second.pending()), second.pending()).subject());
        assertEquals(2, nine.count("/jwks.json"));
        // An unknown kid: one refetch, then no more fetches for a minute.
        for (int i = 0; i < 3; i++) {
            NineException e = refuseRaw(auth, p -> Jwts.sign(TestKeys.of("RS256"), "RS256", Jwts.header("RS256", "k_junk", "JWT"), idClaims(p.nonce())));
            assertEquals("invalid_id_token", e.error());
            assertTrue(e.description().contains("unknown signing key"));
        }
        assertEquals(3, nine.count("/jwks.json"));
        clock.advance(Duration.ofSeconds(61));
        refuseRaw(auth, p -> Jwts.sign(TestKeys.of("RS256"), "RS256", Jwts.header("RS256", "k_junk", "JWT"), idClaims(p.nonce())));
        assertEquals(4, nine.count("/jwks.json"));
    }

    @Test
    void jwksIsCachedForTenMinutes() {
        AuthClient auth = confidential();
        for (int i = 0; i < 3; i++) {
            Login login = auth.createLogin();
            answerWithIdToken("ES384", c -> c, login.pending());
            auth.handleCallback(callback(login.pending()), login.pending());
        }
        assertEquals(1, nine.count("/jwks.json"));
        clock.advance(Duration.ofMinutes(11));
        Login login = auth.createLogin();
        answerWithIdToken("ES384", c -> c, login.pending());
        auth.handleCallback(callback(login.pending()), login.pending());
        assertEquals(2, nine.count("/jwks.json"));
    }

    @Test
    void jwksOutageIsReported() {
        nine.on("GET", "/.well-known/jwks.json", r -> json(500, null));
        NineException e = refuseRaw(confidential(), p -> Jwts.sign("RS256", "JWT", idClaims(p.nonce())));
        assertEquals("jwks_unavailable", e.error());
    }

    @Test
    void edDsaOnARuntimeWithoutEd25519() {
        assumeFalse(TestKeys.ed25519Available(), "only on Java 11-14, which have no Ed25519");
        Map<String, Object> okp = map("kty", "OKP", "crv", "Ed25519", "kid", "k_ed", "alg", "EdDSA", "use", "sig", "x", Codec.base64Url(new byte[32]));
        nine.jwks.add(okp);
        Function<PendingLogin, String> token = p -> Jwts.encode(Jwts.header("EdDSA", "k_ed", "JWT")) + "." + Jwts.encode(idClaims(p.nonce())) + "." + Codec.base64Url(new byte[64]);
        // A public client gets its ID token straight from the token endpoint over TLS: claims checks suffice.
        AuthClient pub = publicClient();
        Login login = pub.createLogin();
        answerRaw(token.apply(login.pending()));
        assertEquals("usr_123", pub.handleCallback(callback(login.pending()), login.pending()).subject());
        // ... but the claims are still checked.
        Login bad = pub.createLogin();
        answerRaw(Jwts.encode(Jwts.header("EdDSA", "k_ed", "JWT")) + "." + Jwts.encode(idClaims("wrong")) + "." + Codec.base64Url(new byte[64]));
        assertEquals("invalid_id_token", assertThrows(NineException.class, () -> pub.handleCallback(callback(bad.pending()), bad.pending())).error());
        // A confidential client must verify the signature.
        NineException e = refuseRaw(confidential(), token);
        assertEquals("unsupported_algorithm", e.error());
    }

    // ---- refresh ----

    TokenSet signedIn(AuthClient auth) {
        Login login = auth.createLogin();
        answerWithIdToken("RS256", c -> c, login.pending());
        return auth.handleCallback(callback(login.pending()), login.pending());
    }

    @Test
    void refreshRotatesTheRefreshToken() {
        AuthClient auth = confidential();
        TokenSet first = signedIn(auth);
        clock.advance(Duration.ofMinutes(5));
        long now = clock.epochSecond();
        token.set(r -> json(200, map("access_token", "at_2", "token_type", "Bearer", "expires_in", 600, "refresh_token", "rt_2",
                "id_token", Jwts.sign("RS256", "JWT", Jwts.claims().with("iss", nine.issuer).with("sub", "usr_123").with("aud", CLIENT).with("iat", now).with("exp", now + 600).with("name", "Jane")))));
        TokenSet next = auth.refresh(first);
        assertEquals("at_2", next.accessToken());
        assertEquals("rt_2", next.refreshToken());
        assertEquals("Jane", next.claim("name"));
        assertEquals(first.returnTo(), next.returnTo());
        Map<String, String> form = FakeNine.form(nine.last("/oauth/token"));
        assertEquals("refresh_token", form.get("grant_type"));
        assertEquals("rt_1", form.get("refresh_token"));
    }

    @Test
    void refreshKeepsTheOldRefreshTokenAndClaimsWhenNoneAreReturned() {
        AuthClient auth = confidential();
        TokenSet first = signedIn(auth);
        token.set(r -> json(200, map("access_token", "at_2", "token_type", "Bearer", "expires_in", 600)));
        TokenSet next = auth.refresh(first);
        assertEquals("rt_1", next.refreshToken());
        assertEquals("usr_123", next.subject());
        assertEquals(first.idToken(), next.idToken());
        assertEquals("openid profile email offline_access", next.scope());
        TokenSet byString = auth.refresh("rt_x");
        assertEquals("rt_x", byString.refreshToken());
        assertEquals("rt_x", FakeNine.form(nine.last("/oauth/token")).get("refresh_token"));
    }

    @Test
    void refreshRefusesAnIdTokenForAnotherUser() {
        AuthClient auth = confidential();
        TokenSet first = signedIn(auth);
        long now = clock.epochSecond();
        token.set(r -> json(200, map("access_token", "at_2", "refresh_token", "rt_2",
                "id_token", Jwts.sign("RS256", "JWT", Jwts.claims().with("iss", nine.issuer).with("sub", "usr_other").with("aud", CLIENT).with("iat", now).with("exp", now + 600)))));
        assertEquals("invalid_id_token", assertThrows(NineException.class, () -> auth.refresh(first)).error());
    }

    @Test
    void refreshErrors() {
        AuthClient auth = confidential();
        TokenSet first = signedIn(auth);
        token.set(r -> json(400, error("invalid_grant", "refresh token reused")));
        NineException e = assertThrows(NineException.class, () -> auth.refresh(first));
        assertEquals("invalid_grant", e.error());
        TokenSet noRefresh = first.toBuilder().refreshToken(null).build();
        assertEquals("login_required", assertThrows(NineException.class, () -> auth.refresh(noRefresh)).error());
        assertEquals("login_required", assertThrows(NineException.class, () -> auth.refresh((String) null)).error());
    }

    @Test
    void ensureFreshReturnsTheSameInstanceUntilNearExpiry() {
        AuthClient auth = confidential();
        TokenSet first = signedIn(auth);
        assertSame(first, auth.ensureFresh(first, Duration.ofSeconds(60)));
        clock.advance(Duration.ofSeconds(3600 - 59));
        token.set(r -> json(200, map("access_token", "at_2", "expires_in", 3600, "refresh_token", "rt_2")));
        TokenSet next = auth.ensureFresh(first, Duration.ofSeconds(60));
        assertNotEquals(first, next);
        assertEquals("rt_2", next.refreshToken());
    }

    // ---- userinfo, revoke, logout ----

    @Test
    void userInfo() {
        AtomicReference<String> auth = new AtomicReference<>();
        nine.on("GET", "/oauth/userinfo", r -> {
            auth.set(r.header("Authorization"));
            return json(200, map("sub", "usr_123", "email", "jane@example.com"));
        });
        Map<String, Object> info = confidential().userInfo("at_1");
        assertEquals("usr_123", info.get("sub"));
        assertEquals("Bearer at_1", auth.get());
        nine.on("GET", "/oauth/userinfo", r -> json(401, error("invalid_token", null)));
        NineException e = assertThrows(NineException.class, () -> confidential().userInfo("at_1"));
        assertEquals("invalid_token", e.error());
        assertEquals(401, e.status());
        nine.on("GET", "/oauth/userinfo", r -> json(500, null));
        assertEquals("userinfo_failed", assertThrows(NineException.class, () -> confidential().userInfo("at_1")).error());
    }

    @Test
    void revoke() {
        nine.on("POST", "/oauth/revoke", r -> json(200, null));
        confidential().revoke("rt_1", "refresh_token");
        HttpRequest req = nine.last("/oauth/revoke");
        assertEquals("rt_1", FakeNine.form(req).get("token"));
        assertEquals("refresh_token", FakeNine.form(req).get("token_type_hint"));
        assertTrue(req.header("Authorization").startsWith("Basic "));
        publicClient().revoke("at_1", "access_token");
        assertEquals(CLIENT, FakeNine.form(nine.last("/oauth/revoke")).get("client_id"));
        nine.on("POST", "/oauth/revoke", r -> json(401, error("invalid_client", null)));
        assertEquals("invalid_client", assertThrows(NineException.class, () -> confidential().revoke("rt", null)).error());
        nine.discovery.remove("revocation_endpoint");
        builder().build().revoke("rt", null); // nothing to call
    }

    @Test
    void logoutUrl() {
        String url = publicClient().logoutUrl("id.tok.en", "https://app.example.com/bye", "st");
        assertEquals(nine.issuer + "/oauth/logout?client_id=app_test&id_token_hint=id.tok.en&post_logout_redirect_uri="
                + Codec.urlEncode("https://app.example.com/bye") + "&state=st", url);
        nine.discovery.remove("end_session_endpoint");
        assertEquals(nine.issuer + "/oauth/logout?client_id=app_test", builder().build().logoutUrl(null, null, null));
    }

    // ---- client credentials and device flow ----

    @Test
    void clientCredentials() {
        token.set(r -> json(200, map("access_token", "m2m", "token_type", "Bearer", "expires_in", 300, "scope", "orders:read")));
        TokenSet t = confidential().clientCredentials("https://api.example.com", "orders:read");
        assertEquals("m2m", t.accessToken());
        assertTrue(t.claims().isEmpty());
        Map<String, String> form = FakeNine.form(nine.last("/oauth/token"));
        assertEquals("client_credentials", form.get("grant_type"));
        assertEquals("https://api.example.com", form.get("audience"));
        assertEquals("orders:read", form.get("scope"));
        assertEquals("invalid_options", assertThrows(NineException.class, () -> publicClient().clientCredentials(null, null)).error());
    }

    AuthClient deviceClient(List<Duration> sleeps) {
        return builder().scopes("openid", "offline_access").sleeper(d -> {
            sleeps.add(d);
            clock.advance(d);
        }).build();
    }

    @Test
    void deviceFlowPollsUntilApproved() {
        nine.on("POST", "/oauth/device/authorize", r -> json(200, map("device_code", "dc", "user_code", "ABCD-EFGH",
                "verification_uri", nine.issuer + "/device", "verification_uri_complete", nine.issuer + "/device?user_code=ABCD-EFGH",
                "expires_in", 600, "interval", 5)));
        List<Duration> sleeps = new ArrayList<>();
        AuthClient auth = deviceClient(sleeps);
        DeviceAuthorization device = auth.startDeviceAuthorization(null);
        assertEquals("ABCD-EFGH", device.userCode());
        assertEquals(nine.issuer + "/device", device.verificationUri());
        assertEquals(Duration.ofSeconds(5), device.interval());
        assertEquals(clock.instant().plusSeconds(600), device.expiresAt());
        Map<String, String> start = FakeNine.form(nine.last("/oauth/device/authorize"));
        assertEquals("openid offline_access", start.get("scope"));
        assertEquals(CLIENT, start.get("client_id"));

        AtomicInteger polls = new AtomicInteger();
        token.set(r -> {
            int n = polls.incrementAndGet();
            if (n == 1) return json(400, error("authorization_pending", null));
            if (n == 2) return json(400, error("slow_down", null));
            if (n == 3) return json(400, error("authorization_pending", null));
            long now = clock.epochSecond();
            return json(200, map("access_token", "at_dev", "refresh_token", "rt_dev", "expires_in", 3600,
                    "id_token", Jwts.sign("ES256", "JWT", Jwts.claims().with("iss", nine.issuer).with("sub", "usr_tv").with("aud", CLIENT).with("iat", now).with("exp", now + 60))));
        });
        TokenSet tokens = auth.pollDeviceAuthorization(device);
        assertEquals("at_dev", tokens.accessToken());
        assertEquals("usr_tv", tokens.subject());
        assertEquals(List.of(Duration.ofSeconds(5), Duration.ofSeconds(5), Duration.ofSeconds(10), Duration.ofSeconds(10)), sleeps);
        Map<String, String> poll = FakeNine.form(nine.last("/oauth/token"));
        assertEquals("urn:ietf:params:oauth:grant-type:device_code", poll.get("grant_type"));
        assertEquals("dc", poll.get("device_code"));
    }

    @Test
    void deviceFlowStopsWhenDeniedOrExpired() {
        List<Duration> sleeps = new ArrayList<>();
        AuthClient auth = deviceClient(sleeps);
        DeviceAuthorization device = new DeviceAuthorization("dc", "U", "v", null, clock.instant().plusSeconds(20), Duration.ofSeconds(5));
        token.set(r -> json(400, error("access_denied", "the user said no")));
        assertEquals("access_denied", assertThrows(NineException.class, () -> auth.pollDeviceAuthorization(device)).error());
        token.set(r -> json(400, error("expired_token", null)));
        assertEquals("expired_token", assertThrows(NineException.class, () -> auth.pollDeviceAuthorization(device)).error());
        token.set(r -> json(400, error("authorization_pending", null)));
        DeviceAuthorization shortLived = new DeviceAuthorization("dc", "U", "v", null, clock.instant().plusSeconds(12), Duration.ofSeconds(5));
        assertEquals("expired_token", assertThrows(NineException.class, () -> auth.pollDeviceAuthorization(shortLived)).error());
    }

    @Test
    void deviceFlowStopsWhenInterrupted() {
        AuthClient auth = builder().sleeper(d -> {
            throw new InterruptedException();
        }).build();
        DeviceAuthorization device = new DeviceAuthorization("dc", "U", "v", null, clock.instant().plusSeconds(60), Duration.ofSeconds(1));
        try {
            assertEquals("interrupted", assertThrows(NineException.class, () -> auth.pollDeviceAuthorization(device)).error());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    // ---- configuration ----

    @ParameterizedTest
    @ValueSource(strings = {"http://acme.9in.io", "http://192.168.1.10", "ftp://acme.9in.io"})
    void insecureIssuersAreRefused(String issuer) {
        assumeFalse(io.ninein.internal.Issuers.insecureAllowedByEnv());
        NineException e = assertThrows(NineException.class, () -> AuthClient.builder().issuer(issuer).clientId(CLIENT).build());
        assertEquals("insecure_issuer", e.error());
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:8787", "http://auth.localhost", "http://127.0.0.1:9000", "http://[::1]:8080"})
    void localHttpIssuersAreAllowed(String issuer) {
        assertEquals(issuer, AuthClient.builder().issuer(issuer + "/").clientId(CLIENT).build().issuer());
    }

    @Test
    void insecureIssuerOptOut() {
        assertEquals("http://acme.test", AuthClient.builder().issuer("http://acme.test").clientId(CLIENT).allowInsecureIssuer(true).build().issuer());
        Map<String, String> env = new HashMap<>();
        env.put("NINE_ISSUER", "http://acme.test");
        env.put("NINE_CLIENT_ID", CLIENT);
        env.put("NINE_ALLOW_INSECURE_ISSUER", "true");
        assertEquals("http://acme.test", AuthClient.fromEnv(env).issuer());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://acme.9in.io?x=1", "https://acme.9in.io#f", "https://user:pw@acme.9in.io", "acme.9in.io", "", "https://"})
    void malformedIssuersAreRefused(String issuer) {
        NineException e = assertThrows(NineException.class, () -> AuthClient.builder().issuer(issuer).clientId(CLIENT).build());
        assertEquals("invalid_issuer", e.error());
    }

    @Test
    void requiredSettings() {
        assertEquals("invalid_options", assertThrows(NineException.class, () -> AuthClient.builder().issuer(nine.issuer).build()).error());
        assertEquals("invalid_issuer", assertThrows(NineException.class, () -> AuthClient.builder().clientId(CLIENT).build()).error());
        assertEquals("invalid_options", assertThrows(NineException.class, () -> AuthClient.builder().issuer(nine.issuer).clientId(CLIENT).scopes().build()).error());
    }

    @Test
    void fromEnvReadsTheNineVariables() {
        Map<String, String> env = new HashMap<>();
        env.put("NINE_ISSUER", "https://acme.9in.io/");
        env.put("NINE_CLIENT_ID", "app_env");
        env.put("NINE_CLIENT_SECRET", "sec");
        env.put("NINE_REDIRECT_URI", "https://app/cb");
        env.put("NINE_AUDIENCE", "https://api");
        env.put("NINE_SCOPES", "openid,email");
        AuthClient auth = AuthClient.fromEnv(env);
        assertEquals("https://acme.9in.io", auth.issuer());
        assertEquals("app_env", auth.clientId());
        assertTrue(auth.isConfidential());
        assertEquals("https://app/cb", auth.redirectUri());
        assertEquals(List.of("openid", "email"), auth.scopes());
        AuthClient overridden = AuthClient.builder().env(env).clientSecret(null).transport(nine).build();
        assertFalse(overridden.isConfidential());
    }

    @Test
    void networkFailuresAreNineExceptionsWithoutDetails() {
        AuthClient auth = AuthClient.builder().issuer(nine.issuer).clientId(CLIENT).redirectUri(REDIRECT)
                .transport(r -> {
                    throw new java.net.ConnectException("refused");
                }).build();
        NineException e = assertThrows(NineException.class, auth::createLogin);
        assertEquals("network_error", e.error());
        assertNotNull(e.getCause());
    }

    @Test
    void toStringNeverShowsSecrets() {
        AuthClient auth = confidential();
        assertFalse(auth.toString().contains(SECRET));
        TokenSet tokens = signedIn(auth);
        assertFalse(tokens.toString().contains("at_1"));
        assertFalse(tokens.toString().contains("rt_1"));
        PendingLogin p = auth.createLogin().pending();
        assertFalse(p.toString().contains(p.codeVerifier()));
        assertFalse(p.toString().contains(p.state()));
    }
}
