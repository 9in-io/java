package io.ninein;

import static io.ninein.testing.FakeNine.list;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.ninein.internal.Codec;
import io.ninein.testing.FakeNine;
import io.ninein.testing.Jwts;
import io.ninein.testing.TestClock;
import io.ninein.testing.TestKeys;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenVerifierTest {
    static final String API = "https://api.example.com";

    FakeNine nine;
    TestClock clock;
    TokenVerifier verifier;

    @BeforeEach
    void setUp() {
        nine = new FakeNine();
        clock = new TestClock();
        verifier = TokenVerifier.builder().issuer(nine.issuer).audience(API).secret(TestKeys.HMAC_SECRET).transport(nine).clock(clock).build();
    }

    Jwts.Claims claims() {
        long now = clock.epochSecond();
        return Jwts.claims().with("iss", nine.issuer).with("sub", "usr_1").with("aud", API).with("client_id", "app_1")
                .with("scope", "openid orders:read orders:write").with("iat", now).with("exp", now + 600).with("jti", "j1").with("sid", "s1");
    }

    String token(String alg, Function<Jwts.Claims, Jwts.Claims> tweak) {
        return Jwts.sign(alg, "at+jwt", tweak.apply(claims()));
    }

    void refused(String token, String why) {
        InvalidTokenException e = assertThrows(InvalidTokenException.class, () -> verifier.verify(token), why);
        assertEquals("invalid_token", e.error());
        assertEquals(401, e.status());
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512"})
    void acceptsEveryAlgorithm(String alg) {
        assumeTrue(!alg.equals("EdDSA") || TestKeys.ed25519Available(), "Ed25519 needs Java 15+");
        AccessTokenClaims c = verifier.verify("Bearer " + token(alg, x -> x), "orders:read");
        assertEquals("usr_1", c.subject());
        assertEquals("app_1", c.clientId());
        assertEquals(Arrays.asList("openid", "orders:read", "orders:write"), c.scopes());
        assertTrue(c.hasScope("orders:write"));
        assertEquals("j1", c.tokenId());
        assertEquals("s1", c.sessionId());
        assertEquals(Arrays.asList(API), c.audience());
        assertEquals(clock.epochSecond() + 600, c.expiresAt().getEpochSecond());
        assertEquals(nine.issuer, c.issuer());
    }

    @Test
    void typeMustBeAtJwt() {
        refused(Jwts.sign("RS256", "JWT", claims()), "ID-token type");
        refused(Jwts.sign("RS256", null, claims()), "no type");
        verifier.verify(Jwts.sign("RS256", "application/at+jwt", claims()));
        verifier.verify(Jwts.sign("RS256", "AT+JWT", claims()));
    }

    @Test
    void algorithmAttacks() {
        refused(Jwts.none(claims(), "at+jwt"), "alg none");
        refused(Jwts.hmac("HS256", "wrong-secret", Jwts.header("HS256", null, "at+jwt"), claims()), "wrong HMAC secret");
        // HMAC with the RSA public key's modulus as the secret (classic confusion)
        String n = (String) TestKeys.of("RS256").jwk.get("n");
        refused(Jwts.hmac("HS256", n, Jwts.header("HS256", "k_rs256", "at+jwt"), claims()), "HS256 with public key material");
        // ES256 header with an RSA kid
        refused(Jwts.sign(TestKeys.of("ES256"), "ES256", Jwts.header("ES256", "k_rs256", "at+jwt"), claims()), "ES256 with an RSA key");
        // RS512 header with the RS256 key (the JWK names RS256)
        refused(Jwts.sign(TestKeys.of("RS256"), "RS512", Jwts.header("RS512", "k_rs256", "at+jwt"), claims()), "alg differs from the JWK's");
        Map<String, Object> unknown = Jwts.header("XS256", "k_rs256", "at+jwt");
        refused(Jwts.sign(TestKeys.of("RS256"), "RS256", unknown, claims()), "unknown alg");
    }

    @Test
    void hmacTokenWithoutASecret() {
        TokenVerifier noSecret = TokenVerifier.builder().issuer(nine.issuer).audience(API).transport(nine).clock(clock).build();
        InvalidTokenException e = assertThrows(InvalidTokenException.class, () -> noSecret.verify(token("HS256", x -> x)));
        assertTrue(e.description().contains("secret"));
    }

    @Test
    void tamperedSignatureAndPayload() {
        String good = token("ES256", x -> x);
        refused(Jwts.tamper(good, claims().with("scope", "admin")), "tampered payload");
        String[] parts = good.split("\\.");
        byte[] sig = Codec.base64UrlDecode(parts[2]);
        sig[5] ^= 1;
        refused(parts[0] + "." + parts[1] + "." + Codec.base64Url(sig), "tampered signature");
        refused(parts[0] + "." + parts[1] + ".", "no signature");
    }

    @Test
    void claimChecks() {
        long now = clock.epochSecond();
        refused(token("RS256", c -> c.with("exp", now - 31)), "expired");
        refused(token("RS256", c -> c.without("exp")), "no exp");
        refused(token("RS256", c -> c.with("exp", "tomorrow")), "string exp");
        refused(token("RS256", c -> c.with("nbf", now + 31)), "not yet valid");
        refused(token("RS256", c -> c.with("iss", nine.issuer + "/other")), "wrong issuer");
        refused(token("RS256", c -> c.with("aud", "https://other.example.com")), "wrong audience");
        refused(token("RS256", c -> c.without("aud")), "no audience");
        verifier.verify(token("RS256", c -> c.with("exp", now - 29).with("nbf", now + 29)));
        verifier.verify(token("RS256", c -> c.with("aud", list("https://other.example.com", API))));
        verifier.verify(token("RS256", c -> c.with("iss", nine.issuer + "/")));
    }

    @Test
    void scopes() {
        String t = token("RS256", c -> c);
        verifier.verify(t, "orders:read orders:write");
        verifier.verify(t, "orders:read", "openid");
        InsufficientScopeException e = assertThrows(InsufficientScopeException.class, () -> verifier.verify(t, "orders:read admin"));
        assertEquals("insufficient_scope", e.error());
        assertEquals(403, e.status());
        assertTrue(e.description().contains("admin"));
        assertThrows(InsufficientScopeException.class, () -> verifier.verify(token("RS256", c -> c.without("scope")), "orders:read"));
        // "orders" is not "orders:read"
        assertThrows(InsufficientScopeException.class, () -> verifier.verify(t, "orders"));
    }

    @Test
    void missingAndMalformed() {
        refused(null, "null");
        refused("", "empty");
        refused("Bearer ", "bearer only");
        refused("abc", "one part");
        refused("a.b", "two parts");
        refused("a.b.c.d", "four parts");
        refused("!!!.???.###", "not base64url");
        refused(Jwts.encode(Jwts.header("RS256", "k_rs256", "at+jwt")) + "." + Codec.base64Url(Codec.utf8("[1,2]")) + ".sig", "payload not an object");
        refused(Codec.base64Url(new byte[] {(byte) 0xff, (byte) 0xfe}) + "." + Jwts.encode(claims()) + ".sig", "header not UTF-8");
        Map<String, Object> dup = new HashMap<>();
        refused(Codec.base64Url(Codec.utf8("{\"alg\":\"RS256\",\"alg\":\"none\",\"typ\":\"at+jwt\"}")) + "." + Jwts.encode(claims()) + ".x", "duplicate header keys");
        assertTrue(dup.isEmpty());
    }

    @Test
    void bearerPrefixIsOptionalAndCaseInsensitive() {
        String t = token("RS256", c -> c);
        verifier.verify(t);
        verifier.verify("bearer " + t);
        verifier.verify("BEARER   " + t + "  ");
    }

    @Test
    void anyAudienceWithoutConfiguration() {
        TokenVerifier any = TokenVerifier.builder().issuer(nine.issuer).transport(nine).clock(clock).build();
        any.verify(token("RS256", c -> c.with("aud", "https://whatever")));
    }

    @Test
    void severalConfiguredAudiences() {
        TokenVerifier multi = TokenVerifier.builder().issuer(nine.issuer).audience("https://a", API).transport(nine).clock(clock).build();
        multi.verify(token("RS256", c -> c));
        assertThrows(InvalidTokenException.class, () -> multi.verify(token("RS256", c -> c.with("aud", "https://b"))));
    }

    @Test
    void unknownKidRefetchThenThrottle() {
        verifier.verify(token("RS256", c -> c));
        assertEquals(1, nine.count("/jwks.json"));
        TestKeys rotated = TestKeys.fresh("PS256", "k_rotated");
        nine.jwks.add(rotated.jwk);
        verifier.verify(Jwts.sign(rotated, "PS256", Jwts.header("PS256", "k_rotated", "at+jwt"), claims()));
        assertEquals(2, nine.count("/jwks.json"));
        String junk = Jwts.sign(TestKeys.of("RS256"), "RS256", Jwts.header("RS256", "k_junk", "at+jwt"), claims());
        for (int i = 0; i < 5; i++) refused(junk, "unknown kid");
        assertEquals(3, nine.count("/jwks.json"));
        clock.advance(Duration.ofSeconds(61));
        refused(junk, "unknown kid after the throttle");
        assertEquals(4, nine.count("/jwks.json"));
    }

    @Test
    void retiredKeyRemovedFromJwksIsRefusedAfterRefresh() {
        String t = token("ES384", c -> c);
        verifier.verify(t);
        nine.jwks.removeIf(k -> "k_es384".equals(k.get("kid")));
        clock.advance(Duration.ofMinutes(11));
        refused(token("ES384", c -> c), "key no longer published");
    }

    @Test
    void edDsaOnARuntimeWithoutEd25519() {
        assumeFalse(TestKeys.ed25519Available(), "Java 11-14 only");
        nine.jwks.add(FakeNine.map("kty", "OKP", "crv", "Ed25519", "kid", "k_ed", "alg", "EdDSA", "x", Codec.base64Url(new byte[32])));
        String t = Jwts.encode(Jwts.header("EdDSA", "k_ed", "at+jwt")) + "." + Jwts.encode(claims()) + "." + Codec.base64Url(new byte[64]);
        NineException e = assertThrows(NineException.class, () -> verifier.verify(t));
        assertEquals("unsupported_algorithm", e.error());
        assertEquals(401, e.status());
    }

    @Test
    void outagesAreNotTokenErrors() {
        nine.on("GET", "/.well-known/jwks.json", r -> FakeNine.json(503, null));
        NineException e = assertThrows(NineException.class, () -> verifier.verify(token("RS256", c -> c)));
        assertEquals("jwks_unavailable", e.error());
        assertTrue(!(e instanceof InvalidTokenException));
    }

    @Test
    void fromEnv() {
        Map<String, String> env = new HashMap<>();
        env.put("NINE_ISSUER", nine.issuer);
        env.put("NINE_AUDIENCE", "https://signin-audience");
        env.put("NINE_API_AUDIENCE", API);
        env.put("NINE_API_SECRET", TestKeys.HMAC_SECRET);
        TokenVerifier v = TokenVerifier.builder().env(env).transport(nine).clock(clock).build();
        assertEquals(Arrays.asList(API), v.audiences());
        v.verify(token("HS512", c -> c));
    }
}
