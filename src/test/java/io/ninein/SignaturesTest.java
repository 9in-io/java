package io.ninein;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** The 9in signature scheme, including the reference vectors from the PHP SDK's SignatureTest. */
class SignaturesTest {
    static final String SECRET = "adapter_secret_test";
    static final String BODY = "{\"identifier\":{\"type\":\"email\",\"value\":\"jane@acme.com\"},\"password\":\"hunter2\"}";

    static long now() {
        return System.currentTimeMillis() / 1000;
    }

    static Signatures.Result check(List<String> secrets, String header, String method, String path, String body) {
        return Signatures.check(secrets, header, method, path, body.getBytes(StandardCharsets.UTF_8), Signatures.DEFAULT_TOLERANCE, Clock.systemUTC());
    }

    static Signatures.Result check(String secret, String header, String method, String path, String body) {
        return check(Collections.singletonList(secret), header, method, path, body);
    }

    @Test
    void matchesTheReferenceVectors() {
        // sso-sdk/php/tests/SignatureTest.php, computed with the 9in server's scheme.
        assertEquals("t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c",
                Signatures.sign(SECRET, "post", "/nine/authenticate", BODY, 1762682400L));
        assertEquals("t=1762682400,v1=1b9fb41e87bb256836ea5d5d6600270b77578ffd166d84a2cf35ab9841b3585a",
                Signatures.sign(SECRET, "POST", "/nine/authenticate#req_123", "{\"user\":{\"id\":\"42\"}}", 1762682400L));
        // and they verify at their own time
        Clock then = Clock.fixed(java.time.Instant.ofEpochSecond(1762682400L + 100), java.time.ZoneOffset.UTC);
        assertTrue(Signatures.check(Collections.singletonList(SECRET),
                "t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c",
                "POST", "/nine/authenticate", BODY.getBytes(StandardCharsets.UTF_8), Signatures.DEFAULT_TOLERANCE, then).ok());
    }

    @Test
    void roundTrip() {
        String header = Signatures.sign(SECRET, "POST", "/nine/user", "{\"id\":\"1\"}");
        assertTrue(Signatures.verify(SECRET, header, "POST", "/nine/user", "{\"id\":\"1\"}"));
        assertTrue(Signatures.verify(SECRET, header, "post", "/nine/user", "{\"id\":\"1\"}"));
    }

    @Test
    void rejectsTamperedBodyPathMethodAndSecret() {
        String header = Signatures.sign(SECRET, "POST", "/nine/user", "{\"id\":\"1\"}");
        assertEquals(Signatures.Reason.MISMATCH, check(SECRET, header, "POST", "/nine/user", "{\"id\":\"2\"}").reason());
        assertEquals(Signatures.Reason.MISMATCH, check(SECRET, header, "POST", "/nine/authenticate", "{\"id\":\"1\"}").reason());
        assertEquals(Signatures.Reason.MISMATCH, check(SECRET, header, "GET", "/nine/user", "{\"id\":\"1\"}").reason());
        assertEquals(Signatures.Reason.MISMATCH, check("other", header, "POST", "/nine/user", "{\"id\":\"1\"}").reason());
        assertEquals(Signatures.Reason.MISMATCH, check(SECRET, header, "POST", "/nine/user", "{\"id\":\"1\"} ").reason());
    }

    @Test
    void rejectsReplaysOutsideTheTolerance() {
        String old = Signatures.sign(SECRET, "POST", "/p", "b", now() - 301);
        assertEquals(Signatures.Reason.EXPIRED, check(SECRET, old, "POST", "/p", "b").reason());
        assertTrue(Signatures.check(Collections.singletonList(SECRET), old, "POST", "/p", "b".getBytes(StandardCharsets.UTF_8),
                Duration.ofSeconds(600), Clock.systemUTC()).ok());
        String future = Signatures.sign(SECRET, "POST", "/p", "b", now() + 301);
        assertFalse(Signatures.verify(SECRET, future, "POST", "/p", "b"));
        String edge = Signatures.sign(SECRET, "POST", "/p", "b", now() - 290);
        assertTrue(Signatures.verify(SECRET, edge, "POST", "/p", "b"));
    }

    @Test
    void missingHeader() {
        assertEquals(Signatures.Reason.MISSING, check(SECRET, null, "POST", "/p", "b").reason());
        assertEquals(Signatures.Reason.MISSING, check(SECRET, "", "POST", "/p", "b").reason());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "garbage", "t=abc,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "t=1",
        "v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "t=1,v1=ABC", "=x",
        "t=1,v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "t=1234567890123,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "t=-1,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "t=1,,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "t=1,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    void malformedHeaders(String bad) {
        assertEquals(Signatures.Reason.MALFORMED, check(SECRET, bad, "POST", "/p", "b").reason(), bad);
    }

    @Test
    void secretRotationAndSeveralSignatures() {
        String header = Signatures.sign("new-secret", "POST", "/p", "b");
        assertTrue(check(Arrays.asList("old-secret", "new-secret"), header, "POST", "/p", "b").ok());
        long t = now();
        String old = Signatures.sign("old-secret", "POST", "/p", "b", t);
        String combined = old + "," + Signatures.sign("new-secret", "POST", "/p", "b", t).split(",")[1];
        assertTrue(check("new-secret", combined, "POST", "/p", "b").ok());
        assertTrue(check("old-secret", combined, "POST", "/p", "b").ok());
        // unknown parameters (future versions) are ignored, spaces are trimmed
        assertTrue(check("new-secret", " t=" + t + " , v0=zz , " + combined.split(",")[2].trim(), "POST", "/p", "b").ok());
        // empty secrets never match
        assertFalse(check(Arrays.asList("", null), header, "POST", "/p", "b").ok());
    }

    @Test
    void requireThrows() {
        SignatureException e = assertThrows(SignatureException.class, () -> Signatures.require(Collections.singletonList(SECRET),
                "t=1,v1=" + new String(new char[64]).replace('\0', '0'), "POST", "/p", "b".getBytes(StandardCharsets.UTF_8), Signatures.DEFAULT_TOLERANCE, Clock.systemUTC()));
        assertEquals("invalid_signature", e.error());
        assertEquals("expired", e.reason());
        assertEquals(401, e.status());
    }

    @Test
    void bytesAndStringsSignAlike() {
        byte[] body = "{\"x\":\"é\"}".getBytes(StandardCharsets.UTF_8);
        assertEquals(Signatures.sign(SECRET, "POST", "/p", body, 1L), Signatures.sign(SECRET, "POST", "/p", "{\"x\":\"é\"}", 1L));
        assertThrows(IllegalArgumentException.class, () -> Signatures.sign("", "POST", "/p", "b"));
    }
}
