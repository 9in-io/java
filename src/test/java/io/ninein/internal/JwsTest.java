package io.ninein.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.ninein.NineException;
import io.ninein.testing.TestKeys;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JwsTest {
    static final byte[] INPUT = Codec.utf8("eyJhbGciOiJ0ZXN0In0.eyJzdWIiOiIxIn0");

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"})
    void verifiesEveryAlgorithmAndRejectsTampering(String alg) {
        assumeTrue(!alg.equals("EdDSA") || TestKeys.ed25519Available());
        TestKeys key = TestKeys.of(alg);
        byte[] sig = key.sign(alg, INPUT);
        assertTrue(Jws.verify(alg, key.jwk, INPUT, sig));
        byte[] tampered = INPUT.clone();
        tampered[3] ^= 1;
        assertFalse(Jws.verify(alg, key.jwk, tampered, sig));
        byte[] badSig = sig.clone();
        badSig[badSig.length / 2] ^= 1;
        assertFalse(Jws.verify(alg, key.jwk, INPUT, badSig));
        assertFalse(Jws.verify(alg, key.jwk, INPUT, Arrays.copyOf(sig, sig.length - 1)));
        assertFalse(Jws.verify(alg, key.jwk, INPUT, new byte[0]));
        // another key of the same type
        assertFalse(Jws.verify(alg, TestKeys.fresh(alg, "other").jwk, INPUT, sig));
    }

    @Test
    void pssNeedsTheExactSaltLength() throws Exception {
        TestKeys key = TestKeys.of("PS256");
        byte[] right = TestKeys.pss("SHA-256", MGF1ParameterSpec.SHA256, 32, key.pair.getPrivate(), INPUT);
        byte[] shortSalt = TestKeys.pss("SHA-256", MGF1ParameterSpec.SHA256, 20, key.pair.getPrivate(), INPUT);
        byte[] noSalt = TestKeys.pss("SHA-256", MGF1ParameterSpec.SHA256, 0, key.pair.getPrivate(), INPUT);
        byte[] otherMgf = TestKeys.pss("SHA-256", MGF1ParameterSpec.SHA1, 32, key.pair.getPrivate(), INPUT);
        assertTrue(Jws.verify("PS256", key.jwk, INPUT, right));
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, shortSalt));
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, noSalt));
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, otherMgf));
        // a PKCS#1 v1.5 signature is not a PSS one, and vice versa
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, key.sign("RS256", INPUT)));
        assertFalse(Jws.verify("RS256", key.jwk, INPUT, right));
        // PS384 / PS512 with another RSA key
        TestKeys big = TestKeys.fresh("PS512", "big");
        assertTrue(Jws.verify("PS512", big.jwk, INPUT, big.sign("PS512", INPUT)));
        assertTrue(Jws.verify("PS384", big.jwk, INPUT, big.sign("PS384", INPUT)));
    }

    /** EMSA-PSS encodings built by hand and signed with the raw RSA private operation. */
    @Test
    void pssRejectsMalformedEncodings() throws Exception {
        TestKeys key = TestKeys.of("PS256");
        java.security.interfaces.RSAPrivateKey priv = (java.security.interfaces.RSAPrivateKey) key.pair.getPrivate();
        assertTrue(Jws.verify("PS256", key.jwk, INPUT, craftPss(priv, 0x01, 0, 0xbc, false)), "a correct hand-made encoding verifies");
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, craftPss(priv, 0x00, 0, 0xbc, false)), "separator byte not 0x01");
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, craftPss(priv, 0x02, 0, 0xbc, false)), "separator byte 0x02");
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, craftPss(priv, 0x01, 1, 0xbc, false)), "non-zero padding");
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, craftPss(priv, 0x01, 0, 0xbd, false)), "wrong trailer");
        assertFalse(Jws.verify("PS256", key.jwk, INPUT, craftPss(priv, 0x01, 0, 0xbc, true)), "top bit set");
    }

    private static byte[] craftPss(java.security.interfaces.RSAPrivateKey priv, int separator, int paddingByte, int trailer, boolean topBit) throws Exception {
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        int modBits = priv.getModulus().bitLength();
        int k = (modBits + 7) / 8;
        int emLen = (modBits - 1 + 7) / 8;
        int hLen = 32;
        byte[] salt = new byte[32];
        new java.security.SecureRandom().nextBytes(salt);
        byte[] mHash = sha.digest(INPUT);
        sha.update(new byte[8]);
        sha.update(mHash);
        sha.update(salt);
        byte[] h = sha.digest();
        byte[] db = new byte[emLen - hLen - 1];
        int psLen = db.length - salt.length - 1;
        if (paddingByte != 0) db[psLen / 2] = (byte) paddingByte;
        db[psLen] = (byte) separator;
        System.arraycopy(salt, 0, db, psLen + 1, salt.length);
        byte[] mask = new byte[db.length];
        java.io.ByteArrayOutputStream mgf = new java.io.ByteArrayOutputStream();
        for (int c = 0; mgf.size() < db.length; c++) {
            sha.update(h);
            sha.update(new byte[] {(byte) (c >>> 24), (byte) (c >>> 16), (byte) (c >>> 8), (byte) c});
            byte[] block = sha.digest();
            mgf.write(block, 0, block.length);
        }
        System.arraycopy(mgf.toByteArray(), 0, mask, 0, db.length);
        byte[] em = new byte[emLen];
        for (int i = 0; i < db.length; i++) em[i] = (byte) (db[i] ^ mask[i]);
        int zeroBits = 8 * emLen - (modBits - 1);
        em[0] &= (byte) (0xff >>> zeroBits);
        if (topBit) em[0] |= (byte) 0x80;
        System.arraycopy(h, 0, em, db.length, hLen);
        em[emLen - 1] = (byte) trailer;
        BigInteger s = new BigInteger(1, em).modPow(priv.getPrivateExponent(), priv.getModulus());
        byte[] raw = s.toByteArray();
        byte[] out = new byte[k];
        if (raw.length > k) System.arraycopy(raw, raw.length - k, out, 0, k);
        else System.arraycopy(raw, 0, out, k - raw.length, raw.length);
        return out;
    }

    @Test
    void pssWithA4096BitKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(4096);
        java.security.KeyPair pair = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", Codec.base64Url(strip(pub.getModulus())));
        jwk.put("e", Codec.base64Url(strip(pub.getPublicExponent())));
        for (String alg : new String[] {"PS256", "PS384", "PS512", "RS256", "RS512"}) {
            assertTrue(Jws.verify(alg, jwk, INPUT, TestKeys.sign(alg, pair.getPrivate(), INPUT)), alg);
        }
    }

    @Test
    void smallRsaKeysAreRefused() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        java.security.KeyPair pair = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", Codec.base64Url(strip(pub.getModulus())));
        jwk.put("e", Codec.base64Url(strip(pub.getPublicExponent())));
        assertFalse(Jws.verify("RS256", jwk, INPUT, TestKeys.sign("RS256", pair.getPrivate(), INPUT)));
        assertFalse(Jws.verify("PS256", jwk, INPUT, TestKeys.sign("PS256", pair.getPrivate(), INPUT)));
    }

    @Test
    void ecdsaRejectsOutOfRangeValues() {
        TestKeys key = TestKeys.of("ES256");
        byte[] zeros = new byte[64];
        assertFalse(Jws.verify("ES256", key.jwk, INPUT, zeros));
        byte[] ones = new byte[64];
        Arrays.fill(ones, (byte) 0xff);
        assertFalse(Jws.verify("ES256", key.jwk, INPUT, ones));
        // a DER signature is not the JOSE form
        assertFalse(Jws.verify("ES256", key.jwk, INPUT, Jws.derSignature(BigInteger.ONE, BigInteger.ONE)));
        // coordinates of the wrong length
        assertFalse(Jws.verify("ES256", key.jwkWith("x", Codec.base64Url(new byte[31])), INPUT, key.sign("ES256", INPUT)));
        // a point that is not on the curve
        assertFalse(Jws.verify("ES256", key.jwkWith("y", key.jwk.get("x")), INPUT, key.sign("ES256", INPUT)));
    }

    @Test
    void keyMustFitTheAlgorithm() {
        assertTrue(Jws.fits(TestKeys.of("RS256").jwk, "PS512"));
        assertFalse(Jws.fits(TestKeys.of("RS256").jwk, "ES256"));
        assertFalse(Jws.fits(TestKeys.of("ES256").jwk, "ES384"));
        assertFalse(Jws.fits(TestKeys.of("ES384").jwk, "ES256"));
        assertFalse(Jws.fits(TestKeys.of("ES256").jwk, "EdDSA"));
        assertFalse(Jws.fits(TestKeys.of("RS256").jwk, "HS256"));
        assertFalse(Jws.fits(TestKeys.of("RS256").jwk, "none"));
        TestKeys es = TestKeys.of("ES256");
        assertFalse(Jws.verify("ES256", TestKeys.of("RS256").jwk, INPUT, es.sign("ES256", INPUT)));
    }

    @Test
    void hmac() {
        for (String alg : TestKeys.HMAC) {
            String token = io.ninein.testing.Jwts.hmac(alg, "k", io.ninein.testing.Jwts.header(alg, null, null), new LinkedHashMap<>());
            String[] parts = token.split("\\.");
            byte[] input = Codec.utf8(parts[0] + "." + parts[1]);
            byte[] sig = Codec.base64UrlDecode(parts[2]);
            assertTrue(Jws.verifyHmac(alg, "k", input, sig));
            assertFalse(Jws.verifyHmac(alg, "K", input, sig));
            assertFalse(Jws.verifyHmac(alg, "", input, sig));
            assertFalse(Jws.verifyHmac(alg, null, input, sig));
        }
        assertFalse(Jws.verifyHmac("HS999", "k", INPUT, new byte[32]));
    }

    @Test
    void edDsaWithoutRuntimeSupportIsAClearError() {
        assumeFalse(TestKeys.ed25519Available(), "Java 11-14 only");
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", Codec.base64Url(new byte[32]));
        NineException e = assertThrows(NineException.class, () -> Jws.verify("EdDSA", jwk, INPUT, new byte[64]));
        assertEquals("unsupported_algorithm", e.error());
        assertFalse(Jws.isSupportedByRuntime("EdDSA"));
    }

    @Test
    void edDsaRejectsWrongLengths() {
        assumeTrue(TestKeys.ed25519Available());
        TestKeys key = TestKeys.of("EdDSA");
        assertTrue(Jws.isSupportedByRuntime("EdDSA"));
        assertFalse(Jws.verify("EdDSA", key.jwkWith("x", Codec.base64Url(new byte[31])), INPUT, key.sign("EdDSA", INPUT)));
        assertFalse(Jws.verify("EdDSA", key.jwk, INPUT, new byte[63]));
    }

    @Test
    void base64UrlIsStrict() {
        assertThrows(IllegalArgumentException.class, () -> Codec.base64UrlDecode("ab+c"));
        assertThrows(IllegalArgumentException.class, () -> Codec.base64UrlDecode("ab/c"));
        assertThrows(IllegalArgumentException.class, () -> Codec.base64UrlDecode("ab c"));
        assertEquals("hi", new String(Codec.base64UrlDecode("aGk")));
    }

    private static byte[] strip(BigInteger v) {
        byte[] raw = v.toByteArray();
        return raw[0] == 0 ? Arrays.copyOfRange(raw, 1, raw.length) : raw;
    }
}
