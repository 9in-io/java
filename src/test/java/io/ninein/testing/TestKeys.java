package io.ninein.testing;

import io.ninein.internal.Codec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Signing keys for every JWS algorithm 9in uses, with their public JWKs. Keys are generated once per run. */
public final class TestKeys {
    public static final String[] ASYMMETRIC = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"};
    public static final String[] HMAC = {"HS256", "HS384", "HS512"};
    public static final String HMAC_SECRET = "api-shared-secret-for-tests-0123456789abcdef";

    private static final Map<String, TestKeys> CACHE = new ConcurrentHashMap<>();

    public final String alg;
    public final String kid;
    public final KeyPair pair;
    public final Map<String, Object> jwk;

    private TestKeys(String alg, String kid, KeyPair pair, Map<String, Object> jwk) {
        this.alg = alg;
        this.kid = kid;
        this.pair = pair;
        this.jwk = jwk;
    }

    /** True when the running JDK has Ed25519 (Java 15+). */
    public static boolean ed25519Available() {
        try {
            KeyPairGenerator.getInstance("Ed25519");
            Signature.getInstance("Ed25519");
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    /** The (cached) key for an asymmetric algorithm, kid "k_<alg>". */
    public static TestKeys of(String alg) {
        return CACHE.computeIfAbsent(alg, a -> generate(a, "k_" + a.toLowerCase()));
    }

    /** A fresh key with its own kid. */
    public static TestKeys fresh(String alg, String kid) {
        return generate(alg, kid);
    }

    private static TestKeys generate(String alg, String kid) {
        try {
            KeyPair pair;
            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kid", kid);
            jwk.put("use", "sig");
            jwk.put("alg", alg);
            if (alg.startsWith("RS") || alg.startsWith("PS")) {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(2048);
                pair = g.generateKeyPair();
                RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
                jwk.put("kty", "RSA");
                jwk.put("n", Codec.base64Url(unsigned(pub.getModulus())));
                jwk.put("e", Codec.base64Url(unsigned(pub.getPublicExponent())));
            } else if (alg.equals("ES256") || alg.equals("ES384")) {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec(alg.equals("ES256") ? "secp256r1" : "secp384r1"));
                pair = g.generateKeyPair();
                ECPublicKey pub = (ECPublicKey) pair.getPublic();
                int size = alg.equals("ES256") ? 32 : 48;
                jwk.put("kty", "EC");
                jwk.put("crv", alg.equals("ES256") ? "P-256" : "P-384");
                jwk.put("x", Codec.base64Url(fixed(pub.getW().getAffineX(), size)));
                jwk.put("y", Codec.base64Url(fixed(pub.getW().getAffineY(), size)));
            } else if (alg.equals("EdDSA")) {
                pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                byte[] spki = pair.getPublic().getEncoded();
                jwk.put("kty", "OKP");
                jwk.put("crv", "Ed25519");
                jwk.put("x", Codec.base64Url(Arrays.copyOfRange(spki, spki.length - 32, spki.length)));
            } else {
                throw new IllegalArgumentException(alg);
            }
            return new TestKeys(alg, kid, pair, jwk);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The JWK without its "alg" member. */
    public Map<String, Object> jwkWithoutAlg() {
        Map<String, Object> copy = new LinkedHashMap<>(jwk);
        copy.remove("alg");
        return copy;
    }

    /** The JWK with other members replaced. */
    public Map<String, Object> jwkWith(String member, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(jwk);
        copy.put(member, value);
        return copy;
    }

    /** Signs {@code input} with this key as JWS algorithm {@code signAlg} (JOSE signature format). */
    public byte[] sign(String signAlg, byte[] input) {
        return sign(signAlg, pair.getPrivate(), input);
    }

    public static byte[] sign(String alg, PrivateKey key, byte[] input) {
        try {
            switch (alg) {
                case "RS256": return jca("SHA256withRSA", key, input);
                case "RS384": return jca("SHA384withRSA", key, input);
                case "RS512": return jca("SHA512withRSA", key, input);
                case "PS256": return pss("SHA-256", MGF1ParameterSpec.SHA256, 32, key, input);
                case "PS384": return pss("SHA-384", MGF1ParameterSpec.SHA384, 48, key, input);
                case "PS512": return pss("SHA-512", MGF1ParameterSpec.SHA512, 64, key, input);
                case "ES256": return rawEcdsa(jca("SHA256withECDSA", key, input), 32);
                case "ES384": return rawEcdsa(jca("SHA384withECDSA", key, input), 48);
                case "EdDSA": return jca("Ed25519", key, input);
                default: throw new IllegalArgumentException(alg);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RSASSA-PSS with an explicit salt length (to test that a wrong one is refused). */
    public static byte[] pss(String hash, MGF1ParameterSpec mgf, int saltLength, PrivateKey key, byte[] input) throws GeneralSecurityException {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec(hash, "MGF1", mgf, saltLength, 1));
        s.initSign(key);
        s.update(input);
        return s.sign();
    }

    private static byte[] jca(String name, PrivateKey key, byte[] input) throws GeneralSecurityException {
        Signature s = Signature.getInstance(name);
        s.initSign(key);
        s.update(input);
        return s.sign();
    }

    /** DER ECDSA signature to the JOSE R||S form. */
    static byte[] rawEcdsa(byte[] der, int size) {
        int offset = 2;
        if ((der[1] & 0x80) != 0) offset = 2 + (der[1] & 0x7f);
        int rLen = der[offset + 1];
        byte[] r = Arrays.copyOfRange(der, offset + 2, offset + 2 + rLen);
        int sOffset = offset + 2 + rLen;
        int sLen = der[sOffset + 1];
        byte[] s = Arrays.copyOfRange(der, sOffset + 2, sOffset + 2 + sLen);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] rf = fixed(new BigInteger(1, r), size);
        byte[] sf = fixed(new BigInteger(1, s), size);
        out.write(rf, 0, rf.length);
        out.write(sf, 0, sf.length);
        return out.toByteArray();
    }

    static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) return Arrays.copyOfRange(raw, 1, raw.length);
        return raw;
    }

    static byte[] fixed(BigInteger value, int size) {
        byte[] raw = unsigned(value);
        if (raw.length == size) return raw;
        byte[] out = new byte[size];
        System.arraycopy(raw, 0, out, size - raw.length, raw.length);
        return out;
    }
}
