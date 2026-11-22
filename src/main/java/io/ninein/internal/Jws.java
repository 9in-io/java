package io.ninein.internal;

import io.ninein.NineException;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * JWS signature verification with the JDK's own crypto, for every algorithm 9in signs with:
 * RS256/384/512, PS256/384/512 (RSASSA-PSS, MGF1 with the same hash, salt length = hash
 * length), ES256 (P-256), ES384 (P-384), EdDSA (Ed25519, Java 15+ and recent Android) and
 * HS256/384/512. Works on Android API 26+ (EdDSA where the platform has it).
 *
 * <p>RSASSA-PSS is verified here (EMSA-PSS-VERIFY, RFC 8017 9.1.2) on the RSA public-key
 * operation, so it works on every runtime (the JDK and Android name and parameterise PSS
 * differently) and enforces the JWS salt length exactly. Internal to the SDK.
 */
public final class Jws {
    public static final Set<String> ASYMMETRIC = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA")));
    public static final Set<String> HMAC = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("HS256", "HS384", "HS512")));

    private static final byte[] ED25519_SPKI_PREFIX = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    private Jws() {}

    /** Whether a JWK can verify {@code alg} (key type and curve), independent of its {@code alg} member. */
    public static boolean fits(Map<String, Object> jwk, String alg) {
        String kty = Json.string(jwk, "kty");
        String crv = Json.string(jwk, "crv");
        switch (alg) {
            case "RS256": case "RS384": case "RS512":
            case "PS256": case "PS384": case "PS512":
                return "RSA".equals(kty);
            case "ES256":
                return "EC".equals(kty) && "P-256".equals(crv);
            case "ES384":
                return "EC".equals(kty) && "P-384".equals(crv);
            case "EdDSA":
                return "OKP".equals(kty) && "Ed25519".equals(crv);
            default:
                return false;
        }
    }

    /**
     * Verifies an asymmetric signature with a public JWK. Returns false for a bad signature or a
     * key that doesn't fit; throws {@code unsupported_algorithm} when the runtime lacks the
     * algorithm (EdDSA before Java 15).
     */
    public static boolean verify(String alg, Map<String, Object> jwk, byte[] input, byte[] signature) {
        if (!fits(jwk, alg)) return false;
        try {
            switch (alg) {
                case "RS256": return verifyJca("SHA256withRSA", rsaKey(jwk), input, signature);
                case "RS384": return verifyJca("SHA384withRSA", rsaKey(jwk), input, signature);
                case "RS512": return verifyJca("SHA512withRSA", rsaKey(jwk), input, signature);
                case "PS256": return verifyPss("SHA-256", jwk, input, signature);
                case "PS384": return verifyPss("SHA-384", jwk, input, signature);
                case "PS512": return verifyPss("SHA-512", jwk, input, signature);
                case "ES256": return verifyEc("SHA256withECDSA", "secp256r1", 32, jwk, input, signature);
                case "ES384": return verifyEc("SHA384withECDSA", "secp384r1", 48, jwk, input, signature);
                case "EdDSA": return verifyEd25519(jwk, input, signature);
                default: return false;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new NineException("unsupported_algorithm", alg + " is not supported by this Java runtime", 401, e);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Whether this runtime can verify {@code alg} (EdDSA needs Java 15+ or a provider). */
    public static boolean isSupportedByRuntime(String alg) {
        if (!"EdDSA".equals(alg)) return ASYMMETRIC.contains(alg) || HMAC.contains(alg);
        try {
            KeyFactory.getInstance("Ed25519");
            Signature.getInstance("Ed25519");
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    /** HS256/384/512 with a shared secret (UTF-8), compared in constant time. */
    public static boolean verifyHmac(String alg, String secret, byte[] input, byte[] signature) {
        if (secret == null || secret.isEmpty()) return false;
        String name;
        switch (alg) {
            case "HS256": name = "HmacSHA256"; break;
            case "HS384": name = "HmacSHA384"; break;
            case "HS512": name = "HmacSHA512"; break;
            default: return false;
        }
        try {
            Mac mac = Mac.getInstance(name);
            mac.init(new SecretKeySpec(Codec.utf8(secret), name));
            return MessageDigest.isEqual(mac.doFinal(input), signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static boolean verifyJca(String algorithm, PublicKey key, byte[] input, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(key);
        verifier.update(input);
        try {
            return verifier.verify(signature);
        } catch (java.security.SignatureException e) {
            return false; // malformed signature bytes
        }
    }

    private static BigInteger unsigned(Map<String, Object> jwk, String member) {
        String value = Json.string(jwk, member);
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("JWK without " + member);
        return new BigInteger(1, Codec.base64UrlDecode(value));
    }

    private static PublicKey rsaKey(Map<String, Object> jwk) throws GeneralSecurityException {
        BigInteger n = unsigned(jwk, "n");
        BigInteger e = unsigned(jwk, "e");
        if (n.bitLength() < 2048) throw new InvalidKeyException("RSA keys must have at least 2048 bits");
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }

    private static boolean verifyEc(String algorithm, String curve, int size, Map<String, Object> jwk, byte[] input, byte[] signature)
            throws GeneralSecurityException {
        if (signature.length != 2 * size) return false;
        byte[] x = Codec.base64UrlDecode(requireMember(jwk, "x"));
        byte[] y = Codec.base64UrlDecode(requireMember(jwk, "y"));
        if (x.length != size || y.length != size) return false;
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, size));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, size, 2 * size));
        BigInteger order = spec.getOrder();
        if (r.signum() == 0 || s.signum() == 0 || r.compareTo(order) >= 0 || s.compareTo(order) >= 0) return false;
        return verifyJca(algorithm, key, input, derSignature(r, s));
    }

    private static boolean verifyEd25519(Map<String, Object> jwk, byte[] input, byte[] signature) throws GeneralSecurityException {
        byte[] x = Codec.base64UrlDecode(requireMember(jwk, "x"));
        if (x.length != 32 || signature.length != 64) return false;
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        Signature verifier = Signature.getInstance("Ed25519");
        byte[] spki = new byte[ED25519_SPKI_PREFIX.length + 32];
        System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
        System.arraycopy(x, 0, spki, ED25519_SPKI_PREFIX.length, 32);
        PublicKey key = factory.generatePublic(new X509EncodedKeySpec(spki));
        verifier.initVerify(key);
        verifier.update(input);
        try {
            return verifier.verify(signature);
        } catch (java.security.SignatureException e) {
            return false;
        }
    }

    private static String requireMember(Map<String, Object> jwk, String member) {
        String value = Json.string(jwk, member);
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("JWK without " + member);
        return value;
    }

    /** RSASSA-PSS with MGF1 over the same hash and salt length = hash length (RFC 7518 3.5). */
    private static boolean verifyPss(String hash, Map<String, Object> jwk, byte[] input, byte[] signature) throws GeneralSecurityException {
        BigInteger n = unsigned(jwk, "n");
        BigInteger e = unsigned(jwk, "e");
        int modBits = n.bitLength();
        if (modBits < 2048) return false;
        int k = (modBits + 7) / 8;
        if (signature.length != k) return false;
        BigInteger s = new BigInteger(1, signature);
        if (s.compareTo(n) >= 0) return false;
        byte[] m = toFixed(s.modPow(e, n), k);

        MessageDigest digest = MessageDigest.getInstance(hash);
        int hLen = digest.getDigestLength();
        int sLen = hLen;
        int emBits = modBits - 1;
        int emLen = (emBits + 7) / 8;
        // EM is the last emLen bytes of m; when emLen < k the leading byte of m must be zero.
        for (int i = 0; i < k - emLen; i++) if (m[i] != 0) return false;
        byte[] em = Arrays.copyOfRange(m, k - emLen, k);
        if (emLen < hLen + sLen + 2) return false;
        if ((em[emLen - 1] & 0xff) != 0xbc) return false;
        byte[] maskedDb = Arrays.copyOfRange(em, 0, emLen - hLen - 1);
        byte[] h = Arrays.copyOfRange(em, emLen - hLen - 1, emLen - 1);
        int zeroBits = 8 * emLen - emBits;
        int topMask = (0xff << (8 - zeroBits)) & 0xff;
        if ((maskedDb[0] & topMask) != 0) return false;
        byte[] dbMask = mgf1(hash, h, emLen - hLen - 1);
        byte[] db = new byte[maskedDb.length];
        for (int i = 0; i < db.length; i++) db[i] = (byte) (maskedDb[i] ^ dbMask[i]);
        db[0] &= (byte) (0xff >>> zeroBits);
        int psLen = emLen - hLen - sLen - 2;
        for (int i = 0; i < psLen; i++) if (db[i] != 0) return false;
        if (db[psLen] != 0x01) return false;
        byte[] salt = Arrays.copyOfRange(db, db.length - sLen, db.length);
        byte[] mHash = MessageDigest.getInstance(hash).digest(input);
        MessageDigest d = MessageDigest.getInstance(hash);
        d.update(new byte[8]);
        d.update(mHash);
        d.update(salt);
        return MessageDigest.isEqual(h, d.digest());
    }

    private static byte[] mgf1(String hash, byte[] seed, int length) throws NoSuchAlgorithmException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MessageDigest digest = MessageDigest.getInstance(hash);
        for (int counter = 0; out.size() < length; counter++) {
            digest.update(seed);
            digest.update(new byte[] {(byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8), (byte) counter});
            byte[] block = digest.digest();
            out.write(block, 0, block.length);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    private static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) return raw;
        byte[] out = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, out, 0, length); // drop the sign byte
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }

    /** DER SEQUENCE { INTEGER r, INTEGER s } for the JCA ECDSA verifier. */
    static byte[] derSignature(BigInteger r, BigInteger s) {
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x02);
        writeLength(body, rb.length);
        body.write(rb, 0, rb.length);
        body.write(0x02);
        writeLength(body, sb.length);
        body.write(sb, 0, sb.length);
        byte[] content = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeLength(out, content.length);
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else {
            out.write(0x82);
            out.write(length >>> 8);
            out.write(length & 0xff);
        }
    }
}
