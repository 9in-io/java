package io.ninein.testing;

import io.ninein.internal.Codec;
import io.ninein.internal.Json;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Builds signed JWTs for tests. */
public final class Jwts {
    private Jwts() {}

    public static Map<String, Object> header(String alg, String kid, String typ) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("alg", alg);
        if (kid != null) h.put("kid", kid);
        if (typ != null) h.put("typ", typ);
        return h;
    }

    /** Signs with the cached key of {@code alg} (asymmetric) or {@link TestKeys#HMAC_SECRET} (HS*). */
    public static String sign(String alg, String typ, Map<String, Object> payload) {
        if (alg.startsWith("HS")) return hmac(alg, TestKeys.HMAC_SECRET, header(alg, "k_hmac", typ), payload);
        TestKeys key = TestKeys.of(alg);
        return sign(key, alg, header(alg, key.kid, typ), payload);
    }

    public static String sign(TestKeys key, String alg, Map<String, Object> header, Map<String, Object> payload) {
        String input = encode(header) + "." + encode(payload);
        return input + "." + Codec.base64Url(key.sign(alg, Codec.utf8(input)));
    }

    public static String hmac(String alg, String secret, Map<String, Object> header, Map<String, Object> payload) {
        String input = encode(header) + "." + encode(payload);
        String name = "Hmac" + alg.replace("HS", "SHA");
        try {
            Mac mac = Mac.getInstance(name);
            mac.init(new SecretKeySpec(Codec.utf8(secret), name));
            return input + "." + Codec.base64Url(mac.doFinal(Codec.utf8(input)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An unsigned token ({@code alg: none}). */
    public static String none(Map<String, Object> payload, String typ) {
        Map<String, Object> h = header("none", null, typ);
        return encode(h) + "." + encode(payload) + ".";
    }

    public static String encode(Map<String, Object> part) {
        return Codec.base64Url(Codec.utf8(Json.write(part)));
    }

    /** Replaces the payload while keeping the signature (a tampered token). */
    public static String tamper(String token, Map<String, Object> payload) {
        String[] parts = token.split("\\.");
        return parts[0] + "." + encode(payload) + "." + parts[2];
    }

    /** Fluent claims. */
    public static Claims claims() {
        return new Claims();
    }

    public static final class Claims extends LinkedHashMap<String, Object> {
        private static final long serialVersionUID = 1L;

        public Claims with(String name, Object value) {
            put(name, value);
            return this;
        }

        public Claims without(String name) {
            remove(name);
            return this;
        }
    }
}
