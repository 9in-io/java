package io.ninein.internal;

import io.ninein.NineException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Signature and claim checks shared by ID token and access token verification.
 * Internal to the SDK.
 */
public final class TokenChecks {
    /** Result of {@link #verifySignature}: checked, or skipped because the runtime lacks the algorithm. */
    public enum SignatureResult { VERIFIED, UNSUPPORTED_BY_RUNTIME }

    private TokenChecks() {}

    /**
     * Verifies the signature of a decoded JWT: HMAC algorithms with {@code hmacSecret}, the others
     * with the tenant's JWK named by {@code kid}. The key decides the algorithm, never the token
     * alone: when the JWK names an {@code alg} the token must use exactly it, and the key type
     * and curve must fit. {@code alg: none} and unknown algorithms are refused.
     *
     * @param allowUnsupportedRuntime return {@link SignatureResult#UNSUPPORTED_BY_RUNTIME} instead of
     *     throwing when the runtime can't verify the algorithm (public clients, ID tokens only)
     */
    public static SignatureResult verifySignature(Jwt jwt, Tenant tenant, String hmacSecret, boolean allowUnsupportedRuntime, String code, String what) {
        if (jwt.header.containsKey("crit")) throw new NineException(code, what + " has critical header parameters", 401);
        String alg = jwt.alg();
        boolean valid;
        if (Jws.HMAC.contains(alg)) {
            if (hmacSecret == null || hmacSecret.isEmpty()) {
                throw new NineException(code, "HMAC-signed " + what + ": pass the shared secret", 401);
            }
            valid = Jws.verifyHmac(alg, hmacSecret, Codec.utf8(jwt.signingInput), jwt.signature);
        } else if (Jws.ASYMMETRIC.contains(alg)) {
            Map<String, Object> jwk = tenant.signingKey(jwt.kid());
            if (jwk == null) throw new NineException(code, "unknown signing key", 401);
            String keyAlg = Json.string(jwk, "alg");
            if ((jwk.containsKey("alg") && !alg.equals(keyAlg)) || !Jws.fits(jwk, alg)) {
                throw new NineException(code, "algorithm does not match the key", 401);
            }
            String use = Json.string(jwk, "use");
            if (jwk.containsKey("use") && !"sig".equals(use)) throw new NineException(code, "the key is not a signing key", 401);
            try {
                valid = Jws.verify(alg, jwk, Codec.utf8(jwt.signingInput), jwt.signature);
            } catch (NineException e) {
                if ("unsupported_algorithm".equals(e.error())) {
                    if (allowUnsupportedRuntime) return SignatureResult.UNSUPPORTED_BY_RUNTIME;
                    throw new NineException("unsupported_algorithm", alg + " is not supported by this Java runtime (EdDSA needs Java 15+)", 401, e);
                }
                throw e;
            }
        } else {
            throw new NineException(code, "unsupported algorithm", 401);
        }
        if (!valid) throw new NineException(code, "bad signature", 401);
        return SignatureResult.VERIFIED;
    }

    /** {@code iss} must be the issuer (a trailing slash is ignored). */
    public static void checkIssuer(Map<String, Object> claims, String issuer, String code) {
        Object iss = claims.get("iss");
        if (!(iss instanceof String) || !Issuers.same((String) iss, issuer)) throw new NineException(code, "issuer mismatch", 401);
    }

    /** {@code exp} required and in the future, {@code nbf} (and {@code iat} when asked) not in the future, all with leeway. */
    public static void checkTimes(Map<String, Object> claims, Clock clock, Duration leeway, boolean checkIat, String code) {
        double now = clock.millis() / 1000.0;
        double skew = leeway.toMillis() / 1000.0;
        Double exp = numericDate(claims.get("exp"));
        if (exp == null) throw new NineException(code, "token has no expiry", 401);
        if (exp + skew < now) throw new NineException(code, "token expired", 401);
        Double nbf = numericDate(claims.get("nbf"));
        if (claims.containsKey("nbf") && nbf == null) throw new NineException(code, "malformed nbf", 401);
        if (nbf != null && nbf - skew > now) throw new NineException(code, "token not yet valid", 401);
        Double iat = numericDate(claims.get("iat"));
        if (claims.containsKey("iat") && iat == null) throw new NineException(code, "malformed iat", 401);
        if (checkIat) {
            if (iat == null) throw new NineException(code, "token has no issue time", 401);
            if (iat - skew > now) throw new NineException(code, "token issued in the future", 401);
        }
    }

    /** At least one of {@code wanted} is in the token's {@code aud} (a string or an array). */
    public static void checkAudience(Map<String, Object> claims, Collection<String> wanted, String code) {
        if (wanted == null || wanted.isEmpty()) return;
        List<String> aud = audiences(claims.get("aud"));
        for (String w : wanted) if (aud.contains(w)) return;
        throw new NineException(code, "audience mismatch", 401);
    }

    /** All required scopes must be granted, else {@code insufficient_scope} (403). */
    public static void checkScope(Map<String, Object> claims, Collection<String> required) {
        if (required == null || required.isEmpty()) return;
        Object granted = claims.get("scope");
        List<String> have = new ArrayList<>();
        if (granted instanceof String) {
            for (String s : ((String) granted).split(" ")) if (!s.isEmpty()) have.add(s);
        } else if (granted instanceof List) {
            for (Object s : (List<?>) granted) if (s instanceof String) have.add((String) s);
        }
        List<String> missing = new ArrayList<>();
        for (String r : required) if (!r.isEmpty() && !have.contains(r)) missing.add(r);
        if (!missing.isEmpty()) throw new NineException("insufficient_scope", "missing " + String.join(", ", missing), 403);
    }

    /** The {@code aud} claim as a list (a string becomes one entry; non-strings are dropped). */
    public static List<String> audiences(Object aud) {
        if (aud instanceof String) return Collections.singletonList((String) aud);
        List<String> out = new ArrayList<>();
        if (aud instanceof List) for (Object a : (List<?>) aud) if (a instanceof String) out.add((String) a);
        return out;
    }

    /** A NumericDate claim as seconds, or null when missing or not a finite number. */
    public static Double numericDate(Object value) {
        if (!(value instanceof Number)) return null;
        double d = ((Number) value).doubleValue();
        return Double.isNaN(d) || Double.isInfinite(d) ? null : d;
    }

    /** True for {@code at+jwt} / {@code application/at+jwt} (any case). */
    public static boolean isAccessTokenType(String typ) {
        String t = typ == null ? "" : typ.toLowerCase(Locale.ROOT);
        return t.equals("at+jwt") || t.equals("application/at+jwt");
    }

    /** Splits a space-separated scope string (or returns the given list) into scopes. */
    public static List<String> scopes(String... scopes) {
        List<String> out = new ArrayList<>();
        if (scopes == null) return out;
        for (String s : scopes) {
            if (s == null) continue;
            for (String part : s.trim().split("\\s+")) if (!part.isEmpty()) out.add(part);
        }
        return out;
    }
}
