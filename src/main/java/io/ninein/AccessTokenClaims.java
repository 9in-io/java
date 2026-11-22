package io.ninein;

import io.ninein.internal.Json;
import io.ninein.internal.TokenChecks;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The claims of a verified access token (a JWT's payload, or 9in's introspection answer for an
 * opaque token). Immutable; {@link #asMap()} has every claim unchanged.
 */
public final class AccessTokenClaims {
    private final Map<String, Object> claims;

    public AccessTokenClaims(Map<String, ?> claims) {
        this.claims = Json.freezeObject(claims);
    }

    /** {@code sub}: the user id, or the client id for client-credentials tokens. */
    public String subject() {
        return Json.string(claims, "sub");
    }

    /** {@code client_id}: the application the token was issued to. */
    public String clientId() {
        return Json.string(claims, "client_id");
    }

    public String issuer() {
        return Json.string(claims, "iss");
    }

    /** The {@code aud} claim as a list. */
    public List<String> audience() {
        return TokenChecks.audiences(claims.get("aud"));
    }

    /** The granted scopes. */
    public List<String> scopes() {
        Object scope = claims.get("scope");
        List<String> out = new ArrayList<>();
        if (scope instanceof String) {
            for (String s : ((String) scope).split(" ")) if (!s.isEmpty()) out.add(s);
        }
        return Collections.unmodifiableList(out);
    }

    public boolean hasScope(String scope) {
        return scopes().contains(scope);
    }

    /** {@code jti}: the token id (what {@code token.revoked} names), or null. */
    public String tokenId() {
        return Json.string(claims, "jti");
    }

    /** {@code sid}: the session (absent for client credentials), or null. */
    public String sessionId() {
        return Json.string(claims, "sid");
    }

    public Instant expiresAt() {
        Double exp = TokenChecks.numericDate(claims.get("exp"));
        return exp == null ? null : Instant.ofEpochMilli((long) (exp * 1000));
    }

    public Instant issuedAt() {
        Double iat = TokenChecks.numericDate(claims.get("iat"));
        return iat == null ? null : Instant.ofEpochMilli((long) (iat * 1000));
    }

    /** A claim by name, or null. */
    public Object get(String name) {
        return claims.get(name);
    }

    /** A string claim, or null. */
    public String getString(String name) {
        return Json.string(claims, name);
    }

    /** Every claim, unchanged (unmodifiable). */
    public Map<String, Object> asMap() {
        return claims;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof AccessTokenClaims && ((AccessTokenClaims) o).claims.equals(claims);
    }

    @Override
    public int hashCode() {
        return claims.hashCode();
    }

    @Override
    public String toString() {
        return "AccessTokenClaims{sub=" + subject() + ", client_id=" + clientId() + ", scope=" + claims.get("scope") + "}";
    }
}
