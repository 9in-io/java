package io.ninein;

import io.ninein.internal.Json;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tokens from 9in's token endpoint, plus the verified ID token claims (the signed-in user).
 * Immutable. 9in rotates refresh tokens: after {@link AuthClient#refresh(TokenSet)} always keep the
 * returned set (it holds the new refresh token).
 *
 * <p>{@link #toJson()} / {@link #fromJson(String)} serialise it for a session store or encrypted
 * device storage. {@link #toString()} never prints the tokens.
 */
public final class TokenSet {
    private final String accessToken;
    private final String tokenType;
    private final Instant expiresAt;
    private final String refreshToken;
    private final String idToken;
    private final String scope;
    private final Map<String, Object> claims;
    private final String returnTo;

    private TokenSet(Builder b) {
        if (b.accessToken == null || b.accessToken.isEmpty()) throw new IllegalArgumentException("accessToken is required");
        this.accessToken = b.accessToken;
        this.tokenType = b.tokenType == null ? "Bearer" : b.tokenType;
        this.expiresAt = b.expiresAt;
        this.refreshToken = b.refreshToken;
        this.idToken = b.idToken;
        this.scope = b.scope;
        this.claims = Json.freezeObject(b.claims);
        this.returnTo = b.returnTo;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** A builder prefilled with this set's values. */
    public Builder toBuilder() {
        return new Builder()
                .accessToken(accessToken)
                .tokenType(tokenType)
                .expiresAt(expiresAt)
                .refreshToken(refreshToken)
                .idToken(idToken)
                .scope(scope)
                .claims(claims)
                .returnTo(returnTo);
    }

    public String accessToken() {
        return accessToken;
    }

    /** Usually {@code Bearer}. */
    public String tokenType() {
        return tokenType;
    }

    /** When the access token expires, or null when unknown. */
    public Instant expiresAt() {
        return expiresAt;
    }

    /** The refresh token (requires the {@code offline_access} scope), or null. */
    public String refreshToken() {
        return refreshToken;
    }

    /** The raw ID token (for {@code id_token_hint} at logout), or null. */
    public String idToken() {
        return idToken;
    }

    /** The granted scopes, space-separated, or null. */
    public String scope() {
        return scope;
    }

    /** The verified ID token claims ({@code sub}, {@code email}, {@code name} ...); empty without an ID token. */
    public Map<String, Object> claims() {
        return claims;
    }

    /** A claim by name, or null. */
    public Object claim(String name) {
        return claims.get(name);
    }

    /** The {@code sub} claim (the 9in user id), or null. */
    public String subject() {
        Object sub = claims.get("sub");
        return sub instanceof String ? (String) sub : null;
    }

    /** The path to return to after sign-in (only a same-site relative path), or null. */
    public String returnTo() {
        return returnTo;
    }

    /** True when the access token expires within {@code leeway} from now (never, when unknown). */
    public boolean isExpired(Duration leeway) {
        return isExpired(leeway, Clock.systemUTC());
    }

    /** As {@link #isExpired(Duration)}, against the given clock. */
    public boolean isExpired(Duration leeway, Clock clock) {
        if (expiresAt == null) return false;
        Duration l = leeway == null ? Duration.ZERO : leeway;
        return !clock.instant().plus(l).isBefore(expiresAt);
    }

    /** JSON with snake_case keys; {@code expires_at} in unix seconds. */
    public String toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("access_token", accessToken);
        map.put("token_type", tokenType);
        if (expiresAt != null) map.put("expires_at", expiresAt.getEpochSecond());
        if (refreshToken != null) map.put("refresh_token", refreshToken);
        if (idToken != null) map.put("id_token", idToken);
        if (scope != null) map.put("scope", scope);
        map.put("claims", claims);
        if (returnTo != null) map.put("return_to", returnTo);
        return Json.write(map);
    }

    /** Reads {@link #toJson()} output. Throws {@link NineException} ({@code invalid_token_set}) on anything else. */
    public static TokenSet fromJson(String json) {
        Map<String, Object> map;
        try {
            map = Json.parseObject(json);
        } catch (NineException e) {
            throw new NineException("invalid_token_set", "stored tokens are not valid JSON");
        }
        String access = Json.string(map, "access_token");
        if (access == null || access.isEmpty()) throw new NineException("invalid_token_set", "stored tokens have no access_token");
        Long expires = Json.number(map, "expires_at");
        Map<String, Object> claims = Json.object(map, "claims");
        return builder()
                .accessToken(access)
                .tokenType(Json.string(map, "token_type"))
                .expiresAt(expires == null ? null : Instant.ofEpochSecond(expires))
                .refreshToken(Json.string(map, "refresh_token"))
                .idToken(Json.string(map, "id_token"))
                .scope(Json.string(map, "scope"))
                .claims(claims == null ? Collections.<String, Object>emptyMap() : claims)
                .returnTo(Json.string(map, "return_to"))
                .build();
    }

    @Override
    public String toString() {
        return "TokenSet{sub=" + subject() + ", expiresAt=" + expiresAt + ", scope=" + scope
                + ", refreshToken=" + (refreshToken == null ? "none" : "present") + "}";
    }

    public static final class Builder {
        private String accessToken;
        private String tokenType;
        private Instant expiresAt;
        private String refreshToken;
        private String idToken;
        private String scope;
        private Map<String, Object> claims = Collections.emptyMap();
        private String returnTo;

        private Builder() {}

        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public Builder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public Builder idToken(String idToken) {
            this.idToken = idToken;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder claims(Map<String, ?> claims) {
            this.claims = claims == null ? Collections.<String, Object>emptyMap() : new LinkedHashMap<String, Object>(claims);
            return this;
        }

        public Builder returnTo(String returnTo) {
            this.returnTo = returnTo;
            return this;
        }

        public TokenSet build() {
            return new TokenSet(this);
        }
    }
}
