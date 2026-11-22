package io.ninein;

import io.ninein.http.HttpTransport;
import io.ninein.http.UrlConnectionTransport;
import io.ninein.internal.Env;
import io.ninein.internal.Issuers;
import io.ninein.internal.Jwt;
import io.ninein.internal.Tenant;
import io.ninein.internal.TokenChecks;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Verifies 9in JWT access tokens locally, with no call to 9in per request: signature, token type
 * ({@code at+jwt}), issuer, expiry / not-before (30 s leeway), audience and required scopes.
 *
 * <p>Every algorithm of 9in's key library is accepted: RS256/384/512, PS256/384/512, ES256,
 * ES384 and EdDSA against the tenant's JWKS, and HS256/384/512 with your API's shared secret
 * ({@link Builder#secret}). When a JWKS key names its {@code alg}, the token must use exactly
 * that algorithm, and the key type and curve must fit it. The JWKS is cached for 10 minutes and
 * fetched again once when a token names an unknown key id (key rotation); unknown key ids are
 * then ignored for a minute.
 *
 * <p>This is a local check: a token revoked before it expires still passes. Use
 * {@link HybridTokenVerifier} when revocation must take effect at once.
 *
 * <pre>{@code
 * TokenVerifier verifier = TokenVerifier.builder()
 *     .issuer("https://acme.9in.io")
 *     .audience("https://api.acme.com")
 *     .build();
 * AccessTokenClaims claims = verifier.verify(request.getHeader("Authorization"), "orders:read");
 * }</pre>
 *
 * <p>Thread-safe; build one and share it.
 */
public final class TokenVerifier implements AccessTokenVerifier {
    private final String issuer;
    private final List<String> audiences;
    private final String secret;
    private final Clock clock;
    private final Duration leeway;
    private final Tenant tenant;

    private TokenVerifier(Builder b) {
        boolean insecure = b.allowInsecureIssuer || Issuers.insecureAllowedByEnv();
        this.issuer = Issuers.normalize(b.issuer, insecure);
        this.audiences = Collections.unmodifiableList(new ArrayList<>(b.audiences));
        this.secret = b.secret == null || b.secret.isEmpty() ? null : b.secret;
        this.clock = b.clock == null ? Clock.systemUTC() : b.clock;
        this.leeway = b.leeway == null ? Duration.ofSeconds(30) : b.leeway;
        HttpTransport transport = b.transport == null ? new UrlConnectionTransport() : b.transport;
        this.tenant = new Tenant(issuer, transport, clock);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * A verifier from the environment: {@code NINE_ISSUER}, {@code NINE_API_AUDIENCE} (or
     * {@code NINE_AUDIENCE}), {@code NINE_API_SECRET} (HMAC keys only) and {@code NINE_ALLOW_INSECURE_ISSUER}.
     */
    public static TokenVerifier fromEnv() {
        return builder().env(System.getenv()).build();
    }

    /** The issuer, normalised. */
    public String issuer() {
        return issuer;
    }

    /** The accepted audiences (empty: any). */
    public List<String> audiences() {
        return audiences;
    }

    @Override
    public AccessTokenClaims verify(String tokenOrAuthorizationHeader, String... requiredScopes) {
        String token = stripBearer(tokenOrAuthorizationHeader);
        if (token == null || token.isEmpty()) throw new InvalidTokenException("missing token");
        Jwt jwt;
        try {
            jwt = Jwt.decode(token, "token");
        } catch (NineException e) {
            throw new InvalidTokenException("malformed token");
        }
        if (!TokenChecks.isAccessTokenType(jwt.typ())) throw new InvalidTokenException("not an access token (typ must be at+jwt)");
        try {
            TokenChecks.verifySignature(jwt, tenant, secret, false, "invalid_token", "token");
        } catch (NineException e) {
            throw asTokenError(e);
        }
        checkClaims(jwt.payload, requiredScopes);
        return new AccessTokenClaims(jwt.payload);
    }

    /**
     * Issuer, expiry / not-before, audience and scope checks on a set of claims (a verified JWT,
     * or an introspection answer for an opaque token).
     */
    void checkClaims(Map<String, Object> claims, String... requiredScopes) {
        try {
            TokenChecks.checkIssuer(claims, issuer, "invalid_token");
            TokenChecks.checkTimes(claims, clock, leeway, false, "invalid_token");
            TokenChecks.checkAudience(claims, audiences, "invalid_token");
        } catch (NineException e) {
            throw asTokenError(e);
        }
        List<String> required = TokenChecks.scopes(requiredScopes);
        try {
            TokenChecks.checkScope(claims, required);
        } catch (NineException e) {
            throw new InsufficientScopeException(e.description());
        }
    }

    Tenant tenant() {
        return tenant;
    }

    Clock clock() {
        return clock;
    }

    private static NineException asTokenError(NineException e) {
        if (e instanceof InvalidTokenException) return e;
        if ("invalid_token".equals(e.error())) return new InvalidTokenException(e.description(), e.getCause());
        return e; // unsupported_algorithm, jwks_unavailable, network_error, discovery_failed: not the token's fault
    }

    /** The token from an {@code Authorization} header value ("Bearer ..."), or the value itself. */
    public static String stripBearer(String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.length() >= 7 && v.substring(0, 7).toLowerCase(Locale.ROOT).equals("bearer ")) return v.substring(7).trim();
        return v;
    }

    @Override
    public String toString() {
        return "TokenVerifier{issuer=" + issuer + ", audiences=" + audiences + "}";
    }

    /** Builds a {@link TokenVerifier}; {@code issuer} is required. */
    public static final class Builder {
        private String issuer;
        private final List<String> audiences = new ArrayList<>();
        private String secret;
        private HttpTransport transport;
        private Clock clock;
        private Duration leeway;
        private boolean allowInsecureIssuer;

        private Builder() {}

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /** The API identifier(s) a token must be issued for (any one matches). Without one, any audience passes. */
        public Builder audience(String... audiences) {
            this.audiences.clear();
            if (audiences != null) for (String a : audiences) if (a != null && !a.isEmpty()) this.audiences.add(a);
            return this;
        }

        /** The shared secret of an HMAC key (HS256/384/512) your API uses, from the console's key library. */
        public Builder secret(String secret) {
            this.secret = secret;
            return this;
        }

        public Builder transport(HttpTransport transport) {
            this.transport = transport;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        /** Allowed clock skew for {@code exp} / {@code nbf} (default 30 seconds). */
        public Builder leeway(Duration leeway) {
            this.leeway = leeway;
            return this;
        }

        /** Accepts a plain-http issuer other than localhost (development only). */
        public Builder allowInsecureIssuer(boolean allow) {
            this.allowInsecureIssuer = allow;
            return this;
        }

        /** Applies {@code NINE_ISSUER}, {@code NINE_API_AUDIENCE} / {@code NINE_AUDIENCE}, {@code NINE_API_SECRET}, {@code NINE_ALLOW_INSECURE_ISSUER}. */
        public Builder env(Map<String, String> env) {
            String v;
            if ((v = Env.get(env, "ISSUER")) != null) issuer = v;
            String audience = Env.get(env, "API_AUDIENCE") != null ? Env.get(env, "API_AUDIENCE") : Env.get(env, "AUDIENCE");
            if (audience != null) audience(Env.list(audience));
            if ((v = Env.get(env, "API_SECRET")) != null) secret = v;
            if (Env.flag(Env.get(env, "ALLOW_INSECURE_ISSUER"))) allowInsecureIssuer = true;
            return this;
        }

        public TokenVerifier build() {
            return new TokenVerifier(this);
        }
    }
}
