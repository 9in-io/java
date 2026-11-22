package io.ninein.spring;

import io.ninein.AccessTokenClaims;
import io.ninein.AccessTokenVerifier;
import io.ninein.HybridTokenVerifier;
import io.ninein.InvalidTokenException;
import io.ninein.NineException;
import io.ninein.internal.Codec;
import io.ninein.internal.Json;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Plugs 9in's verifier into Spring Security's JWT resource server as a {@link JwtDecoder}: every
 * algorithm of 9in's key library (including HMAC keys with your API's secret), {@code at+jwt}, the
 * key's own algorithm, issuer, audience and expiry, and, with a {@link HybridTokenVerifier},
 * revocation. Spring's default converter turns the {@code scope} claim into {@code SCOPE_*}
 * authorities.
 *
 * <pre>{@code
 * @Bean
 * JwtDecoder jwtDecoder() {
 *     return new NineJwtDecoder(HybridTokenVerifier.fromEnv());
 * }
 * // with spring-boot-starter-oauth2-resource-server and
 * // http.oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
 * }</pre>
 *
 * <p>JWTs only: if your API receives opaque {@code 9in_at_} tokens, use
 * {@link NineOpaqueTokenIntrospector}, which takes both.
 */
public final class NineJwtDecoder implements JwtDecoder {
    private final AccessTokenVerifier verifier;

    public NineJwtDecoder(AccessTokenVerifier verifier) {
        if (verifier == null) throw new IllegalArgumentException("a verifier is required");
        this.verifier = verifier;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (token == null || token.startsWith(HybridTokenVerifier.OPAQUE_PREFIX)) {
            throw new BadJwtException("not a JWT (use NineOpaqueTokenIntrospector for opaque tokens)");
        }
        AccessTokenClaims claims;
        try {
            claims = verifier.verify(token);
        } catch (InvalidTokenException e) {
            throw new BadJwtException(e.description(), e);
        } catch (NineException e) {
            if (e.status() != null && e.status() == 401) throw new BadJwtException(e.description(), e);
            throw new JwtException(e.getMessage(), e);
        }
        Map<String, Object> header = Json.parseObject(new String(Codec.base64UrlDecode(token.substring(0, token.indexOf('.'))), StandardCharsets.UTF_8));
        return Jwt.withTokenValue(token)
                .headers(h -> h.putAll(header))
                .claims(c -> c.putAll(SpringClaims.withInstants(claims.asMap())))
                .build();
    }
}
