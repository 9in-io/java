package io.ninein.spring;

import io.ninein.AccessTokenClaims;
import io.ninein.AccessTokenVerifier;
import io.ninein.InvalidTokenException;
import io.ninein.NineException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/**
 * Plugs 9in's verifier into Spring Security's resource server as an {@link OpaqueTokenIntrospector}.
 * Despite the name it takes every 9in access token: JWTs (verified locally, then, with a
 * {@link io.ninein.HybridTokenVerifier}, checked for revocation once and cached) and opaque
 * {@code 9in_at_} tokens (introspected). Scopes become {@code SCOPE_<scope>} authorities.
 *
 * <pre>{@code
 * @Bean
 * HybridTokenVerifier nineVerifier() {
 *     return HybridTokenVerifier.fromEnv();   // NINE_ISSUER, NINE_API_AUDIENCE, NINE_CLIENT_ID, NINE_CLIENT_SECRET
 * }
 *
 * @Bean
 * SecurityFilterChain api(HttpSecurity http, HybridTokenVerifier verifier) throws Exception {
 *     http.authorizeHttpRequests(a -> a
 *             .requestMatchers("/orders/**").hasAuthority("SCOPE_orders:read")
 *             .anyRequest().authenticated())
 *         .oauth2ResourceServer(o -> o.opaqueToken(t -> t.introspector(new NineOpaqueTokenIntrospector(verifier))));
 *     return http.build();
 * }
 * }</pre>
 *
 * <p>An invalid, expired or revoked token becomes {@link BadOpaqueTokenException} (401); 9in being
 * unreachable becomes {@link OAuth2IntrospectionException}.
 */
public final class NineOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    private final AccessTokenVerifier verifier;

    public NineOpaqueTokenIntrospector(AccessTokenVerifier verifier) {
        if (verifier == null) throw new IllegalArgumentException("a verifier is required");
        this.verifier = verifier;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        AccessTokenClaims claims;
        try {
            claims = verifier.verify(token);
        } catch (InvalidTokenException e) {
            throw new BadOpaqueTokenException(e.description(), e);
        } catch (NineException e) {
            if (e.status() != null && e.status() == 401) throw new BadOpaqueTokenException(e.description(), e);
            throw new OAuth2IntrospectionException(e.getMessage(), e);
        }
        Map<String, Object> attributes = SpringClaims.withInstants(claims.asMap());
        return new OAuth2IntrospectionAuthenticatedPrincipal(claims.subject(), attributes, authorities(claims));
    }

    static Collection<GrantedAuthority> authorities(AccessTokenClaims claims) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String scope : claims.scopes()) authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        return authorities;
    }
}
