package io.ninein.spring;

import static io.ninein.testing.FakeNine.json;
import static io.ninein.testing.FakeNine.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.HybridTokenVerifier;
import io.ninein.TokenVerifier;
import io.ninein.testing.FakeNine;
import io.ninein.testing.Jwts;
import io.ninein.testing.TestKeys;
import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

/** The Spring Security helpers, with Spring's own authentication providers and bearer-token filter. */
class SpringSecurityTest {
    static final String API = "https://api.example.com";

    FakeNine nine;
    Map<String, Map<String, Object>> live = new HashMap<>();

    @BeforeEach
    void setUp() {
        nine = new FakeNine();
        nine.on("POST", "/oauth/introspect", r -> {
            Map<String, Object> answer = live.get(FakeNine.form(r).get("token"));
            if (answer == null) return json(200, map("active", false));
            Map<String, Object> body = new HashMap<>(answer);
            body.put("active", true);
            return json(200, body);
        });
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    Jwts.Claims claims() {
        long now = System.currentTimeMillis() / 1000;
        return Jwts.claims().with("iss", nine.issuer).with("sub", "usr_1").with("aud", API).with("client_id", "app_1")
                .with("scope", "orders:read orders:write").with("iat", now).with("exp", now + 600).with("jti", "j1");
    }

    HybridTokenVerifier hybrid() {
        return HybridTokenVerifier.builder().issuer(nine.issuer).audience(API).clientId("app_api").clientSecret("s").transport(nine).build();
    }

    @Test
    void jwtDecoder() {
        NineJwtDecoder decoder = new NineJwtDecoder(TokenVerifier.builder().issuer(nine.issuer).audience(API).secret(TestKeys.HMAC_SECRET).transport(nine).build());
        for (String alg : new String[] {"RS256", "PS384", "ES256", "HS256"}) {
            Jwt jwt = decoder.decode(Jwts.sign(alg, "at+jwt", claims()));
            assertEquals("usr_1", jwt.getSubject());
            assertEquals(alg, jwt.getHeaders().get("alg"));
            assertNotNull(jwt.getExpiresAt());
            assertInstanceOf(Instant.class, jwt.getClaims().get("iat"));
            assertEquals(java.util.List.of(API), jwt.getAudience());
            assertEquals("orders:read orders:write", jwt.getClaimAsString("scope"));
        }
        assertThrows(BadJwtException.class, () -> decoder.decode(Jwts.sign("RS256", "JWT", claims())));
        assertThrows(BadJwtException.class, () -> decoder.decode("9in_at_opaque"));
        assertThrows(BadJwtException.class, () -> decoder.decode("garbage"));
    }

    @Test
    void jwtDecoderWithSpringsProviderGivesScopeAuthorities() {
        NineJwtDecoder decoder = new NineJwtDecoder(TokenVerifier.builder().issuer(nine.issuer).audience(API).transport(nine).build());
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        Authentication auth = provider.authenticate(new org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken(Jwts.sign("ES384", "at+jwt", claims())));
        assertEquals("usr_1", auth.getName());
        // Spring Security 7 also adds its own FACTOR_BEARER authority.
        assertTrue(authorities(auth).containsAll(Set.of("SCOPE_orders:read", "SCOPE_orders:write")), authorities(auth).toString());
    }

    @Test
    void jwtDecoderOutageIsNotABadToken() {
        nine.on("GET", "/.well-known/jwks.json", r -> json(500, null));
        NineJwtDecoder decoder = new NineJwtDecoder(TokenVerifier.builder().issuer(nine.issuer).transport(nine).build());
        JwtException e = assertThrows(JwtException.class, () -> decoder.decode(Jwts.sign("RS256", "at+jwt", claims())));
        assertTrue(!(e instanceof BadJwtException));
    }

    @Test
    void introspectorTakesJwtsAndOpaqueTokensAndSeesRevocation() {
        NineOpaqueTokenIntrospector introspector = new NineOpaqueTokenIntrospector(hybrid());
        String jwt = Jwts.sign("RS256", "at+jwt", claims());
        live.put(jwt, new HashMap<>(claims()));
        OAuth2AuthenticatedPrincipal p = introspector.introspect(jwt);
        assertEquals("usr_1", p.getName());
        assertEquals(Set.of("SCOPE_orders:read", "SCOPE_orders:write"), p.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        assertInstanceOf(Instant.class, p.getAttribute("exp"));

        long now = System.currentTimeMillis() / 1000;
        live.put("9in_at_opaque", map("iss", nine.issuer, "sub", "usr_o", "aud", API, "scope", "orders:read", "exp", now + 60, "iat", now));
        assertEquals("usr_o", introspector.introspect("9in_at_opaque").getName());

        String revoked = Jwts.sign("RS256", "at+jwt", claims().with("jti", "j_revoked"));
        assertThrows(BadOpaqueTokenException.class, () -> introspector.introspect(revoked));
        assertThrows(BadOpaqueTokenException.class, () -> introspector.introspect("not-a-token"));
    }

    @Test
    void introspectorOutageIsNotABadToken() {
        nine.on("POST", "/oauth/introspect", r -> json(401, map("error", "invalid_client")));
        NineOpaqueTokenIntrospector introspector = new NineOpaqueTokenIntrospector(hybrid());
        OAuth2IntrospectionException e = assertThrows(OAuth2IntrospectionException.class, () -> introspector.introspect(Jwts.sign("RS256", "at+jwt", claims())));
        assertTrue(!(e instanceof BadOpaqueTokenException));
    }

    @Test
    void springBearerTokenFilterEndToEnd() throws Exception {
        NineOpaqueTokenIntrospector introspector = new NineOpaqueTokenIntrospector(hybrid());
        BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(new ProviderManager(new OpaqueTokenAuthenticationProvider(introspector)));
        String jwt = Jwts.sign("ES256", "at+jwt", claims());
        live.put(jwt, new HashMap<>(claims()));

        AtomicReference<Authentication> seen = new AtomicReference<>();
        FilterChain chain = (req, res) -> seen.set(SecurityContextHolder.getContext().getAuthentication());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader("Authorization", "Bearer " + jwt);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals(200, response.getStatus());
        assertInstanceOf(BearerTokenAuthentication.class, seen.get());
        assertEquals("usr_1", seen.get().getName());
        assertTrue(authorities(seen.get()).contains("SCOPE_orders:read"));

        SecurityContextHolder.clearContext();
        seen.set(null);
        MockHttpServletRequest bad = new MockHttpServletRequest("GET", "/orders");
        bad.addHeader("Authorization", "Bearer " + Jwts.sign("ES256", "at+jwt", claims().with("aud", "https://other")));
        MockHttpServletResponse badResponse = new MockHttpServletResponse();
        filter.doFilter(bad, badResponse, chain);
        assertEquals(401, badResponse.getStatus());
        assertTrue(badResponse.getHeader("WWW-Authenticate").contains("invalid_token"));
        assertNull(seen.get());
    }

    static Set<String> authorities(Authentication auth) {
        return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
    }
}
