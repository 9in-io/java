package example;

import io.ninein.HybridTokenVerifier;
import io.ninein.MemoryCache;
import io.ninein.Webhooks;
import io.ninein.servlet.WebhookServlet;
import io.ninein.spring.NineOpaqueTokenIntrospector;
import java.net.URI;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    /** Checks bearer tokens: NINE_ISSUER, NINE_API_AUDIENCE, NINE_CLIENT_ID, NINE_CLIENT_SECRET (hybrid mode). */
    @Bean
    HybridTokenVerifier nineVerifier() {
        return HybridTokenVerifier.fromEnv();
    }

    /** /api/**: a resource server; 9in's scopes become SCOPE_* authorities. */
    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http, HybridTokenVerifier verifier) throws Exception {
        http.securityMatcher("/api/**")
            .authorizeHttpRequests(a -> a
                .requestMatchers("/api/orders/**").hasAuthority("SCOPE_read:things")
                .anyRequest().authenticated())
            .oauth2ResourceServer(o -> o.opaqueToken(t -> t.introspector(new NineOpaqueTokenIntrospector(verifier))))
            // Bearer tokens only: never the browser's session cookie, so CSRF protection isn't needed here.
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(c -> c.disable());
        return http.build();
    }

    /** Everything else: sign-in with Spring Security's oauth2Login() against 9in. */
    @Bean
    @Order(2)
    SecurityFilterChain web(HttpSecurity http, ClientRegistrationRepository registrations, Environment env) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());   // PKCE for confidential clients too
        OidcClientInitiatedLogoutSuccessHandler logout = new OidcClientInitiatedLogoutSuccessHandler(registrations);
        logout.setPostLogoutRedirectUri("{baseUrl}/");
        // The callback path from NINE_REDIRECT_URI when set (default /login/oauth2/code/nine).
        String redirect = env.getProperty("NINE_REDIRECT_URI");
        String callback = redirect == null ? "/login/oauth2/code/*" : URI.create(redirect).getPath();
        http.authorizeHttpRequests(a -> a
                .requestMatchers("/nine/webhook", "/error").permitAll()
                .anyRequest().authenticated())
            .oauth2Login(o -> o
                .authorizationEndpoint(e -> e.authorizationRequestResolver(resolver))
                .redirectionEndpoint(r -> r.baseUri(callback)))
            .logout(l -> l.logoutSuccessHandler(logout))
            .csrf(c -> c.ignoringRequestMatchers("/nine/webhook"));
        return http.build();
    }

    /** 9in webhooks: verified, processed once, and revoked tokens evicted from the verifier. */
    @Bean
    ServletRegistrationBean<WebhookServlet> nineWebhook(HybridTokenVerifier verifier) {
        WebhookServlet servlet = WebhookServlet.builder(Webhooks.secretsFromEnv())   // NINE_WEBHOOK_SECRET
            .dedupe(new MemoryCache())                                              // use a shared cache with several servers
            .verifier(verifier)
            .handler(event -> System.out.println("webhook " + event.eventType() + " " + event.id()))
            .build();
        return new ServletRegistrationBean<>(servlet, "/nine/webhook");
    }
}
