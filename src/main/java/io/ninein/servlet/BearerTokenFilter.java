package io.ninein.servlet;

import io.ninein.AccessTokenClaims;
import io.ninein.AccessTokenVerifier;
import io.ninein.InsufficientScopeException;
import io.ninein.InvalidTokenException;
import io.ninein.NineException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A Jakarta Servlet {@link Filter} that only lets requests with a valid 9in access token through
 * (RFC 6750 bearer tokens). Works with {@link io.ninein.TokenVerifier} (local) and
 * {@link io.ninein.HybridTokenVerifier} (revocation-aware).
 *
 * <ul>
 *   <li>No token, or an invalid / expired / revoked one: 401 with {@code WWW-Authenticate: Bearer ...}.
 *   <li>A missing required scope: 403 {@code insufficient_scope}.
 *   <li>9in unreachable (keys or introspection): 503.
 *   <li>Otherwise the request continues with the claims in the {@value #CLAIMS_ATTRIBUTE}
 *       attribute ({@link #claims(HttpServletRequest)}), {@code getUserPrincipal()} named after
 *       {@code sub}, and {@code isUserInRole(scope)} true for each granted scope.
 * </ul>
 *
 * <pre>{@code
 * FilterRegistration.Dynamic f = servletContext.addFilter("nine", new BearerTokenFilter(verifier, "orders:read"));
 * f.addMappingForUrlPatterns(null, false, "/api/*");
 * }</pre>
 */
public class BearerTokenFilter implements Filter {
    /** The request attribute holding the {@link AccessTokenClaims}. */
    public static final String CLAIMS_ATTRIBUTE = "io.ninein.claims";

    private final AccessTokenVerifier verifier;
    private final String[] scopes;

    /**
     * @param requiredScopes scopes every request must have (each may be space-separated)
     */
    public BearerTokenFilter(AccessTokenVerifier verifier, String... requiredScopes) {
        if (verifier == null) throw new IllegalArgumentException("a verifier is required");
        this.verifier = verifier;
        this.scopes = requiredScopes == null ? new String[0] : requiredScopes.clone();
    }

    /** The verified claims of this request, or null when it didn't pass the filter. */
    public static AccessTokenClaims claims(HttpServletRequest request) {
        Object claims = request.getAttribute(CLAIMS_ATTRIBUTE);
        return claims instanceof AccessTokenClaims ? (AccessTokenClaims) claims : null;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (!(req instanceof HttpServletRequest) || !(res instanceof HttpServletResponse)) {
            chain.doFilter(req, res);
            return;
        }
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String header = request.getHeader("Authorization");
        if (header == null || header.trim().isEmpty()) {
            response.setHeader("WWW-Authenticate", "Bearer realm=\"9in\"");
            write(response, 401, "invalid_token", "missing bearer token");
            return;
        }
        if (!header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            response.setHeader("WWW-Authenticate", "Bearer realm=\"9in\", error=\"invalid_request\"");
            write(response, 400, "invalid_request", "use the Bearer authorization scheme");
            return;
        }
        AccessTokenClaims claims;
        try {
            claims = verifier.verify(header, scopes);
        } catch (InsufficientScopeException e) {
            response.setHeader("WWW-Authenticate", "Bearer realm=\"9in\", error=\"insufficient_scope\", error_description=\""
                    + quoted(e.description()) + "\", scope=\"" + quoted(String.join(" ", scopes)) + "\"");
            write(response, 403, "insufficient_scope", e.description());
            return;
        } catch (NineException e) {
            if (e instanceof InvalidTokenException || "unsupported_algorithm".equals(e.error())) {
                response.setHeader("WWW-Authenticate", "Bearer realm=\"9in\", error=\"invalid_token\", error_description=\"" + quoted(e.description()) + "\"");
                write(response, 401, "invalid_token", e.description());
            } else {
                write(response, 503, "temporarily_unavailable", "the token could not be checked: " + e.error());
            }
            return;
        }
        request.setAttribute(CLAIMS_ATTRIBUTE, claims);
        chain.doFilter(new AuthenticatedRequest(request, claims), response);
    }

    private static void write(HttpServletResponse response, int status, String error, String description) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        byte[] bytes = io.ninein.internal.Json.write(body).getBytes(StandardCharsets.UTF_8);
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }

    private static String quoted(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') continue;
            if (c >= 0x20 && c < 0x7f) out.append(c);
        }
        return out.toString();
    }

    /** The request as seen by your servlet: a principal named after the token's subject. */
    static final class AuthenticatedRequest extends HttpServletRequestWrapper {
        private final AccessTokenClaims claims;

        AuthenticatedRequest(HttpServletRequest request, AccessTokenClaims claims) {
            super(request);
            this.claims = claims;
        }

        @Override
        public Principal getUserPrincipal() {
            final String name = claims.subject();
            return name == null ? null : (Principal) () -> name;
        }

        @Override
        public String getRemoteUser() {
            return claims.subject();
        }

        @Override
        public String getAuthType() {
            return "Bearer";
        }

        @Override
        public boolean isUserInRole(String role) {
            return claims.hasScope(role);
        }
    }
}
