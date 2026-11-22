package io.ninein;

/**
 * Verifies bearer tokens for your API. Implemented by {@link TokenVerifier} (local checks) and
 * {@link HybridTokenVerifier} (revocation-aware); the servlet filter and the Spring helpers take
 * either.
 */
public interface AccessTokenVerifier {
    /**
     * Verifies a token (or an {@code Authorization: Bearer ...} header value) and returns its claims.
     *
     * @param requiredScopes scopes that must all be granted (each may be space-separated)
     * @throws InvalidTokenException when the token is missing, malformed, expired, revoked or not for this API (401)
     * @throws InsufficientScopeException when a required scope is missing (403)
     * @throws NineException when 9in can't be reached to fetch keys or introspect
     */
    AccessTokenClaims verify(String tokenOrAuthorizationHeader, String... requiredScopes);
}
