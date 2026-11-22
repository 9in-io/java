# Changelog

## 0.1.0

First release of the official 9in Java SDK (`com.github.9in-io:java` on JitPack, package `io.ninein`).
Java 11+, no runtime dependencies.

- **Sign-in** (`AuthClient`): authorization code flow with PKCE S256 for confidential and public
  clients, endpoints from OIDC discovery, single-use `state` compared in constant time, `nonce`,
  the RFC 9207 `iss` parameter, ID tokens verified against the JWKS (every algorithm the runtime
  supports; `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`), refresh token rotation, `ensureFresh`,
  revocation, RP-initiated logout URL, userinfo, client credentials and the device authorization
  flow (RFC 8628). `screen("signup")` opens the sign-up form; `returnTo` only keeps same-site paths.
- **Token verification**: `TokenVerifier` checks access tokens locally with RS256/384/512,
  PS256/384/512, ES256, ES384, EdDSA (Java 15+) and HS256/384/512, `at+jwt`, the key's own
  algorithm and type, issuer, expiry, audience and scopes, with a 10-minute JWKS cache, one refetch
  for an unknown key and a 60-second throttle. `HybridTokenVerifier` adds `local` / `hybrid` /
  `introspect` modes, cached introspection, opaque tokens, webhook eviction (`handleEvent`) and a
  pluggable shared `Cache`.
- **Management API** (`ManagementClient`): users (list, get, find, create, import, update, delete,
  block, unblock), login links and sessions, with per-scope cached client-credentials tokens.
- **Adapter protocol v2** (`io.ninein.adapter`): `AdapterHandler` with signed requests and
  responses, rotation and the reference status codes.
- **Webhooks**: `Webhooks.verify`, `WebhookEvent`, and `EventDeduplicator` to process each event once.
- **Signatures**: `Signatures` (the 9in `t=…,v1=…` scheme), passing the PHP SDK's reference vectors.
- **Framework helpers**: Jakarta Servlet `BearerTokenFilter`, `AdapterServlet` and `WebhookServlet`;
  Spring Security `NineOpaqueTokenIntrospector` and `NineJwtDecoder`. Compile-only dependencies.
- **Android-safe core**: `AuthClient` and what it uses run on Android API 26+ and never reference
  the server-side classes; the 9in Android SDK is built on it.
- Configuration from `NINE_*` environment variables; issuers must use https.
