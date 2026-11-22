9in Java SDK
============

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official Java SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO.

It has no dependencies, needs Java 11+, and works with Spring Boot, Jakarta EE, Micronaut, Quarkus
and plain servlets. The 9in Android SDK is built on its sign-in core.

- **Sign users in** with the authorization code flow + PKCE: endpoints from OIDC discovery, `state`,
  `nonce` and `iss` checks, ID tokens verified against your tenant's JWKS, refresh token rotation,
  revocation, logout, userinfo. Confidential (client secret) and public (PKCE only) clients.
- **Protect your API**: verify access tokens locally with every algorithm of your tenant's key
  library (RS, PS, ES and EdDSA from the JWKS, HS with your API's shared secret), and, in hybrid
  mode, catch revocations at once with cached introspection.
- **Manage users** through the Management API: users, sessions, single-use sign-in links and bulk
  import.
- **Keep users in your own database** with the adapter protocol v2 (`/authenticate`, `/user`,
  `/event`) and timestamped, replay-proof signatures.
- **Receive webhooks**, verify their signature and process each event once.
- **Machine to machine and devices**: client credentials, and the device flow for CLIs and TVs.
- **Framework helpers**: a Jakarta Servlet filter, adapter and webhook servlets, and Spring
  Security integration (resource server and `oauth2Login()`).

Requires Java 11 or later (EdDSA keys need Java 15+). No runtime dependencies: JSON, HTTP
(`HttpURLConnection` and `java.net.http`) and crypto come from the JDK.

The SDK is published on [JitPack](https://jitpack.io/#9in-io/java). Gradle:

```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.9in-io:java:v0.1.0")
}
```

Maven:

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
  <groupId>com.github.9in-io</groupId>
  <artifactId>java</artifactId>
  <version>v0.1.0</version>
</dependency>
```

Building an Android app? Use [`com.github.9in-io:android`](https://github.com/9in-io/android)
(Custom Tabs, Keystore storage, coroutines), which brings this SDK along. Guides are at
[9in.io/docs](https://9in.io/docs/).

## Configuration

Every class can be built from the environment:

| Variable | Used for |
|---|---|
| `NINE_ISSUER` | Your tenant, e.g. `https://acme.9in.io` or your custom login domain |
| `NINE_CLIENT_ID` | Application (client) id |
| `NINE_CLIENT_SECRET` | Confidential applications, introspection and the Management API |
| `NINE_REDIRECT_URI` | The callback URL registered for the application |
| `NINE_AUDIENCE` | An API identifier: sign-in asks for access tokens for that API |
| `NINE_API_AUDIENCE` | The identifier your API checks tokens for (default `NINE_AUDIENCE`) |
| `NINE_API_SECRET` | Your API's shared secret, only for HMAC (HS256/384/512) keys |
| `NINE_TOKEN_MODE` | `local`, `hybrid` or `introspect` (default hybrid with client credentials) |
| `NINE_ADAPTER_SECRET` | Adapter secret (Connections → User database); `NINE_ADAPTER_SECRET_PREVIOUS` during rotation |
| `NINE_WEBHOOK_SECRET` | Webhook endpoint secret; `NINE_WEBHOOK_SECRET_PREVIOUS` during rotation |
| `NINE_ALLOW_INSECURE_ISSUER` | `true` accepts a plain-http issuer (development only) |

`AuthClient.fromEnv()`, `TokenVerifier.fromEnv()`, `HybridTokenVerifier.fromEnv()`,
`ManagementClient.fromEnv()`, `AdapterHandler.fromEnv(adapter)` and `Webhooks.secretsFromEnv()`
read them. Every class also has a builder.

## Sign users in

`AuthClient` does the protocol; you keep the pending sign-in and the tokens in the user's session.

```java
import io.ninein.*;

AuthClient auth = AuthClient.builder()
    .issuer("https://acme.9in.io")                        // or your custom domain
    .clientId("app_7f3k2m9q")
    .clientSecret(System.getenv("NINE_CLIENT_SECRET"))    // leave out for public clients
    .redirectUri("https://app.acme.com/callback")
    .audience("https://api.acme.com")                     // optional: access tokens for your API
    .build();                                             // or AuthClient.fromEnv()

// GET /login
Login login = auth.createLogin(LoginOptions.builder().returnTo("/dashboard").build());
// LoginOptions.builder().screen("signup") opens the sign-up form instead
session.setAttribute("nine.pending", login.pending().toJson());
response.sendRedirect(login.url());

// GET /callback
String pending = (String) session.getAttribute("nine.pending");
session.removeAttribute("nine.pending");                  // each sign-in is used once
TokenSet tokens = auth.handleCallback(
    request.getRequestURL() + "?" + request.getQueryString(),
    pending == null ? null : PendingLogin.fromJson(pending));
session.setAttribute("nine.tokens", tokens.toJson());
String user = tokens.subject();                           // tokens.claims(): email, name, ...
response.sendRedirect(tokens.returnTo() != null ? tokens.returnTo() : "/");
```

`handleCallback` refuses a callback whose `state` doesn't match (`invalid_state`, compared in
constant time), whose `iss` isn't your issuer (`invalid_issuer`), or that carries an `error`
(`access_denied`, `login_required`, ...). It exchanges the code with the PKCE verifier and verifies
the ID token: signature against the JWKS, `iss`, `aud` (and `azp`), `exp`, `iat` and `nonce`.
`returnTo` only keeps same-site relative paths, so it can't be turned into an open redirect.

Access tokens expire (an hour by default). Refresh them before use; 9in rotates refresh tokens, so
always store the set you get back:

```java
TokenSet fresh = auth.ensureFresh(tokens, Duration.ofSeconds(60));   // the same object while still valid
if (fresh != tokens) session.setAttribute("nine.tokens", fresh.toJson());
```

A refresh token that was revoked or already used fails with `invalid_grant`: sign the user in again.

Sign out: revoke the refresh token and end the 9in session.

```java
auth.revoke(tokens.refreshToken(), "refresh_token");
session.invalidate();
response.sendRedirect(auth.logoutUrl(tokens.idToken(), "https://app.acme.com/", null));
```

Also on `AuthClient`: `userInfo(accessToken)`, `discovery()`, and
`createLogin(LoginOptions.builder().prompt("none"))` for a silent sign-in. A runnable web app is in
[examples/webapp](examples/webapp).

**Public clients** (desktop apps, CLIs, and the Android SDK built on this) leave out the client
secret: the code exchange then relies on PKCE alone. Their ID tokens come straight from the token
endpoint over TLS, so if the runtime can't verify the signature algorithm (EdDSA before Java 15)
the claim checks are enough, as OpenID Connect Core 3.1.3.7 allows. A confidential client always
verifies the signature, and fails with `unsupported_algorithm` instead.

### Machine to machine and devices

```java
TokenSet m2m = auth.clientCredentials("https://api.acme.com", "orders:read");   // confidential clients

DeviceAuthorization device = auth.startDeviceAuthorization(null);   // a TV or CLI, no browser
System.out.println("Go to " + device.verificationUri() + " and enter " + device.userCode());
TokenSet tokens = auth.pollDeviceAuthorization(device);             // blocks until approved or denied
```

## Protect your API

`TokenVerifier` checks access tokens locally, with no call to 9in per request: signature, type
(`at+jwt`), issuer, expiry, audience and scopes.

```java
TokenVerifier verifier = TokenVerifier.builder()
    .issuer("https://acme.9in.io")
    .audience("https://api.acme.com")
    .build();                                   // or TokenVerifier.fromEnv()

try {
    AccessTokenClaims claims = verifier.verify(request.getHeader("Authorization"), "orders:read");
    String userId = claims.subject();           // claims.clientId(), claims.scopes(), claims.asMap()
} catch (InsufficientScopeException e) {
    response.sendError(403);                    // insufficient_scope
} catch (InvalidTokenException e) {
    response.sendError(401);                    // invalid_token: missing, expired, wrong audience...
}
```

Every algorithm of 9in's key library is accepted: RS256/384/512, PS256/384/512, ES256, ES384 and
EdDSA (Java 15+) against your tenant's JWKS, and HS256/384/512 with your API's shared secret
(`.secret(...)`). The key decides the algorithm, never the token: when a key names its `alg`, the
token must use exactly it, and the key type must fit. The JWKS is cached for 10 minutes and fetched
again once when a token names an unknown key (rotation); unknown key ids are then ignored for a
minute.

### Revocation-aware verification (hybrid)

A local check accepts a revoked token until it expires. `HybridTokenVerifier` adds one
introspection per token, cached at most `cacheTtl` (5 minutes) and never past the token's expiry,
and drops cached answers as soon as 9in's webhook says a token, session or user was revoked:

```java
HybridTokenVerifier verifier = HybridTokenVerifier.builder()
    .issuer("https://acme.9in.io")
    .audience("https://api.acme.com")
    .clientId(System.getenv("NINE_CLIENT_ID"))          // a confidential application,
    .clientSecret(System.getenv("NINE_CLIENT_SECRET"))  // used for introspection
    .build();                                           // or HybridTokenVerifier.fromEnv()

AccessTokenClaims claims = verifier.verify(request.getHeader("Authorization"), "orders:read");

// In your webhook endpoint (subscribe it to token.revoked, session.revoked and the user.* events):
verifier.handleEvent(Webhooks.verify(webhookSecret, rawBody, signatureHeader, path));
```

| Mode | What it does |
|---|---|
| `HYBRID` (default with client credentials) | Local check, then one introspection per token, cached and evicted by webhooks |
| `LOCAL` (default without) | Signature and claims only; a revoked token works until it expires |
| `INTROSPECT` | Asks 9in on every call |

Opaque access tokens (`9in_at_…`) are always introspected. Concurrent checks of the same token
share one request. Answers live in memory; with several servers, pass a shared `Cache` (Redis...)
with `.cache(...)` so a webhook received by one server evicts the answer everywhere.

### Jakarta Servlet filter

```java
servletContext.addFilter("nine", new BearerTokenFilter(verifier, "orders:read"))
    .addMappingForUrlPatterns(null, false, "/api/*");

// in your servlet
AccessTokenClaims claims = BearerTokenFilter.claims(request);   // also request.getUserPrincipal()
```

The filter answers 401 with `WWW-Authenticate: Bearer` for a missing or invalid token, 403 for a
missing scope, and 503 when 9in can't be reached to check it.

### Spring Security (resource server)

Plug the verifier into Spring Security's resource server. `NineOpaqueTokenIntrospector` takes
every 9in token (JWTs and opaque ones) and keeps hybrid revocation; scopes become `SCOPE_*`
authorities. Add `spring-boot-starter-oauth2-resource-server`, then:

```java
@Configuration
class SecurityConfig {
    @Bean
    HybridTokenVerifier nineVerifier() {
        return HybridTokenVerifier.fromEnv();   // NINE_ISSUER, NINE_API_AUDIENCE, NINE_CLIENT_ID, NINE_CLIENT_SECRET
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http, HybridTokenVerifier verifier) throws Exception {
        http.securityMatcher("/api/**")
            .authorizeHttpRequests(a -> a
                .requestMatchers("/api/orders/**").hasAuthority("SCOPE_orders:read")
                .anyRequest().authenticated())
            .oauth2ResourceServer(o -> o.opaqueToken(t -> t.introspector(new NineOpaqueTokenIntrospector(verifier))))
            .csrf(c -> c.disable());
        return http.build();
    }
}
```

For JWTs only, `new NineJwtDecoder(verifier)` is a `JwtDecoder` for `oauth2ResourceServer(o -> o.jwt(...))`.
Both take a `TokenVerifier` too, for local-only checks. They need Spring Security 6.x or 7.x.

### Spring Security (sign-in with `oauth2Login()`)

Spring Security's own OpenID Connect login works with 9in. Register
`https://app.acme.com/login/oauth2/code/nine` as a callback URL of your application, add
`spring-boot-starter-oauth2-client`, and point it at your issuer:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          nine:
            client-id: ${NINE_CLIENT_ID}
            client-secret: ${NINE_CLIENT_SECRET}
            scope: openid,profile,email,offline_access
        provider:
          nine:
            issuer-uri: ${NINE_ISSUER}
```

```java
@Bean
SecurityFilterChain web(HttpSecurity http, ClientRegistrationRepository registrations) throws Exception {
    DefaultOAuth2AuthorizationRequestResolver resolver =
        new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());   // PKCE for confidential clients too
    OidcClientInitiatedLogoutSuccessHandler logout = new OidcClientInitiatedLogoutSuccessHandler(registrations);
    logout.setPostLogoutRedirectUri("{baseUrl}/");                                                  // register it as a logout URL
    http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
        .oauth2Login(o -> o.authorizationEndpoint(e -> e.authorizationRequestResolver(resolver)))
        .logout(l -> l.logoutSuccessHandler(logout));
    return http.build();
}
```

Spring verifies ID tokens signed with RS256 by default, which is what a new 9in tenant uses. If
your tenant's default key is ES256, PS256 or EdDSA, register an `OidcIdTokenDecoderFactory` bean
and `setJwsAlgorithmResolver(registration -> SignatureAlgorithm.ES256)` (or the matching
algorithm). [examples/spring-boot](examples/spring-boot) has both halves running together.

## Manage users

`ManagementClient` calls the Management API with a client-credentials token of a confidential
application that was given management scopes (**Applications → app → API Access**). Each call asks
for only the scope it needs; tokens are cached until shortly before they expire. Wire data is 9in's
snake_case JSON as `Map<String, Object>`, unchanged.

```java
ManagementClient nine = ManagementClient.fromEnv();   // NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET

Map<String, Object> user = nine.createUser(Map.of(
    "email", "jane@acme.com", "password", "correct horse battery", "name", "Jane Doe",
    "metadata", Map.of("plan", "pro")));
String id = (String) user.get("id");

nine.updateUser(id, Map.of("name", "Jane Smith"));
Map<String, Object> found = nine.findUserByEmail("jane@acme.com");   // null when there is none
nine.blockUser(id);                                                  // and unblockUser(id)
Map<String, Object> link = nine.createLoginLink(id, "/welcome", 600); // single-use sign-in URL
nine.revokeUserSessions(id);                                         // sign out everywhere
nine.deleteUser(id);
```

Also: `listUsers(query, cursor, limit)`, `listAllUsers(query)`, `getUser(id)` (with identities,
sessions and two-factor state), `findUser("phone_number" | "username", value)`,
`importUsers(users, onConflict, source)` (up to 500 per call, with password hashes),
`listUserSessions(id)` and `revokeSession(sid)`. Errors are `NineException`s with the server's
`error()`, `description()` and `status()`.

## Keep users in your own database

With the adapter protocol, 9in asks your server to check passwords and look users up. Implement
`Adapter` and serve it with `AdapterHandler`:

```java
import io.ninein.adapter.*;

class MyUserAdapter implements Adapter {
    @Override
    public AdapterUser authenticate(Identifier identifier, String password) {
        User row = users.findByEmail(identifier.value());              // identifier.type(): email, username or phone
        if (row == null || !passwords.matches(password, row.hash)) return null;   // 401 invalid_credentials
        return toNine(row);                                            // blocked(true) answers 403
    }

    @Override
    public AdapterUser findUser(UserQuery query) {
        User row = query.isById() ? users.find(query.id()) : users.findByEmail(query.identifier().value());
        return row == null ? null : toNine(row);                      // 404 not_found
    }

    @Override
    public void onEvent(Map<String, Object> event) {
        // otp.requested (when you deliver codes yourself), user.updated, user.password_changed
    }

    private AdapterUser toNine(User row) {
        return AdapterUser.builder(String.valueOf(row.id))
            .email(row.email).emailVerified(true).name(row.name).blocked(row.disabled)
            .build();
    }
}

AdapterHandler handler = AdapterHandler.fromEnv(new MyUserAdapter());   // NINE_ADAPTER_SECRET
```

In a servlet container, map `new AdapterServlet(handler)` to your adapter base URL with a wildcard
(`/nine/*` serves `/nine/authenticate`, `/nine/user` and `/nine/event`). Anywhere else, call
`handler.handle(method, path, headers, rawBody)` and send back the `AdapterResponse`'s status,
headers and body.

Requests must carry a valid `9in-signature` (HMAC-SHA256 over the timestamp, method, path and raw
body, a 5-minute window, compared in constant time; several secrets during rotation). Every
response is signed over `<path>#<9in-request-id>`, so it can't be replayed for another request.

## Webhooks

```java
WebhookEvent event = Webhooks.verify(System.getenv("NINE_WEBHOOK_SECRET"),
    rawBody,                                   // the bytes as received, before any JSON parsing
    request.getHeader("9in-signature"),
    request.getRequestURI());                  // the path 9in posted to
if (event.eventType().equals("user.created")) {
    Map<String, Object> user = event.user();
}
```

A bad signature throws `SignatureException` (401); a body that isn't an event throws
`invalid_payload` (400). Events keep their `id()` on every retry, so process each one once:

```java
EventDeduplicator dedupe = new EventDeduplicator(cache);   // a shared Cache whose add() is atomic
EventDeduplicator.Outcome outcome = dedupe.process(event.id(), () -> handle(event));
response.setStatus(outcome.httpStatus());                  // 204, or 409 while another delivery runs
```

If `handle` throws, the id is released and the exception rethrown: answer 5xx and 9in retries.
`WebhookServlet` does all of this in a servlet container:

```java
servletContext.addServlet("nine-webhook", WebhookServlet.builder(Webhooks.secretsFromEnv())
        .dedupe(cache)          // process each event once
        .verifier(verifier)     // HybridTokenVerifier: revocations take effect at once
        .handler(event -> { /* your code */ })
        .build())
    .addMapping("/nine/webhook");
```

## Issuers must use https

Every client refuses an issuer that isn't `https` (`insecure_issuer`), except `localhost`,
`*.localhost` and loopback addresses for development. `allowInsecureIssuer(true)` or
`NINE_ALLOW_INSECURE_ISSUER=true` turns the check off; never in production. Issuers with a query,
fragment or credentials are refused (`invalid_issuer`). A trailing slash is ignored.

## Errors

Everything throws `NineException` (unchecked) with `error()`, `description()` and `status()`:

| `error()` | Meaning |
|---|---|
| `invalid_state` | The callback doesn't match a sign-in in progress (expired, another browser, a replay) |
| `invalid_issuer` | The callback's `iss` (or the discovery document) isn't your issuer |
| `missing_code` | The callback has no code |
| `invalid_id_token` | The ID token failed verification |
| `invalid_token` | An access token failed verification (`InvalidTokenException`, 401) |
| `insufficient_scope` | A required scope is missing (`InsufficientScopeException`, 403) |
| `login_required` | No refresh token: sign the user in |
| `invalid_signature` | A webhook or adapter request failed verification (`SignatureException`, 401) |
| `invalid_payload` | A webhook body isn't an event |
| `insecure_issuer`, `invalid_issuer` | The issuer isn't https, or isn't a plain URL |
| `unsupported_algorithm` | The runtime can't verify the token's algorithm (EdDSA before Java 15) |
| `discovery_failed`, `jwks_unavailable`, `introspection_failed`, `userinfo_failed`, `network_error` | 9in couldn't be reached or answered unexpectedly |
| `invalid_options` | A required setting is missing |
| OAuth errors | `access_denied`, `invalid_grant`, `invalid_client`... from 9in, passed through |

Descriptions never contain tokens or secrets, and neither does any `toString()`.

## HTTP

The SDK talks HTTP through `io.ninein.http.HttpTransport`. `UrlConnectionTransport`
(`HttpURLConnection`, also on Android) is the default; `ManagementClient` uses
`JavaHttpClientTransport` (`java.net.http`), because `HttpURLConnection` can't send `PATCH`. Both
time out after 10 seconds and never follow redirects. Pass your own with `.transport(...)` to add a
proxy or use another HTTP client. Every class is thread-safe; build one and share it.

## Development

```bash
./gradlew test                      # unit tests (JUnit 5)
./gradlew springTest                # Spring Security helpers (Java 17+)
./gradlew test -PtestJavaHome=/path/to/jdk-11    # on another JDK
NINE_E2E_ENV=/path/to/.env.e2e ./gradlew test -Pe2e --tests '*LiveTest'   # against live 9in
```

The build needs Java 17+ and compiles for Java 11 (`--release 11`). The sign-in core (`AuthClient`
and what it uses) stays within Android API 26; a test checks it with the API 26 signatures.

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in is by [Cubelet Ltd](https://cubelet.co.uk).
