# Example: Spring Boot with 9in

Spring Security's own `oauth2Login()` signs users in with 9in (PKCE, OpenID Connect logout), and
`/api/**` is a resource server that checks bearer tokens with the 9in SDK's
`NineOpaqueTokenIntrospector` (every key algorithm, opaque tokens, hybrid revocation). 9in's
webhooks arrive at `/nine/webhook` (the SDK's `WebhookServlet`), which also evicts revoked tokens.

```bash
export NINE_ISSUER=https://acme.9in.io
export NINE_CLIENT_ID=app_...
export NINE_CLIENT_SECRET=...                       # a confidential application
export NINE_API_AUDIENCE=https://api.acme.com       # the API that /api/** protects
export NINE_WEBHOOK_SECRET=...                      # optional
export PORT=8080
../../gradlew bootRun
```

Register `http://127.0.0.1:8080/login/oauth2/code/nine` as a callback URL of the application (or
set `NINE_REDIRECT_URI` to a callback you registered), and `http://127.0.0.1:8080/` as a logout URL.
Open http://127.0.0.1:8080/ and sign in. Call the API with an access token for `NINE_API_AUDIENCE`:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/me
```

Needs Java 17+ (Spring Boot 4). The same configuration works with Spring Boot 3.5.
