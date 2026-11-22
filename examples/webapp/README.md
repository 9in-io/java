# Example: sign-in and a protected API with plain Java

A web app on the JDK's built-in HTTP server: sign-in and sign-up through 9in's hosted pages,
refresh before expiry, sign-out (revoke + end the 9in session), a bearer-token API, and a webhook
endpoint that processes each event once and evicts revoked tokens.

```bash
export NINE_ISSUER=https://acme.9in.io
export NINE_CLIENT_ID=app_...
export NINE_CLIENT_SECRET=...                      # a confidential application
export NINE_REDIRECT_URI=http://127.0.0.1:8932/callback   # registered on the application
export NINE_API_AUDIENCE=https://api.acme.com      # optional: protects /api/me
export NINE_WEBHOOK_SECRET=...                     # optional: enables /nine/webhook
../../gradlew run
```

Open http://127.0.0.1:8932/ and sign in. The server listens on the redirect URI's host and port
and serves the callback at its path. Sessions live in memory: this is a demo, not a session store.
