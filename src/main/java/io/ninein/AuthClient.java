package io.ninein;

import io.ninein.http.HttpTransport;
import io.ninein.http.UrlConnectionTransport;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Sign-in for any client: confidential (with a secret) or public (PKCE only). Work in progress. */
public final class AuthClient {
    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final List<String> scopes;
    private final String audience;
    private final HttpTransport transport;
    private final Clock clock;

    private AuthClient(Builder b) {
        this.issuer = b.issuer;
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.redirectUri = b.redirectUri;
        this.scopes = Collections.unmodifiableList(Arrays.asList(b.scopes));
        this.audience = b.audience;
        this.transport = b.transport == null ? new UrlConnectionTransport() : b.transport;
        this.clock = b.clock == null ? Clock.systemUTC() : b.clock;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static AuthClient fromEnv() {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public Discovery discovery() {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public Login createLogin() {
        return createLogin(LoginOptions.defaults());
    }

    public Login createLogin(LoginOptions options) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public TokenSet handleCallback(String callbackUrl, PendingLogin pending) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public TokenSet refresh(TokenSet tokens) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public TokenSet refresh(String refreshToken) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public TokenSet ensureFresh(TokenSet tokens, Duration leeway) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public Map<String, Object> userInfo(String accessToken) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public void revoke(String token, String tokenTypeHint) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public String logoutUrl(String idTokenHint, String postLogoutRedirectUri, String state) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public TokenSet clientCredentials(String audience, String scope) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public DeviceAuthorization startDeviceAuthorization(String scope) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public TokenSet pollDeviceAuthorization(DeviceAuthorization authorization) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public static final class Builder {
        private String issuer;
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private String[] scopes = {"openid", "profile", "email", "offline_access"};
        private String audience;
        private HttpTransport transport;
        private Clock clock;
        private boolean allowInsecureIssuer;

        private Builder() {}

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder clientId(String id) {
            this.clientId = id;
            return this;
        }

        public Builder clientSecret(String secretOrNull) {
            this.clientSecret = secretOrNull;
            return this;
        }

        public Builder redirectUri(String uri) {
            this.redirectUri = uri;
            return this;
        }

        public Builder scopes(String... scopes) {
            this.scopes = scopes.clone();
            return this;
        }

        public Builder audience(String audienceOrNull) {
            this.audience = audienceOrNull;
            return this;
        }

        public Builder transport(HttpTransport t) {
            this.transport = t;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public Builder allowInsecureIssuer(boolean allow) {
            this.allowInsecureIssuer = allow;
            return this;
        }

        public AuthClient build() {
            return new AuthClient(this);
        }
    }
}
