package io.ninein;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Options for {@link AuthClient#createLogin(LoginOptions)}. Immutable; build with
 * {@link #builder()}:
 *
 * <pre>{@code
 * LoginOptions.builder().returnTo("/dashboard").screen("signup").build()
 * }</pre>
 */
public final class LoginOptions {
    private final String returnTo;
    private final String screen;
    private final String prompt;
    private final String loginHint;
    private final String redirectUri;
    private final String locale;
    private final Map<String, String> extra;

    private LoginOptions(Builder b) {
        this.returnTo = b.returnTo;
        this.screen = b.screen;
        this.prompt = b.prompt;
        this.loginHint = b.loginHint;
        this.redirectUri = b.redirectUri;
        this.locale = b.locale;
        this.extra = Collections.unmodifiableMap(new LinkedHashMap<>(b.extra));
    }

    public static Builder builder() {
        return new Builder();
    }

    static LoginOptions defaults() {
        return new Builder().build();
    }

    /** A path in your app to come back to after sign-in (only same-site relative paths are kept). */
    public String returnTo() {
        return returnTo;
    }

    /** {@code "signup"} opens the sign-up form; {@code "login"} (or null) the sign-in form. */
    public String screen() {
        return screen;
    }

    /** OpenID Connect {@code prompt}: {@code login}, {@code consent}, {@code none}, {@code select_account}, {@code create}. */
    public String prompt() {
        return prompt;
    }

    /** Prefills the identifier on the sign-in page. */
    public String loginHint() {
        return loginHint;
    }

    /** Overrides the client's redirect URI for this sign-in. */
    public String redirectUri() {
        return redirectUri;
    }

    /** Language of the hosted pages ({@code ui_locales}), e.g. {@code "de"}. */
    public String locale() {
        return locale;
    }

    /** Extra authorization parameters (they never replace state, nonce, PKCE or the client's own). */
    public Map<String, String> extra() {
        return extra;
    }

    public static final class Builder {
        private String returnTo;
        private String screen;
        private String prompt;
        private String loginHint;
        private String redirectUri;
        private String locale;
        private final Map<String, String> extra = new LinkedHashMap<>();

        private Builder() {}

        public Builder returnTo(String returnTo) {
            this.returnTo = returnTo;
            return this;
        }

        /** {@code "signup"} opens the sign-up form. */
        public Builder screen(String screen) {
            this.screen = screen;
            return this;
        }

        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public Builder loginHint(String loginHint) {
            this.loginHint = loginHint;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder locale(String locale) {
            this.locale = locale;
            return this;
        }

        public Builder extra(Map<String, String> extra) {
            if (extra != null) this.extra.putAll(extra);
            return this;
        }

        public Builder extra(String name, String value) {
            this.extra.put(name, value);
            return this;
        }

        public LoginOptions build() {
            return new LoginOptions(this);
        }
    }
}
