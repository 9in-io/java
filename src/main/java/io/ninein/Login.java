package io.ninein;

/**
 * A sign-in in progress: send the browser to {@link #url()} and keep {@link #pending()} until the
 * callback (in the user's server-side session, or encrypted storage on a device; it's secret).
 */
public final class Login {
    private final String url;
    private final PendingLogin pending;

    public Login(String url, PendingLogin pending) {
        this.url = url;
        this.pending = pending;
    }

    /** The authorization URL on 9in's hosted sign-in page. */
    public String url() {
        return url;
    }

    /** What {@link AuthClient#handleCallback(String, PendingLogin)} needs to finish the sign-in. */
    public PendingLogin pending() {
        return pending;
    }

    @Override
    public String toString() {
        return "Login{url=" + url + "}";
    }
}
