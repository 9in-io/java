package io.ninein;

import io.ninein.internal.Json;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What to keep between the redirect to 9in and the callback: the {@code state}, {@code nonce}
 * and PKCE {@code code_verifier} of one sign-in, the redirect URI it used, the path to return to
 * and when it started. It is secret (the code verifier is a credential): keep it server-side in
 * the user's session, or in encrypted storage on a device, and use it once.
 *
 * <p>{@link #toJson()} / {@link #fromJson(String)} serialise it, e.g. for a session store.
 */
public final class PendingLogin {
    private final String state;
    private final String nonce;
    private final String codeVerifier;
    private final String redirectUri;
    private final String returnTo;
    private final Instant createdAt;

    public PendingLogin(String state, String nonce, String codeVerifier, String redirectUri, String returnTo, Instant createdAt) {
        if (state == null || state.isEmpty()) throw new IllegalArgumentException("state is required");
        if (nonce == null || nonce.isEmpty()) throw new IllegalArgumentException("nonce is required");
        if (codeVerifier == null || codeVerifier.isEmpty()) throw new IllegalArgumentException("codeVerifier is required");
        if (createdAt == null) throw new IllegalArgumentException("createdAt is required");
        this.state = state;
        this.nonce = nonce;
        this.codeVerifier = codeVerifier;
        this.redirectUri = redirectUri;
        this.returnTo = returnTo;
        this.createdAt = createdAt;
    }

    public String state() {
        return state;
    }

    public String nonce() {
        return nonce;
    }

    public String codeVerifier() {
        return codeVerifier;
    }

    /** The redirect URI the authorization request used (sent again with the code). */
    public String redirectUri() {
        return redirectUri;
    }

    /** The same-site path to return to after sign-in, or null. */
    public String returnTo() {
        return returnTo;
    }

    public Instant createdAt() {
        return createdAt;
    }

    /** JSON with snake_case keys; {@code created_at} in unix seconds. */
    public String toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("state", state);
        map.put("nonce", nonce);
        map.put("code_verifier", codeVerifier);
        if (redirectUri != null) map.put("redirect_uri", redirectUri);
        if (returnTo != null) map.put("return_to", returnTo);
        map.put("created_at", createdAt.getEpochSecond());
        return Json.write(map);
    }

    /** Reads {@link #toJson()} output. Throws {@link NineException} ({@code invalid_state}) on anything else. */
    public static PendingLogin fromJson(String json) {
        Map<String, Object> map;
        try {
            map = Json.parseObject(json);
        } catch (NineException e) {
            throw new NineException("invalid_state", "the pending sign-in is not valid JSON", 400);
        }
        String state = Json.string(map, "state");
        String nonce = Json.string(map, "nonce");
        String verifier = Json.string(map, "code_verifier");
        Long created = Json.number(map, "created_at");
        if (state == null || state.isEmpty() || nonce == null || nonce.isEmpty() || verifier == null || verifier.isEmpty() || created == null) {
            throw new NineException("invalid_state", "the pending sign-in is incomplete", 400);
        }
        return new PendingLogin(state, nonce, verifier, Json.string(map, "redirect_uri"), Json.string(map, "return_to"), Instant.ofEpochSecond(created));
    }

    @Override
    public String toString() {
        return "PendingLogin{createdAt=" + createdAt + ", returnTo=" + returnTo + "}"; // never the secrets
    }
}
