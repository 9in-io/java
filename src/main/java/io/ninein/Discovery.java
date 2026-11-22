package io.ninein;

import io.ninein.internal.Json;
import java.util.Map;

/**
 * A tenant's OpenID Connect metadata ({@code /.well-known/openid-configuration}), as
 * {@link AuthClient#discovery()} fetched it. Immutable; {@link #raw()} has every field unchanged.
 */
public final class Discovery {
    private final Map<String, Object> raw;

    public Discovery(Map<String, ?> raw) {
        this.raw = Json.freezeObject(raw);
    }

    public String issuer() {
        return Json.string(raw, "issuer");
    }

    public String authorizationEndpoint() {
        return Json.string(raw, "authorization_endpoint");
    }

    public String tokenEndpoint() {
        return Json.string(raw, "token_endpoint");
    }

    public String userinfoEndpoint() {
        return Json.string(raw, "userinfo_endpoint");
    }

    public String jwksUri() {
        return Json.string(raw, "jwks_uri");
    }

    /** RP-initiated logout endpoint, or null. */
    public String endSessionEndpoint() {
        return Json.string(raw, "end_session_endpoint");
    }

    /** Token revocation endpoint (RFC 7009), or null. */
    public String revocationEndpoint() {
        return Json.string(raw, "revocation_endpoint");
    }

    /** Token introspection endpoint (RFC 7662), or null. */
    public String introspectionEndpoint() {
        return Json.string(raw, "introspection_endpoint");
    }

    /** Device authorization endpoint (RFC 8628), or null. */
    public String deviceAuthorizationEndpoint() {
        return Json.string(raw, "device_authorization_endpoint");
    }

    /** True when the server sends the RFC 9207 {@code iss} parameter on the callback (then it is required). */
    public boolean authorizationResponseIssParameterSupported() {
        return Boolean.TRUE.equals(raw.get("authorization_response_iss_parameter_supported"));
    }

    /** Every metadata field, unchanged. */
    public Map<String, Object> raw() {
        return raw;
    }

    @Override
    public String toString() {
        return "Discovery{issuer=" + issuer() + "}";
    }
}
