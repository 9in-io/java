package io.ninein;

import java.time.Duration;
import java.time.Instant;

/**
 * A device authorization in progress (RFC 8628): show the user {@link #userCode()} and
 * {@link #verificationUri()} (or a QR code of {@link #verificationUriComplete()}), then call
 * {@link AuthClient#pollDeviceAuthorization(DeviceAuthorization)}. Immutable.
 */
public final class DeviceAuthorization {
    private final String deviceCode;
    private final String userCode;
    private final String verificationUri;
    private final String verificationUriComplete;
    private final Instant expiresAt;
    private final Duration interval;

    public DeviceAuthorization(String deviceCode, String userCode, String verificationUri, String verificationUriComplete, Instant expiresAt, Duration interval) {
        if (deviceCode == null || deviceCode.isEmpty()) throw new IllegalArgumentException("deviceCode is required");
        this.deviceCode = deviceCode;
        this.userCode = userCode;
        this.verificationUri = verificationUri;
        this.verificationUriComplete = verificationUriComplete;
        this.expiresAt = expiresAt;
        this.interval = interval == null ? Duration.ofSeconds(5) : interval;
    }

    /** The secret code the device polls with (never show it). */
    public String deviceCode() {
        return deviceCode;
    }

    /** The short code the user types on the verification page. */
    public String userCode() {
        return userCode;
    }

    /** Where the user goes on another device. */
    public String verificationUri() {
        return verificationUri;
    }

    /** The verification URI with the user code filled in (for a QR code), or null. */
    public String verificationUriComplete() {
        return verificationUriComplete;
    }

    /** When the codes expire. */
    public Instant expiresAt() {
        return expiresAt;
    }

    /** How long to wait between polls (default 5 seconds). */
    public Duration interval() {
        return interval;
    }

    @Override
    public String toString() {
        return "DeviceAuthorization{userCode=" + userCode + ", verificationUri=" + verificationUri + ", expiresAt=" + expiresAt + "}";
    }
}
