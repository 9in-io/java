package io.ninein;

import io.ninein.internal.Env;
import io.ninein.internal.Json;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Verifies webhooks from 9in: the {@code 9in-signature} header over the raw body and the path
 * 9in posted to, then parses the event.
 *
 * <pre>{@code
 * WebhookEvent event = Webhooks.verify(System.getenv("NINE_WEBHOOK_SECRET"), rawBody,
 *     request.getHeader("9in-signature"), request.getRequestURI());
 * if (event.eventType().equals("user.created")) { ... }
 * }</pre>
 *
 * <p>Pass the body exactly as received (bytes, before any JSON parsing) and the path as in your
 * endpoint URL, without the query string.
 */
public final class Webhooks {
    public static final String SIGNATURE_HEADER = Signatures.HEADER;
    public static final String EVENT_ID_HEADER = "9in-event-id";
    public static final String EVENT_TYPE_HEADER = "9in-event-type";
    public static final String DELIVERY_ID_HEADER = "9in-delivery-id";

    private Webhooks() {}

    /** Verifies a webhook signed with {@code secret}; throws {@link SignatureException} (401) or {@code invalid_payload} (400). */
    public static WebhookEvent verify(String secret, byte[] body, String signatureHeader, String path) {
        return verify(Collections.singletonList(secret), body, signatureHeader, path, Signatures.DEFAULT_TOLERANCE);
    }

    public static WebhookEvent verify(String secret, String body, String signatureHeader, String path) {
        return verify(secret, body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8), signatureHeader, path);
    }

    /** With several secrets (rotation) and a tolerance. */
    public static WebhookEvent verify(List<String> secrets, byte[] body, String signatureHeader, String path, Duration tolerance) {
        return verify(secrets, "POST", body, signatureHeader, path, tolerance, Clock.systemUTC());
    }

    /** The full form: the request method must be POST. */
    public static WebhookEvent verify(List<String> secrets, String method, byte[] body, String signatureHeader, String path, Duration tolerance, Clock clock) {
        if (secrets == null || secrets.isEmpty() || allEmpty(secrets)) throw new NineException("invalid_options", "a webhook secret is required");
        if (method == null || !method.toUpperCase(Locale.ROOT).equals("POST")) throw new SignatureException("mismatch", "webhooks are POST requests");
        byte[] raw = body == null ? new byte[0] : body;
        Signatures.require(secrets, signatureHeader, "POST", path, raw, tolerance, clock);
        Map<String, Object> event;
        try {
            event = Json.parseObject(new String(raw, StandardCharsets.UTF_8));
        } catch (NineException e) {
            throw new NineException("invalid_payload", "the webhook body is not a JSON event", 400);
        }
        if (Json.string(event, "id") == null || Json.string(event, "event_type") == null) {
            throw new NineException("invalid_payload", "the webhook body is not a 9in event", 400);
        }
        return new WebhookEvent(event);
    }

    /**
     * The webhook secrets from the environment: {@code NINE_WEBHOOK_SECRET} (comma-separated for
     * several) and {@code NINE_WEBHOOK_SECRET_PREVIOUS} during rotation.
     */
    public static List<String> secretsFromEnv() {
        return secretsFromEnv(System.getenv(), "WEBHOOK_SECRET");
    }

    static List<String> secretsFromEnv(Map<String, String> env, String name) {
        List<String> secrets = new ArrayList<>();
        for (String key : new String[] {name, name + "_PREVIOUS"}) {
            String value = Env.get(env, key);
            if (value == null) continue;
            for (String s : value.split(",")) if (!s.trim().isEmpty()) secrets.add(s.trim());
        }
        return secrets;
    }

    private static boolean allEmpty(List<String> secrets) {
        for (String s : secrets) if (s != null && !s.isEmpty()) return false;
        return true;
    }
}
