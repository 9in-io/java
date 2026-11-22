package io.ninein;

import io.ninein.internal.Json;
import java.util.Map;

/**
 * A verified webhook event: {@code {id, event_type, created_at, tenant, environment, data}}
 * (snake_case, ISO 8601 UTC times). {@link #data()} carries the event details and the
 * {@code user} it is about (null when there is none). The {@link #id()} stays the same on every
 * retry and redelivery. Immutable; {@link #asMap()} has the event unchanged.
 */
public final class WebhookEvent {
    private final Map<String, Object> event;

    public WebhookEvent(Map<String, ?> event) {
        this.event = Json.freezeObject(event);
    }

    /** The event id: the same on every retry and redelivery (deduplicate on it). */
    public String id() {
        return Json.string(event, "id");
    }

    /** {@code user.created}, {@code token.revoked}, ... (also in the {@code 9in-event-type} header). */
    public String eventType() {
        return Json.string(event, "event_type");
    }

    /** ISO 8601 UTC. */
    public String createdAt() {
        return Json.string(event, "created_at");
    }

    /** The tenant id ({@code tnt_...}). */
    public String tenant() {
        return Json.string(event, "tenant");
    }

    /** {@code production} or {@code sandbox}. */
    public String environment() {
        return Json.string(event, "environment");
    }

    /** The event details (empty when absent). */
    public Map<String, Object> data() {
        Map<String, Object> data = Json.object(event, "data");
        return data == null ? java.util.Collections.<String, Object>emptyMap() : data;
    }

    /** The user the event is about ({@code data.user}), or null. For {@code user.deleted}, the user as it was. */
    public Map<String, Object> user() {
        return Json.object(data(), "user");
    }

    /** The whole event, unchanged. */
    public Map<String, Object> asMap() {
        return event;
    }

    @Override
    public String toString() {
        return "WebhookEvent{id=" + id() + ", event_type=" + eventType() + "}";
    }
}
