package io.ninein.adapter;

import io.ninein.internal.Json;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * A user from your database, in the shape 9in expects (OpenID Connect claim names, snake_case).
 * {@code metadata} is stored on the 9in user. Immutable.
 *
 * <pre>{@code
 * AdapterUser.builder(String.valueOf(row.id))
 *     .email(row.email).emailVerified(true)
 *     .name(row.fullName)
 *     .metadata(Map.of("plan", row.plan))
 *     .build();
 * }</pre>
 */
public final class AdapterUser {
    /** The fields 9in reads; anything else is dropped. */
    public static final Set<String> FIELDS = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            "id", "email", "email_verified", "phone_number", "phone_number_verified", "username", "name",
            "given_name", "family_name", "picture", "locale", "zoneinfo", "birthdate", "blocked", "metadata")));
    private static final Set<String> FLAGS = new LinkedHashSet<>(Arrays.asList("email_verified", "phone_number_verified", "blocked"));

    private final Map<String, Object> fields;

    private AdapterUser(Map<String, Object> fields) {
        Object id = fields.get("id");
        if (id == null || id.toString().isEmpty()) throw new IllegalArgumentException("a user id is required");
        this.fields = Json.freezeObject(fields);
    }

    public static Builder builder(String id) {
        return new Builder(id);
    }

    /**
     * A user from a snake_case map (unknown keys dropped, {@code id} turned into a string, flags into
     * booleans, a non-object {@code metadata} into null).
     */
    public static AdapterUser of(Map<String, ?> data) {
        Map<String, Object> clean = new LinkedHashMap<>();
        for (Map.Entry<String, ?> e : data.entrySet()) {
            if (!FIELDS.contains(e.getKey())) continue;
            Object v = e.getValue();
            if (e.getKey().equals("id") && v != null) v = v.toString();
            if (FLAGS.contains(e.getKey()) && v != null && !(v instanceof Boolean)) v = truthy(v);
            if (e.getKey().equals("metadata") && v != null && !(v instanceof Map)) v = null;
            clean.put(e.getKey(), v);
        }
        return new AdapterUser(clean);
    }

    public String id() {
        return (String) fields.get("id");
    }

    public boolean isBlocked() {
        return Boolean.TRUE.equals(fields.get("blocked"));
    }

    /** A field by its snake_case name, or null. */
    public Object get(String field) {
        return fields.get(field);
    }

    /** The JSON object 9in receives. */
    public Map<String, Object> toMap() {
        return fields;
    }

    private static boolean truthy(Object v) {
        if (v instanceof Number) return ((Number) v).doubleValue() != 0;
        String s = v.toString().trim().toLowerCase(java.util.Locale.ROOT);
        return s.equals("1") || s.equals("true") || s.equals("yes") || s.equals("on");
    }

    @Override
    public String toString() {
        return "AdapterUser{id=" + id() + "}";
    }

    /** Builds an {@link AdapterUser}. Only the fields you set are sent. */
    public static final class Builder {
        private final Map<String, Object> fields = new LinkedHashMap<>();

        private Builder(String id) {
            fields.put("id", id);
        }

        private Builder put(String name, Object value) {
            fields.put(name, value);
            return this;
        }

        public Builder email(String email) {
            return put("email", email);
        }

        public Builder emailVerified(Boolean verified) {
            return put("email_verified", verified);
        }

        /** E.164, e.g. {@code +447700900123}. */
        public Builder phoneNumber(String phone) {
            return put("phone_number", phone);
        }

        public Builder phoneNumberVerified(Boolean verified) {
            return put("phone_number_verified", verified);
        }

        public Builder username(String username) {
            return put("username", username);
        }

        public Builder name(String name) {
            return put("name", name);
        }

        public Builder givenName(String givenName) {
            return put("given_name", givenName);
        }

        public Builder familyName(String familyName) {
            return put("family_name", familyName);
        }

        /** An https URL. */
        public Builder picture(String url) {
            return put("picture", url);
        }

        public Builder locale(String locale) {
            return put("locale", locale);
        }

        public Builder zoneinfo(String zoneinfo) {
            return put("zoneinfo", zoneinfo);
        }

        /** {@code YYYY-MM-DD}. */
        public Builder birthdate(String birthdate) {
            return put("birthdate", birthdate);
        }

        /** True refuses sign-in (403 {@code blocked}). */
        public Builder blocked(Boolean blocked) {
            return put("blocked", blocked);
        }

        /** Stored on the 9in user (a JSON object). */
        public Builder metadata(Map<String, ?> metadata) {
            return put("metadata", metadata == null ? null : new LinkedHashMap<String, Object>(metadata));
        }

        public AdapterUser build() {
            return new AdapterUser(fields);
        }
    }
}
