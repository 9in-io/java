package io.ninein.internal;

import java.util.Locale;
import java.util.Map;

/** Reads {@code NINE_*} settings from an environment map. Internal to the SDK. */
public final class Env {
    private Env() {}

    /** {@code NINE_<name>} (name with or without the prefix), or null when unset or empty. */
    public static String get(Map<String, String> env, String name) {
        String key = name.startsWith("NINE_") ? name : "NINE_" + name;
        String value = env == null ? null : env.get(key);
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    /** True for 1, true, yes, on (any case). */
    public static boolean flag(String value) {
        if (value == null) return false;
        String v = value.trim().toLowerCase(Locale.ROOT);
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

    /** Comma- or space-separated values, or an empty array. */
    public static String[] list(String value) {
        if (value == null || value.trim().isEmpty()) return new String[0];
        return value.trim().split("[\\s,]+");
    }
}
