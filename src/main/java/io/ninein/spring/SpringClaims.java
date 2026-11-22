package io.ninein.spring;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Spring Security expects time claims as {@link Instant}s. */
final class SpringClaims {
    private static final String[] TIMES = {"exp", "iat", "nbf", "auth_time"};

    private SpringClaims() {}

    static Map<String, Object> withInstants(Map<String, Object> claims) {
        Map<String, Object> out = new LinkedHashMap<>(claims);
        for (String name : TIMES) {
            Object value = out.get(name);
            if (value instanceof Number) out.put(name, Instant.ofEpochMilli((long) (((Number) value).doubleValue() * 1000)));
        }
        return out;
    }
}
