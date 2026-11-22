package io.ninein;

import java.time.Duration;

/**
 * A key-value store shared by your servers (Redis, Memcached, a database table...), for the
 * hybrid verifier's answers and for processing each webhook once. Values are strings. A null
 * {@code ttl} means no expiry. Implementations must be thread-safe, and {@link #add} must be
 * atomic (insert only when the key is absent or expired), e.g. Redis {@code SET key value NX EX ttl}.
 *
 * <p>{@link MemoryCache} is the in-process implementation (one server, tests).
 */
public interface Cache {
    /** The value, or null when absent or expired. */
    String get(String key);

    void set(String key, String value, Duration ttl);

    void delete(String key);

    /** Stores the value only when the key is absent (or expired); true when it did. Must be atomic. */
    boolean add(String key, String value, Duration ttl);
}
