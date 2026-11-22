package io.ninein;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An in-process {@link Cache}: thread-safe, entries expire after their TTL, and the least recently
 * used go first beyond {@code maxEntries} (default 10 000). Only for one process: with several
 * servers, use a shared store.
 */
public final class MemoryCache implements Cache {
    private static final class Entry {
        final String value;
        final Instant expiresAt;

        Entry(String value, Instant expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
    }

    private final int maxEntries;
    private final Clock clock;
    private final LinkedHashMap<String, Entry> entries;

    public MemoryCache() {
        this(10_000, Clock.systemUTC());
    }

    public MemoryCache(int maxEntries) {
        this(maxEntries, Clock.systemUTC());
    }

    public MemoryCache(int maxEntries, Clock clock) {
        if (maxEntries < 1) throw new IllegalArgumentException("maxEntries must be positive");
        this.maxEntries = maxEntries;
        this.clock = clock;
        this.entries = new LinkedHashMap<>(16, 0.75f, true);
    }

    @Override
    public synchronized String get(String key) {
        Entry e = live(key);
        return e == null ? null : e.value;
    }

    @Override
    public synchronized void set(String key, String value, Duration ttl) {
        entries.put(key, new Entry(value, ttl == null ? null : clock.instant().plus(ttl)));
        trim();
    }

    @Override
    public synchronized void delete(String key) {
        entries.remove(key);
    }

    @Override
    public synchronized boolean add(String key, String value, Duration ttl) {
        if (live(key) != null) return false;
        set(key, value, ttl);
        return true;
    }

    /** Number of entries (including expired ones not yet dropped). */
    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
    }

    private Entry live(String key) {
        Entry e = entries.get(key);
        if (e != null && e.expiresAt != null && !clock.instant().isBefore(e.expiresAt)) {
            entries.remove(key);
            return null;
        }
        return e;
    }

    private void trim() {
        if (entries.size() <= maxEntries) return;
        Instant now = clock.instant();
        for (Iterator<Map.Entry<String, Entry>> it = entries.entrySet().iterator(); it.hasNext(); ) {
            Entry e = it.next().getValue();
            if (e.expiresAt != null && !now.isBefore(e.expiresAt)) it.remove();
        }
        Iterator<String> it = entries.keySet().iterator();
        while (entries.size() > maxEntries && it.hasNext()) {
            it.next();
            it.remove();
        }
    }
}
