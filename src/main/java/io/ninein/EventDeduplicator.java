package io.ninein;

import java.time.Duration;

/**
 * Processes each webhook event at most once. 9in keeps the event id on every retry and
 * redelivery, and retries until it gets a 2xx, for about a day.
 *
 * <pre>{@code
 * EventDeduplicator dedupe = new EventDeduplicator(cache);   // a shared Cache with an atomic add
 * EventDeduplicator.Outcome outcome = dedupe.process(event.id(), () -> handle(event));
 * response.setStatus(outcome.httpStatus());                  // 204, or 409 while in progress
 * }</pre>
 *
 * <ul>
 *   <li>{@link Outcome#PROCESSED}: first delivery, the handler succeeded: answer 2xx.
 *   <li>{@link Outcome#DUPLICATE}: already processed: answer 2xx so 9in stops retrying.
 *   <li>{@link Outcome#IN_PROGRESS}: another delivery of the same event is still running: answer
 *       409 so 9in tries again later.
 *   <li>The handler threw: the id is released and the exception rethrown: answer 5xx so 9in retries.
 * </ul>
 */
public final class EventDeduplicator {
    /** The result of {@link #process}. */
    public enum Outcome {
        PROCESSED("processed", 204), DUPLICATE("duplicate", 204), IN_PROGRESS("in_progress", 409);

        private final String status;
        private final int httpStatus;

        Outcome(String status, int httpStatus) {
            this.status = status;
            this.httpStatus = httpStatus;
        }

        /** {@code processed}, {@code duplicate} or {@code in_progress}. */
        public String status() {
            return status;
        }

        /** What to answer 9in: 204, or 409 for {@link #IN_PROGRESS}. */
        public int httpStatus() {
            return httpStatus;
        }
    }

    private final Cache cache;
    private final Duration ttl;
    private final Duration claimTtl;
    private final String prefix;

    /** Processed ids are remembered for 3 days; a running handler holds its id for 5 minutes. */
    public EventDeduplicator(Cache cache) {
        this(cache, Duration.ofDays(3), Duration.ofMinutes(5), "nine:event:");
    }

    /**
     * @param ttl how long a processed id is remembered
     * @param claimTtl how long a running handler holds the id before another delivery may take over
     * @param prefix cache key prefix
     */
    public EventDeduplicator(Cache cache, Duration ttl, Duration claimTtl, String prefix) {
        if (cache == null) throw new IllegalArgumentException("a cache is required");
        this.cache = cache;
        this.ttl = ttl;
        this.claimTtl = claimTtl;
        this.prefix = prefix == null ? "" : prefix;
    }

    /** Runs {@code handler} unless this event id was (or is being) processed. Rethrows what the handler throws. */
    public Outcome process(String eventId, Runnable handler) {
        if (eventId == null || eventId.isEmpty()) throw new NineException("invalid_event", "an event id is required", 400);
        String key = prefix + eventId;
        if (!cache.add(key, "processing", claimTtl)) {
            return "done".equals(cache.get(key)) ? Outcome.DUPLICATE : Outcome.IN_PROGRESS;
        }
        try {
            handler.run();
        } catch (RuntimeException | Error e) {
            cache.delete(key);
            throw e;
        }
        cache.set(key, "done", ttl);
        return Outcome.PROCESSED;
    }
}
