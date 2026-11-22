package io.ninein.testing;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A clock tests move by hand. */
public final class TestClock extends Clock {
    private volatile Instant now;

    public TestClock() {
        this(Instant.now());
    }

    public TestClock(Instant now) {
        this.now = now;
    }

    public void advance(Duration d) {
        now = now.plus(d);
    }

    public long epochSecond() {
        return now.getEpochSecond();
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return now;
    }
}
