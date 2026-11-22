package io.ninein;

import io.ninein.internal.Codec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 9in request signatures, used by webhooks and the adapter protocol:
 *
 * <pre>
 * 9in-signature: t=&lt;unix seconds&gt;,v1=&lt;hex HMAC-SHA256(secret, "&lt;t&gt;.&lt;METHOD&gt;.&lt;path&gt;.&lt;raw body&gt;")&gt;
 * </pre>
 *
 * <p>The timestamp is part of the signed payload and must be within a tolerance (300 seconds by
 * default), so a captured request can't be replayed later. Several {@code v1=} values and several
 * secrets are accepted, for secret rotation. Comparisons are constant-time. Adapter responses are
 * signed the same way over the path {@code <request path>#<9in-request-id>}.
 */
public final class Signatures {
    public static final String HEADER = "9in-signature";
    public static final String REQUEST_ID_HEADER = "9in-request-id";
    public static final Duration DEFAULT_TOLERANCE = Duration.ofSeconds(300);

    private static final Pattern TIMESTAMP = Pattern.compile("^[0-9]{1,12}$");
    private static final Pattern V1 = Pattern.compile("^[0-9a-f]{64}$");

    private Signatures() {}

    /** Why a signature check failed. */
    public enum Reason {
        MISSING, MALFORMED, EXPIRED, MISMATCH;

        /** {@code missing}, {@code malformed}, {@code expired} or {@code mismatch}. */
        public String code() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** The outcome of {@link #check}: ok, or the reason it failed. */
    public static final class Result {
        private final Reason reason;
        private final Long timestamp;

        private Result(Reason reason, Long timestamp) {
            this.reason = reason;
            this.timestamp = timestamp;
        }

        public boolean ok() {
            return reason == null;
        }

        /** Null when ok. */
        public Reason reason() {
            return reason;
        }

        /** The signed timestamp (unix seconds), when the header could be parsed. */
        public Long timestamp() {
            return timestamp;
        }
    }

    /** The header value for a request or response signed now. */
    public static String sign(String secret, String method, String path, byte[] body) {
        return sign(secret, method, path, body, Clock.systemUTC().millis() / 1000);
    }

    /** The header value for a signature at {@code timestamp} (unix seconds). */
    public static String sign(String secret, String method, String path, byte[] body, long timestamp) {
        if (secret == null || secret.isEmpty()) throw new IllegalArgumentException("a signing secret is required");
        return "t=" + timestamp + ",v1=" + Codec.hex(mac(secret, timestamp, method, path, body));
    }

    public static String sign(String secret, String method, String path, String body) {
        return sign(secret, method, path, utf8(body));
    }

    public static String sign(String secret, String method, String path, String body, long timestamp) {
        return sign(secret, method, path, utf8(body), timestamp);
    }

    /** True when the header is a valid signature by one of {@code secrets}, within the default tolerance. */
    public static boolean verify(List<String> secrets, String header, String method, String path, byte[] body) {
        return check(secrets, header, method, path, body, DEFAULT_TOLERANCE, Clock.systemUTC()).ok();
    }

    public static boolean verify(String secret, String header, String method, String path, byte[] body) {
        return verify(Collections.singletonList(secret), header, method, path, body);
    }

    public static boolean verify(String secret, String header, String method, String path, String body) {
        return verify(Collections.singletonList(secret), header, method, path, utf8(body));
    }

    /** Checks a signature and says why it failed. */
    public static Result check(List<String> secrets, String header, String method, String path, byte[] body, Duration tolerance, Clock clock) {
        if (header == null || header.isEmpty()) return new Result(Reason.MISSING, null);
        Long timestamp = null;
        List<byte[]> candidates = new ArrayList<>();
        for (String part : header.split(",", -1)) {
            int eq = part.indexOf('=');
            if (eq < 1) return new Result(Reason.MALFORMED, null);
            String name = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            if (name.equals("t")) {
                if (!TIMESTAMP.matcher(value).matches()) return new Result(Reason.MALFORMED, null);
                timestamp = Long.parseLong(value);
            } else if (name.equals("v1")) {
                if (!V1.matcher(value).matches()) return new Result(Reason.MALFORMED, null);
                candidates.add(Codec.fromHex(value));
            }
        }
        if (timestamp == null || candidates.isEmpty()) return new Result(Reason.MALFORMED, null);
        long now = clock.millis() / 1000;
        long window = (tolerance == null ? DEFAULT_TOLERANCE : tolerance).getSeconds();
        if (Math.abs(now - timestamp) > window) return new Result(Reason.EXPIRED, timestamp);
        if (secrets != null) {
            for (String secret : secrets) {
                if (secret == null || secret.isEmpty()) continue;
                byte[] expected = mac(secret, timestamp, method, path, body);
                for (byte[] candidate : candidates) {
                    if (MessageDigest.isEqual(expected, candidate)) return new Result(null, timestamp);
                }
            }
        }
        return new Result(Reason.MISMATCH, timestamp);
    }

    /** Like {@link #check} but throws {@link SignatureException}; returns the signed timestamp. */
    public static long require(List<String> secrets, String header, String method, String path, byte[] body, Duration tolerance, Clock clock) {
        Result result = check(secrets, header, method, path, body, tolerance, clock);
        if (!result.ok()) {
            throw new SignatureException(result.reason().code(), "signature verification failed (" + result.reason().code() + ")");
        }
        return result.timestamp();
    }

    private static byte[] mac(String secret, long timestamp, String method, String path, byte[] body) {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        byte[] prefix = (timestamp + "." + method.toUpperCase(Locale.ROOT) + "." + path + ".").getBytes(StandardCharsets.UTF_8);
        payload.write(prefix, 0, prefix.length);
        if (body != null) payload.write(body, 0, body.length);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(payload.toByteArray());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is not available", e);
        }
    }

    private static byte[] utf8(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }
}
