package io.ninein;

/**
 * Every error the SDK raises: an OAuth-style error code ({@link #error()}), a human-readable
 * {@link #description()} and, when it maps to one, the HTTP status ({@link #status()}).
 *
 * <p>Errors from 9in keep the server's {@code error} and {@code error_description} unchanged,
 * so you can switch on {@code error()} ({@code "invalid_grant"}, {@code "access_denied"},
 * {@code "invalid_state"}, {@code "insecure_issuer"} ...).
 */
public class NineException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String error;
    private final String description;
    private final Integer status;

    public NineException(String error, String description) {
        this(error, description, null, null);
    }

    public NineException(String error, String description, Integer status) {
        this(error, description, status, null);
    }

    public NineException(String error, String description, Integer status, Throwable cause) {
        super(description == null || description.isEmpty() ? error : error + ": " + description, cause);
        this.error = error;
        this.description = description == null ? "" : description;
        this.status = status;
    }

    /** The error code, e.g. {@code invalid_token}, {@code invalid_grant}, {@code invalid_state}. */
    public String error() {
        return error;
    }

    /** What went wrong, in words (never contains tokens or secrets). */
    public String description() {
        return description;
    }

    /** The HTTP status this error maps to (the server's, or 400/401/403 for local checks), or null. */
    public Integer status() {
        return status;
    }
}
