package io.ninein;

/**
 * A webhook or adapter request failed signature verification ({@code invalid_signature}, 401).
 * {@link #reason()} says why: {@code missing}, {@code malformed}, {@code expired} or {@code mismatch}.
 */
public class SignatureException extends NineException {
    private static final long serialVersionUID = 1L;

    private final String reason;

    public SignatureException(String reason, String description) {
        super("invalid_signature", description, 401);
        this.reason = reason;
    }

    /** {@code missing}, {@code malformed}, {@code expired} or {@code mismatch}. */
    public String reason() {
        return reason;
    }
}
