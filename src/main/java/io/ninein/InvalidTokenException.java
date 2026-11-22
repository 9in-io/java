package io.ninein;

/** An access token is missing, malformed, expired, revoked or not for this API: answer 401 with {@code invalid_token}. */
public class InvalidTokenException extends NineException {
    private static final long serialVersionUID = 1L;

    public InvalidTokenException(String description) {
        super("invalid_token", description, 401);
    }

    public InvalidTokenException(String description, Throwable cause) {
        super("invalid_token", description, 401, cause);
    }
}
