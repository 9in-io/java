package io.ninein;

/** The access token is valid but lacks a required scope: answer 403 with {@code insufficient_scope}. */
public class InsufficientScopeException extends NineException {
    private static final long serialVersionUID = 1L;

    public InsufficientScopeException(String description) {
        super("insufficient_scope", description, 403);
    }
}
