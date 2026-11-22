package io.ninein.adapter;

/** A lookup from 9in: by your user id, or by an identifier. Exactly one of {@link #id()} and {@link #identifier()} is set. */
public final class UserQuery {
    private final String id;
    private final Identifier identifier;

    private UserQuery(String id, Identifier identifier) {
        this.id = id;
        this.identifier = identifier;
    }

    public static UserQuery byId(String id) {
        return new UserQuery(id, null);
    }

    public static UserQuery byIdentifier(Identifier identifier) {
        return new UserQuery(null, identifier);
    }

    /** Your user id, or null when looking up by identifier. */
    public String id() {
        return id;
    }

    /** The identifier, or null when looking up by id. */
    public Identifier identifier() {
        return identifier;
    }

    public boolean isById() {
        return id != null;
    }

    @Override
    public String toString() {
        return id != null ? "UserQuery{id}" : "UserQuery{" + identifier + "}";
    }
}
