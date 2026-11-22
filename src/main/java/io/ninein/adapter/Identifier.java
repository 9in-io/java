package io.ninein.adapter;

/** How a user identified themselves: {@code email}, {@code username} or {@code phone}, and the value. Immutable. */
public final class Identifier {
    private final String type;
    private final String value;

    public Identifier(String type, String value) {
        this.type = type;
        this.value = value;
    }

    /** {@code email}, {@code username} or {@code phone}. */
    public String type() {
        return type;
    }

    /** The email address, username or phone number (E.164) as typed. */
    public String value() {
        return value;
    }

    public boolean isEmail() {
        return "email".equals(type);
    }

    public boolean isUsername() {
        return "username".equals(type);
    }

    public boolean isPhone() {
        return "phone".equals(type);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Identifier && type.equals(((Identifier) o).type) && value.equals(((Identifier) o).value);
    }

    @Override
    public int hashCode() {
        return 31 * type.hashCode() + value.hashCode();
    }

    @Override
    public String toString() {
        return "Identifier{" + type + "}";
    }
}
