package io.ninein.adapter;

import java.util.Map;

/**
 * Your user database, as 9in sees it (adapter protocol v2). Implement it and serve it with
 * {@link AdapterHandler} (or {@code io.ninein.servlet.AdapterServlet}).
 */
public interface Adapter {
    /**
     * Checks a password. Return the user; null for an unknown user or a wrong password (9in does
     * not tell them apart); a user with {@code blocked(true)} to refuse a blocked account.
     */
    AdapterUser authenticate(Identifier identifier, String password);

    /** Looks a user up by your id or by an identifier; null when unknown. */
    AdapterUser findUser(UserQuery query);

    /**
     * Notifications: {@code otp.requested} (deliver the code yourself: {@code data} has
     * {@code user_id}, {@code channel}, {@code to}, {@code code}, {@code purpose}, {@code expires_at}),
     * {@code user.updated} and {@code user.password_changed} ({@code user_id}, {@code fields}).
     * The event is {@code {id, event_type, created_at, data}}. Does nothing by default.
     */
    default void onEvent(Map<String, Object> event) {}
}
