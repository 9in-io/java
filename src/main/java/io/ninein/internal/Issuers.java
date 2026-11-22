package io.ninein.internal;

import io.ninein.NineException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Issuer URL rules, the same in every 9in SDK: issuers must use https. Plain http is accepted
 * only for {@code localhost}, {@code *.localhost} and loopback addresses (development), or when
 * the caller allows it ({@code allowInsecureIssuer} / {@code NINE_ALLOW_INSECURE_ISSUER=true}).
 * Issuers with a query, fragment or credentials are rejected. A trailing slash is dropped.
 * Internal to the SDK.
 */
public final class Issuers {
    private static final Pattern LOOPBACK_V4 = Pattern.compile("^127(\\.\\d{1,3}){3}$");

    private Issuers() {}

    /**
     * Returns the issuer without a trailing slash. Throws {@link NineException}
     * ({@code invalid_issuer} or {@code insecure_issuer}).
     */
    public static String normalize(String issuer, boolean allowInsecure) {
        if (issuer == null || issuer.trim().isEmpty()) throw new NineException("invalid_issuer", "an issuer is required");
        URI uri;
        try {
            uri = new URI(issuer.trim());
        } catch (URISyntaxException e) {
            throw new NineException("invalid_issuer", "not a URL: " + issuer);
        }
        String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if (scheme == null || host == null || host.isEmpty() || uri.isOpaque()) {
            throw new NineException("invalid_issuer", "not a URL: " + issuer);
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getRawUserInfo() != null || issuer.indexOf('?') >= 0 || issuer.indexOf('#') >= 0) {
            throw new NineException("invalid_issuer", "an issuer has no query, fragment or credentials");
        }
        boolean secure = "https".equals(scheme)
                || ("http".equals(scheme) && (allowInsecure || isLocalHost(host) || insecureAllowedByEnv()));
        if (!secure) {
            throw new NineException("insecure_issuer", "issuer must use https (got " + scheme + "://" + host + "); plain http is only accepted for localhost");
        }
        String out = issuer.trim();
        while (out.endsWith("/")) out = out.substring(0, out.length() - 1);
        return out;
    }

    /** {@code localhost}, {@code *.localhost}, {@code ::1} or {@code 127.x.x.x}. */
    public static boolean isLocalHost(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        return h.equals("localhost") || h.endsWith(".localhost") || h.equals("::1") || h.equals("0:0:0:0:0:0:0:1") || LOOPBACK_V4.matcher(h).matches();
    }

    /** True when {@code NINE_ALLOW_INSECURE_ISSUER} is 1/true/yes/on. */
    public static boolean insecureAllowedByEnv() {
        return Env.flag(System.getenv("NINE_ALLOW_INSECURE_ISSUER"));
    }

    /** Two issuers are the same when they are equal without trailing slashes. */
    public static boolean same(String a, String b) {
        if (a == null || b == null) return false;
        return strip(a).equals(strip(b));
    }

    private static String strip(String s) {
        String out = s;
        while (out.endsWith("/")) out = out.substring(0, out.length() - 1);
        return out;
    }
}
