package io.ninein.internal;

import io.ninein.NineException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Encoding helpers: base64url, hex, URL encoding, random strings, SHA-256 and constant-time
 * comparison. Internal to the SDK; the API may change without notice.
 */
public final class Codec {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Codec() {}

    public static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Decodes unpadded (or padded) base64url; throws IllegalArgumentException on anything else. */
    public static byte[] base64UrlDecode(String value) {
        if (value == null) throw new IllegalArgumentException("null");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=';
            if (!ok) throw new IllegalArgumentException("not base64url");
        }
        return Base64.getUrlDecoder().decode(value);
    }

    /** {@code bytes} random bytes as base64url. */
    public static String randomString(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return base64Url(buf);
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    public static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[2 * i] = HEX[(bytes[i] >> 4) & 0xf];
            out[2 * i + 1] = HEX[bytes[i] & 0xf];
        }
        return new String(out);
    }

    /** Lower-case hex to bytes; null when it isn't. */
    public static byte[] fromHex(String hex) {
        if (hex == null || hex.length() % 2 != 0) return null;
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) return null;
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Constant-time equality of two strings (by their UTF-8 bytes). Null never equals anything. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(utf8(a), utf8(b));
    }

    /** RFC 3986 percent-encoding of a query component (space as %20). */
    public static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8").replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code application/x-www-form-urlencoded} body for a form. */
    public static String formEncode(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (e.getValue() == null) continue;
            if (sb.length() > 0) sb.append('&');
            sb.append(urlEncode(e.getKey())).append('=').append(urlEncode(e.getValue()));
        }
        return sb.toString();
    }

    /** Appends query parameters to a URL that may already have a query. */
    public static String appendQuery(String url, Map<String, String> params) {
        String query = formEncode(params);
        if (query.isEmpty()) return url;
        int hash = url.indexOf('#');
        String base = hash < 0 ? url : url.substring(0, hash);
        String sep = base.indexOf('?') < 0 ? "?" : (base.endsWith("?") || base.endsWith("&") ? "" : "&");
        return base + sep + query;
    }

    /**
     * Parses a query string ({@code a=1&b=2}) into a map. A parameter given twice is refused
     * ({@code invalid_request}): on a callback that would be an attempt to smuggle a second value.
     */
    public static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return out;
        for (String pair : query.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = decode(eq < 0 ? pair : pair.substring(0, eq));
            String value = eq < 0 ? "" : decode(pair.substring(eq + 1));
            if (out.containsKey(name)) throw new NineException("invalid_request", "parameter \"" + name + "\" appears twice", 400);
            out.put(name, value);
        }
        return out;
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        } catch (IllegalArgumentException e) {
            throw new NineException("invalid_request", "malformed URL encoding", 400);
        }
    }
}
