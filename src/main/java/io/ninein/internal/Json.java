package io.ninein.internal;

import io.ninein.NineException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, strict JSON reader and writer (RFC 8259), so the SDK needs no JSON library.
 *
 * <p>Objects read as {@code LinkedHashMap<String, Object>} (key order kept), arrays as
 * {@code ArrayList<Object>}, strings as {@code String}, {@code true}/{@code false} as
 * {@code Boolean}, {@code null} as null, integers as {@code Long} (or {@code BigInteger} when too
 * large) and other numbers as {@code Double}. The reader rejects everything RFC 8259 doesn't
 * allow (trailing commas, comments, single quotes, leading zeros, NaN, control characters in
 * strings, trailing content) and also duplicate object keys, which have been used to smuggle
 * claims past one parser and not another. Nesting is limited to 128 levels.
 *
 * <p>Internal to the SDK; the API may change without notice.
 */
public final class Json {
    private static final int MAX_DEPTH = 128;

    private Json() {}

    /** Parses any JSON value. Throws {@link NineException} ({@code invalid_json}) on bad input. */
    public static Object parse(String text) {
        if (text == null) throw new NineException("invalid_json", "no JSON");
        Reader r = new Reader(text);
        r.skipWhitespace();
        Object value = r.readValue(0);
        r.skipWhitespace();
        if (r.pos != text.length()) throw r.error("unexpected content after the JSON value");
        return value;
    }

    /** Parses a JSON object. Throws {@link NineException} ({@code invalid_json}) if it isn't one. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) throw new NineException("invalid_json", "expected a JSON object");
        return (Map<String, Object>) value;
    }

    /** Writes a value: Map, Collection, array of Object, String, Number, Boolean, Character or null. */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value, 0);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object value, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("JSON nested too deeply");
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String || value instanceof Character) {
            writeString(sb, value.toString());
        } else if (value instanceof Boolean) {
            sb.append(value.toString());
        } else if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("JSON can't represent " + d);
            if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                sb.append((long) d);
            } else {
                sb.append(Double.toString(d));
            }
        } else if (value instanceof Number) {
            sb.append(value.toString());
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                if (!(e.getKey() instanceof String)) throw new IllegalArgumentException("JSON object keys must be strings");
                if (!first) sb.append(',');
                first = false;
                writeString(sb, (String) e.getKey());
                sb.append(':');
                write(sb, e.getValue(), depth + 1);
            }
            sb.append('}');
        } else if (value instanceof Collection) {
            sb.append('[');
            boolean first = true;
            for (Object item : (Collection<?>) value) {
                if (!first) sb.append(',');
                first = false;
                write(sb, item, depth + 1);
            }
            sb.append(']');
        } else if (value instanceof Object[]) {
            sb.append('[');
            Object[] items = (Object[]) value;
            for (int i = 0; i < items.length; i++) {
                if (i > 0) sb.append(',');
                write(sb, items[i], depth + 1);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("can't write " + value.getClass().getName() + " as JSON");
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20 || c == ' ' || c == ' ') {
                        appendUnicodeEscape(sb, c);
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                            sb.append(c).append(s.charAt(++i));
                        } else {
                            appendUnicodeEscape(sb, c); // lone surrogate: keep it, escaped (like JSON.stringify)
                        }
                    } else if (Character.isLowSurrogate(c)) {
                        appendUnicodeEscape(sb, c);
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    private static void appendUnicodeEscape(StringBuilder sb, char c) {
        sb.append("\\u");
        String hex = Integer.toHexString(c);
        for (int k = hex.length(); k < 4; k++) sb.append('0');
        sb.append(hex);
    }

    private static final class Reader {
        private final String s;
        private int pos;

        Reader(String s) {
            this.s = s;
        }

        NineException error(String message) {
            return new NineException("invalid_json", message + " at offset " + pos);
        }

        void skipWhitespace() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object readValue(int depth) {
            if (depth > MAX_DEPTH) throw error("JSON nested too deeply");
            if (pos >= s.length()) throw error("unexpected end of JSON");
            char c = s.charAt(pos);
            switch (c) {
                case '{': return readObject(depth);
                case '[': return readArray(depth);
                case '"': return readString();
                case 't': expectWord("true"); return Boolean.TRUE;
                case 'f': expectWord("false"); return Boolean.FALSE;
                case 'n': expectWord("null"); return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return readNumber();
                    throw error("unexpected character '" + printable(c) + "'");
            }
        }

        private void expectWord(String word) {
            if (!s.startsWith(word, pos)) throw error("invalid literal");
            pos += word.length();
        }

        private Map<String, Object> readObject(int depth) {
            pos++; // {
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (pos < s.length() && s.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (pos >= s.length() || s.charAt(pos) != '"') throw error("expected a string key");
                String key = readString();
                if (map.containsKey(key)) throw error("duplicate key \"" + key + "\"");
                skipWhitespace();
                if (pos >= s.length() || s.charAt(pos) != ':') throw error("expected ':'");
                pos++;
                skipWhitespace();
                map.put(key, readValue(depth + 1));
                skipWhitespace();
                if (pos >= s.length()) throw error("unexpected end of JSON");
                char c = s.charAt(pos++);
                if (c == '}') return map;
                if (c != ',') throw error("expected ',' or '}'");
            }
        }

        private List<Object> readArray(int depth) {
            pos++; // [
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (pos < s.length() && s.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipWhitespace();
                list.add(readValue(depth + 1));
                skipWhitespace();
                if (pos >= s.length()) throw error("unexpected end of JSON");
                char c = s.charAt(pos++);
                if (c == ']') return list;
                if (c != ',') throw error("expected ',' or ']'");
            }
        }

        private String readString() {
            pos++; // opening quote
            StringBuilder sb = null;
            int start = pos;
            while (true) {
                if (pos >= s.length()) throw error("unterminated string");
                char c = s.charAt(pos);
                if (c == '"') {
                    String out = sb == null ? s.substring(start, pos) : sb.append(s, start, pos).toString();
                    pos++;
                    return out;
                }
                if (c < 0x20) throw error("control character in string");
                if (c == '\\') {
                    if (sb == null) sb = new StringBuilder();
                    sb.append(s, start, pos);
                    pos++;
                    if (pos >= s.length()) throw error("unterminated escape");
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > s.length()) throw error("bad unicode escape");
                            int code = 0;
                            for (int k = 0; k < 4; k++) {
                                int d = Character.digit(s.charAt(pos + k), 16);
                                if (d < 0) throw error("bad unicode escape");
                                code = code * 16 + d;
                            }
                            pos += 4;
                            sb.append((char) code);
                            break;
                        default:
                            throw error("bad escape '\\" + printable(e) + "'");
                    }
                    start = pos;
                } else {
                    pos++;
                }
            }
        }

        private Object readNumber() {
            int start = pos;
            if (s.charAt(pos) == '-') pos++;
            if (pos >= s.length()) throw error("bad number");
            char c = s.charAt(pos);
            if (c == '0') {
                pos++;
            } else if (c >= '1' && c <= '9') {
                while (pos < s.length() && isDigit(s.charAt(pos))) pos++;
            } else {
                throw error("bad number");
            }
            boolean integral = true;
            if (pos < s.length() && s.charAt(pos) == '.') {
                integral = false;
                pos++;
                if (pos >= s.length() || !isDigit(s.charAt(pos))) throw error("bad number");
                while (pos < s.length() && isDigit(s.charAt(pos))) pos++;
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                integral = false;
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                if (pos >= s.length() || !isDigit(s.charAt(pos))) throw error("bad number");
                while (pos < s.length() && isDigit(s.charAt(pos))) pos++;
            }
            if (pos < s.length() && isDigit(s.charAt(pos))) throw error("leading zeros are not allowed");
            String text = s.substring(start, pos);
            if (integral) {
                if (text.length() <= 18) return Long.parseLong(text);
                BigInteger big = new BigInteger(text);
                return big.bitLength() < 64 ? (Object) big.longValue() : big;
            }
            double d = Double.parseDouble(text);
            if (Double.isInfinite(d)) throw error("number out of range");
            return d;
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }

        private static String printable(char c) {
            return c < 0x20 || c > 0x7e ? String.format("\\u%04x", (int) c) : String.valueOf(c);
        }
    }

    // ---- small typed accessors for wire data ----

    /** A string field, or null when missing or not a string. */
    public static String string(Map<String, ?> map, String key) {
        Object v = map == null ? null : map.get(key);
        return v instanceof String ? (String) v : null;
    }

    /** A whole-number field as Long, or null when missing or not a whole number. */
    public static Long number(Map<String, ?> map, String key) {
        Object v = map == null ? null : map.get(key);
        return asLong(v);
    }

    /** A whole number as Long (Long, Integer, BigInteger in range, or a Double without fraction), else null. */
    public static Long asLong(Object v) {
        if (v instanceof Long || v instanceof Integer || v instanceof Short || v instanceof Byte) return ((Number) v).longValue();
        if (v instanceof BigInteger) {
            BigInteger b = (BigInteger) v;
            return b.bitLength() < 64 ? b.longValue() : null;
        }
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d) || d != Math.floor(d) || Math.abs(d) > 9.007199254740991E15) return null;
            return (long) d;
        }
        return null;
    }

    /** A JSON object field, or null. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Map<String, ?> map, String key) {
        Object v = map == null ? null : map.get(key);
        return v instanceof Map ? (Map<String, Object>) v : null;
    }

    /** Deep, unmodifiable copy of parsed wire data. */
    @SuppressWarnings("unchecked")
    public static Object freeze(Object value) {
        if (value instanceof Map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) value).entrySet()) copy.put(e.getKey(), freeze(e.getValue()));
            return Collections.unmodifiableMap(copy);
        }
        if (value instanceof List) {
            List<Object> copy = new ArrayList<>();
            for (Object item : (List<Object>) value) copy.add(freeze(item));
            return Collections.unmodifiableList(copy);
        }
        return value;
    }

    /** Deep, unmodifiable copy of a parsed JSON object. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> freezeObject(Map<String, ?> value) {
        return value == null ? Collections.<String, Object>emptyMap() : (Map<String, Object>) freeze(value);
    }
}
