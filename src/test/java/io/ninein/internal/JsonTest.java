package io.ninein.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ninein.NineException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JsonTest {
    @Test
    void parsesEveryKindOfValue() {
        Map<String, Object> m = Json.parseObject(" {\"s\":\"a\\\"b\\\\c\\/d\\n\\u00e9\\ud83d\\ude00\",\"i\":-12,\"big\":12345678901234567890123,"
                + "\"l\":9007199254740993,\"d\":1.5e2,\"t\":true,\"f\":false,\"n\":null,\"a\":[1,[2],{}],\"o\":{\"x\":{}}} ");
        assertEquals("a\"b\\c/d\né\uD83D\uDE00", m.get("s"));
        assertEquals(-12L, m.get("i"));
        assertEquals(new BigInteger("12345678901234567890123"), m.get("big"));
        assertEquals(9007199254740993L, m.get("l"));
        assertEquals(150.0, m.get("d"));
        assertEquals(Boolean.TRUE, m.get("t"));
        assertEquals(Boolean.FALSE, m.get("f"));
        assertTrue(m.containsKey("n"));
        assertNull(m.get("n"));
        assertEquals(Arrays.asList(1L, Arrays.asList(2L), new LinkedHashMap<>()), m.get("a"));
        assertEquals(Arrays.asList("s", "i", "big", "l", "d", "t", "f", "n", "a", "o"), Arrays.asList(m.keySet().toArray()));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "", " ", "{", "}", "{\"a\":1,}", "[1,]", "{\"a\" 1}", "{a:1}", "{'a':1}", "01", "-", "1.", ".5", "1e", "+1",
        "NaN", "Infinity", "tru", "nul", "\"abc", "\"\\x\"", "\"\\u12\"", "\"tab\there\"", "{\"a\":1}x", "[1] [2]",
        "{\"a\":1,\"a\":2}", "// c\n{}", "[1e999]", "\"\\uZZZZ\""})
    void rejectsInvalidJson(String text) {
        NineException e = assertThrows(NineException.class, () -> Json.parse(text));
        assertEquals("invalid_json", e.error());
    }

    @Test
    void rejectsDeepNesting() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 200; i++) sb.append('[');
        for (int i = 0; i < 200; i++) sb.append(']');
        assertThrows(NineException.class, () -> Json.parse(sb.toString()));
        StringBuilder ok = new StringBuilder();
        for (int i = 0; i < 100; i++) ok.append('[');
        for (int i = 0; i < 100; i++) ok.append(']');
        Json.parse(ok.toString());
    }

    @Test
    void parseObjectNeedsAnObject() {
        assertThrows(NineException.class, () -> Json.parseObject("[1]"));
        assertThrows(NineException.class, () -> Json.parseObject("\"s\""));
        assertThrows(NineException.class, () -> Json.parseObject(null));
    }

    @Test
    void writesAndRoundTrips() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("s", "quote\" back\\ nl\n ctl\u0001 é 😀 </script> \u2028");
        m.put("i", 42);
        m.put("l", 1794203600L);
        m.put("d", 2.5);
        m.put("whole", 3.0);
        m.put("b", true);
        m.put("n", null);
        m.put("list", Arrays.asList("a", 1, null));
        m.put("arr", new Object[] {"x"});
        m.put("o", new LinkedHashMap<>());
        String text = Json.write(m);
        assertEquals("{\"s\":\"quote\\\" back\\\\ nl\\n ctl\\u0001 é 😀 </script> \\u2028\",\"i\":42,\"l\":1794203600,\"d\":2.5,\"whole\":3,"
                + "\"b\":true,\"n\":null,\"list\":[\"a\",1,null],\"arr\":[\"x\"],\"o\":{}}", text);
        Map<String, Object> back = Json.parseObject(text);
        assertEquals(m.get("s"), back.get("s"));
        assertEquals(1794203600L, back.get("l"));
    }

    @Test
    void writerRefusesWhatJsonCannotHold() {
        assertThrows(IllegalArgumentException.class, () -> Json.write(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> Json.write(new Object()));
        Map<Object, Object> bad = new LinkedHashMap<>();
        bad.put(1, "x");
        assertThrows(IllegalArgumentException.class, () -> Json.write(bad));
    }

    @Test
    void loneSurrogatesAreEscaped() {
        assertEquals("\"\\ud800x\"", Json.write("\uD800x"));
        assertEquals("\uD800", Json.parse("\"\\ud800\""));
    }

    @Test
    void accessorsAndFreeze() {
        Map<String, Object> m = Json.parseObject("{\"s\":\"v\",\"n\":5,\"d\":5.0,\"f\":5.5,\"o\":{\"k\":[1]}}");
        assertEquals("v", Json.string(m, "s"));
        assertNull(Json.string(m, "n"));
        assertEquals(5L, Json.number(m, "n"));
        assertEquals(5L, Json.number(m, "d"));
        assertNull(Json.number(m, "f"));
        Map<String, Object> frozen = Json.freezeObject(m);
        assertThrows(UnsupportedOperationException.class, () -> frozen.put("x", 1));
        @SuppressWarnings("unchecked")
        List<Object> inner = (List<Object>) Json.object(frozen, "o").get("k");
        assertThrows(UnsupportedOperationException.class, () -> inner.add(2));
    }
}
