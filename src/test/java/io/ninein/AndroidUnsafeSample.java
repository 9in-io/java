package io.ninein;

import java.util.List;

/** Deliberately uses Java 9+ APIs that Android API 26 lacks; AndroidSafetyTest checks they are caught. */
final class AndroidUnsafeSample {
    private AndroidUnsafeSample() {}

    static boolean sample(String s) {
        List<String> list = List.of(s);
        return s.isBlank() || list.isEmpty();
    }
}
