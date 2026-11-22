package io.ninein;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.codehaus.mojo.animal_sniffer.SignatureChecker;
import org.codehaus.mojo.animal_sniffer.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The Android SDK is built on {@link AuthClient}: everything it reaches must run on Android API 26
 * and must not drag in the server-only parts (which R8 then strips from apps).
 *
 * <ul>
 *   <li>The classes reachable from the shared-core contract never reference server-only classes
 *       or packages Android lacks.
 *   <li>Every JDK class, method and field those classes use exists in Android API 26
 *       (animal-sniffer with the API 26 signature).
 * </ul>
 */
class AndroidSafetyTest {
    /** The contract the Android SDK uses (SPEC.md, "Contract for the Java SDK's shared core"). */
    static final List<String> CONTRACT = Arrays.asList(
            "io/ninein/AuthClient", "io/ninein/AuthClient$Builder", "io/ninein/LoginOptions", "io/ninein/LoginOptions$Builder",
            "io/ninein/Login", "io/ninein/PendingLogin", "io/ninein/TokenSet", "io/ninein/TokenSet$Builder", "io/ninein/DeviceAuthorization",
            "io/ninein/Discovery", "io/ninein/NineException", "io/ninein/http/HttpTransport", "io/ninein/http/HttpRequest",
            "io/ninein/http/HttpRequest$Builder", "io/ninein/http/HttpResponse", "io/ninein/http/UrlConnectionTransport");

    /** Server-only parts the core must never reference. */
    static final List<String> SERVER_ONLY = Arrays.asList(
            "io/ninein/TokenVerifier", "io/ninein/HybridTokenVerifier", "io/ninein/ManagementClient", "io/ninein/Webhooks",
            "io/ninein/WebhookEvent", "io/ninein/EventDeduplicator", "io/ninein/Signatures", "io/ninein/Cache", "io/ninein/MemoryCache",
            "io/ninein/AccessTokenClaims", "io/ninein/AccessTokenVerifier", "io/ninein/InvalidTokenException",
            "io/ninein/InsufficientScopeException", "io/ninein/SignatureException", "io/ninein/adapter/", "io/ninein/servlet/",
            "io/ninein/spring/", "io/ninein/http/JavaHttpClientTransport");

    /** Packages and classes Android doesn't have (or that the core must not use). */
    static final List<String> FORBIDDEN = Arrays.asList(
            "java/net/http/", "javax/servlet/", "jakarta/", "org/springframework/", "java/lang/Record", "java/lang/ProcessHandle",
            "java/lang/invoke/", "java/lang/reflect/", "sun/", "com/sun/", "jdk/", "java/util/concurrent/Flow", "java/lang/StackWalker",
            "java/util/HexFormat", "java/lang/Module");

    static Path mainClasses;

    @BeforeAll
    static void locate() {
        String dirs = System.getProperty("nine.mainClasses");
        for (String d : dirs.split(File.pathSeparator)) if (new File(d, "io/ninein/AuthClient.class").exists()) mainClasses = new File(d).toPath();
        assertTrue(mainClasses != null, "main classes not found in " + dirs);
    }

    @Test
    void coreReachesNoServerOnlyClassOrForbiddenPackage() throws IOException {
        Set<String> core = closure();
        assertTrue(core.contains("io/ninein/internal/Tenant"), "sanity: the closure follows internal classes");
        assertTrue(core.contains("io/ninein/internal/Jws"));
        List<String> problems = new ArrayList<>();
        for (String cls : core) {
            for (String bad : SERVER_ONLY) if (cls.equals(bad) || (bad.endsWith("/") && cls.startsWith(bad))) problems.add(cls + " (server-only)");
            for (String ref : references(cls)) {
                for (String f : FORBIDDEN) if (ref.startsWith(f)) problems.add(cls + " -> " + ref);
            }
        }
        assertEquals(new ArrayList<String>(), problems, "core classes: " + core);
    }

    @Test
    void coreUsesOnlyAndroidApi26(@TempDir Path tmp) throws IOException {
        Set<String> core = closure();
        for (String cls : core) {
            Path target = tmp.resolve(cls + ".class");
            Files.createDirectories(target.getParent());
            Files.copy(mainClasses.resolve(cls + ".class"), target, StandardCopyOption.REPLACE_EXISTING);
        }
        List<String> errors = check(tmp.toFile());
        assertEquals(new ArrayList<String>(), errors, "the core uses JDK APIs that Android API 26 lacks");
    }

    @Test
    void theCheckCatchesJava9PlusApis(@TempDir Path tmp) throws IOException {
        // Guards the test above: a class calling String.isBlank() and List.of() must fail the check.
        String cls = "io/ninein/AndroidUnsafeSample";
        Path compiled = null;
        for (String d : System.getProperty("java.class.path").split(File.pathSeparator)) {
            File f = new File(d, cls + ".class");
            if (f.exists()) compiled = f.toPath();
        }
        assertTrue(compiled != null, "sample class compiled");
        Path target = tmp.resolve(cls + ".class");
        Files.createDirectories(target.getParent());
        Files.copy(compiled, target);
        List<String> errors = check(tmp.toFile());
        assertFalse(errors.isEmpty(), "animal-sniffer must flag Java 11 APIs");
        String all = String.join("\n", errors);
        assertTrue(all.contains("isBlank"), all);
        assertTrue(all.contains("List.of") || all.contains("java.util.List"), all);
    }

    private static List<String> check(File dir) throws IOException {
        final List<String> errors = new ArrayList<>();
        Logger logger = new Logger() {
            public void info(String m) {}
            public void info(String m, Throwable t) {}
            public void debug(String m) {}
            public void debug(String m, Throwable t) {}
            public void warn(String m) {}
            public void warn(String m, Throwable t) {}
            public void error(String m) {
                errors.add(m);
            }
            public void error(String m, Throwable t) {
                errors.add(m);
            }
        };
        Set<String> ignored = new HashSet<>(Arrays.asList("io.ninein.*", "io.ninein.http.*", "io.ninein.internal.*"));
        try (InputStream signature = new FileInputStream(System.getProperty("nine.androidSignature"))) {
            SignatureChecker checker = new SignatureChecker(signature, ignored, logger);
            checker.setSourcePath(new ArrayList<File>());
            checker.setAnnotationTypes(new ArrayList<String>());
            checker.process(dir);
            if (checker.isSignatureBroken() && errors.isEmpty()) errors.add("signature broken");
        }
        return errors;
    }

    /** Every io/ninein class reachable from the contract types. */
    static Set<String> closure() throws IOException {
        Set<String> seen = new TreeSet<>();
        Deque<String> todo = new ArrayDeque<>(CONTRACT);
        while (!todo.isEmpty()) {
            String cls = todo.pop();
            if (!seen.add(cls)) continue;
            for (String ref : references(cls)) {
                if (ref.startsWith("io/ninein/") && !seen.contains(ref) && Files.exists(mainClasses.resolve(ref + ".class"))) todo.push(ref);
            }
        }
        return seen;
    }

    private static final Pattern DESCRIPTOR_CLASS = Pattern.compile("L([A-Za-z0-9_$/]+);");

    /** Class names a class file refers to: CONSTANT_Class entries and class names inside descriptors. */
    static Set<String> references(String cls) throws IOException {
        Set<String> out = new TreeSet<>();
        List<String> utf8 = new ArrayList<>();
        List<Integer> classIndexes = new ArrayList<>();
        try (DataInputStream in = new DataInputStream(Files.newInputStream(mainClasses.resolve(cls + ".class")))) {
            if (in.readInt() != 0xCAFEBABE) throw new IOException("not a class file: " + cls);
            in.readUnsignedShort();
            in.readUnsignedShort();
            int count = in.readUnsignedShort();
            String[] strings = new String[count];
            for (int i = 1; i < count; i++) {
                int tag = in.readUnsignedByte();
                switch (tag) {
                    case 1: strings[i] = in.readUTF(); utf8.add(strings[i]); break;
                    case 3: case 4: in.readInt(); break;
                    case 5: case 6: in.readLong(); i++; break;
                    case 7: classIndexes.add(in.readUnsignedShort()); break;
                    case 8: case 16: case 19: case 20: in.readUnsignedShort(); break;
                    case 9: case 10: case 11: case 12: case 17: case 18: in.readInt(); break;
                    case 15: in.readUnsignedByte(); in.readUnsignedShort(); break;
                    default: throw new IOException("unknown constant tag " + tag + " in " + cls);
                }
            }
            for (int index : classIndexes) {
                String name = strings[index];
                if (name != null && !name.startsWith("[")) out.add(name);
                else if (name != null) addDescriptorClasses(name, out);
            }
        }
        for (String s : utf8) addDescriptorClasses(s, out);
        return out;
    }

    private static void addDescriptorClasses(String s, Set<String> out) {
        if (!(s.startsWith("(") || s.startsWith("L") || s.startsWith("["))) return;
        Matcher m = DESCRIPTOR_CLASS.matcher(s);
        while (m.find()) out.add(m.group(1));
    }
}
