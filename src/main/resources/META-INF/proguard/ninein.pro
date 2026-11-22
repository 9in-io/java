# 9in Java SDK: rules for R8 / ProGuard (Android). The sign-in core (io.ninein.AuthClient and
# what it uses) has no optional dependencies. The server-side helpers in the same jar refer to
# APIs Android doesn't have (Jakarta Servlet, Spring Security, java.net.http); apps never load
# them, so R8 removes them, but it must not fail on the missing classes.
-dontwarn jakarta.servlet.**
-dontwarn org.springframework.**
-dontwarn java.net.http.**
