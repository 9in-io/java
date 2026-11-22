package io.ninein.servlet;

import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Reads raw request bodies (signatures cover the exact bytes). */
final class Bodies {
    private Bodies() {}

    /** The body, or null when it is larger than {@code max} bytes. */
    static byte[] read(HttpServletRequest request, int max) throws IOException {
        if (request.getContentLengthLong() > max) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = request.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                if (out.size() > max) return null;
            }
        }
        return out.toByteArray();
    }
}
