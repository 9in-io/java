package io.ninein.servlet;

import io.ninein.adapter.AdapterHandler;
import io.ninein.adapter.AdapterResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serves 9in's adapter protocol from a Jakarta servlet container. Map it to your adapter base
 * URL with a wildcard ({@code /nine/*} serves {@code /nine/authenticate}, {@code /nine/user} and
 * {@code /nine/event}):
 *
 * <pre>{@code
 * servletContext.addServlet("nine-adapter", new AdapterServlet(AdapterHandler.fromEnv(new MyUserAdapter())))
 *     .addMapping("/nine/*");
 * }</pre>
 *
 * <p>The signature covers the path exactly as 9in called it: {@code getRequestURI()}. Behind a
 * proxy that rewrites paths, override {@link #signedPath(HttpServletRequest)}.
 */
public class AdapterServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final int MAX_BODY = 1024 * 1024;

    private final transient AdapterHandler handler;

    public AdapterServlet(AdapterHandler handler) {
        if (handler == null) throw new IllegalArgumentException("an adapter handler is required");
        this.handler = handler;
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
        byte[] body = Bodies.read(request, MAX_BODY);
        if (body == null) {
            response.sendError(413);
            return;
        }
        Map<String, String> headers = new LinkedHashMap<>();
        for (Enumeration<String> names = request.getHeaderNames(); names != null && names.hasMoreElements(); ) {
            String name = names.nextElement();
            headers.put(name, request.getHeader(name));
        }
        AdapterResponse result = handler.handle(request.getMethod(), signedPath(request), headers, body);
        response.setStatus(result.status());
        for (Map.Entry<String, String> h : result.headers().entrySet()) response.setHeader(h.getKey(), h.getValue());
        byte[] out = result.body();
        if (out.length > 0) {
            response.setContentLength(out.length);
            response.getOutputStream().write(out);
        }
    }

    /** The path 9in signed: by default the raw request URI (context path included, no query string). */
    protected String signedPath(HttpServletRequest request) {
        return request.getRequestURI();
    }
}
