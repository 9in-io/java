package io.ninein.http;

import java.io.IOException;

/**
 * How the SDK talks HTTP. The default is {@link UrlConnectionTransport} (works on the JVM and on
 * Android); plug in your own to use another client, add a proxy, or fake 9in in tests.
 *
 * <p>Implementations must not follow redirects (the SDK never needs them, and following one to
 * another origin could leak credentials), should apply timeouts, and must return non-2xx
 * responses as {@link HttpResponse}s rather than throwing. Throw {@link IOException} only when
 * there is no response at all.
 */
@FunctionalInterface
public interface HttpTransport {
    HttpResponse send(HttpRequest request) throws IOException;
}
