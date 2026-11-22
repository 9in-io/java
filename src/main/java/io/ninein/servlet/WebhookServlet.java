package io.ninein.servlet;

import io.ninein.Cache;
import io.ninein.EventDeduplicator;
import io.ninein.HybridTokenVerifier;
import io.ninein.NineException;
import io.ninein.Signatures;
import io.ninein.WebhookEvent;
import io.ninein.Webhooks;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * Receives 9in webhooks in a Jakarta servlet container: verifies the signature, processes each
 * event once (with a {@link Cache}), drops stale answers from your {@link HybridTokenVerifier}s,
 * then calls your handler.
 *
 * <pre>{@code
 * WebhookServlet webhooks = WebhookServlet.builder(Webhooks.secretsFromEnv())
 *     .dedupe(sharedCache)          // optional: process each event once
 *     .verifier(hybridVerifier)     // optional: revocation takes effect at once
 *     .handler(event -> { if (event.eventType().equals("user.created")) ... })
 *     .build();
 * servletContext.addServlet("nine-webhook", webhooks).addMapping("/nine/webhook");
 * }</pre>
 *
 * <p>Answers: 204 when handled (or a duplicate), 409 while another delivery of the same event is
 * running, 401 for a bad signature, 400 for a body that isn't an event, 405 for non-POST, and 500
 * when your handler throws (the event is released, so 9in retries it).
 */
public class WebhookServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final int MAX_BODY = 1024 * 1024;

    private final transient List<String> secrets;
    private final transient EventDeduplicator dedupe;
    private final transient List<HybridTokenVerifier> verifiers;
    private final transient Consumer<WebhookEvent> handler;

    protected WebhookServlet(Builder b) {
        if (b.secrets.isEmpty()) throw new NineException("invalid_options", "a webhook secret is required");
        this.secrets = Collections.unmodifiableList(new ArrayList<>(b.secrets));
        this.dedupe = b.dedupe;
        this.verifiers = Collections.unmodifiableList(new ArrayList<>(b.verifiers));
        this.handler = b.handler;
    }

    public static Builder builder(List<String> secrets) {
        return new Builder(secrets);
    }

    public static Builder builder(String secret) {
        return new Builder(Collections.singletonList(secret));
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setHeader("Allow", "POST");
            response.setStatus(405);
            return;
        }
        byte[] body = Bodies.read(request, MAX_BODY);
        if (body == null) {
            response.setStatus(413);
            return;
        }
        WebhookEvent event;
        try {
            event = Webhooks.verify(secrets, "POST", body, request.getHeader(Signatures.HEADER), signedPath(request), Signatures.DEFAULT_TOLERANCE, Clock.systemUTC());
        } catch (NineException e) {
            int status = e.status() == null ? 400 : e.status();
            response.setStatus(status);
            response.setContentType("application/json");
            response.getOutputStream().write(("{\"error\":\"" + e.error() + "\"}").getBytes(StandardCharsets.UTF_8));
            return;
        }
        Runnable work = () -> {
            for (HybridTokenVerifier v : verifiers) v.handleEvent(event);
            if (handler != null) handler.accept(event);
        };
        int status;
        if (dedupe != null) {
            status = dedupe.process(event.id(), work).httpStatus();
        } else {
            work.run();
            status = 204;
        }
        response.setStatus(status);
    }

    /** The path 9in posted to (signed): by default the raw request URI without the query string. */
    protected String signedPath(HttpServletRequest request) {
        return request.getRequestURI();
    }

    /** Builds a {@link WebhookServlet}. */
    public static class Builder {
        private final List<String> secrets = new ArrayList<>();
        private EventDeduplicator dedupe;
        private final List<HybridTokenVerifier> verifiers = new ArrayList<>();
        private Consumer<WebhookEvent> handler;

        protected Builder(List<String> secrets) {
            if (secrets != null) for (String s : secrets) if (s != null && !s.isEmpty()) this.secrets.add(s);
        }

        /** Processes each event once, with this shared cache (its {@code add} must be atomic). */
        public Builder dedupe(Cache cache) {
            this.dedupe = new EventDeduplicator(cache);
            return this;
        }

        public Builder dedupe(EventDeduplicator dedupe) {
            this.dedupe = dedupe;
            return this;
        }

        /** Passes every event to this verifier's {@link HybridTokenVerifier#handleEvent}. */
        public Builder verifier(HybridTokenVerifier verifier) {
            if (verifier != null) verifiers.add(verifier);
            return this;
        }

        /** Your code; throw to have 9in retry the event. */
        public Builder handler(Consumer<WebhookEvent> handler) {
            this.handler = handler;
            return this;
        }

        public WebhookServlet build() {
            return new WebhookServlet(this);
        }
    }
}
