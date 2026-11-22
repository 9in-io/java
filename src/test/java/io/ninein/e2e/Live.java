package io.ninein.e2e;

import io.ninein.internal.Json;
import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Settings and helpers for the live end-to-end tests against 9in's production test tenants.
 * Settings come from the file named by {@code NINE_E2E_ENV} (default {@code ../v2/e2e/.env.e2e});
 * {@code E2E_*} environment variables override. Values are never printed.
 */
final class Live {
    private static final Map<String, String> VALUES = load();
    /** A unique marker per run, for emails. */
    static final String RUN = Long.toString(System.currentTimeMillis(), 36) + Integer.toString((int) (Math.random() * 46656), 36);

    private Live() {}

    private static Map<String, String> load() {
        Map<String, String> values = new HashMap<>();
        String file = System.getenv("NINE_E2E_ENV");
        Path path = file != null ? Paths.get(file) : Paths.get("..", "v2", "e2e", ".env.e2e");
        if (Files.exists(path)) {
            try {
                for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                    Matcher m = Pattern.compile("^([A-Z0-9_]+)=(.*)$").matcher(line.trim());
                    if (m.matches()) values.put(m.group(1), m.group(2));
                }
            } catch (IOException e) {
                throw new IllegalStateException("cannot read the E2E settings file");
            }
        }
        for (Map.Entry<String, String> e : System.getenv().entrySet()) {
            if (e.getKey().startsWith("E2E_")) values.put(e.getKey().substring(4), e.getValue());
        }
        return values;
    }

    static String env(String name) {
        String value = VALUES.get(name);
        if (value == null || value.isEmpty()) throw new IllegalStateException("E2E setting " + name + " is missing");
        return value;
    }

    static boolean has(String name) {
        String value = VALUES.get(name);
        return value != null && !value.isEmpty();
    }

    // ---- a minimal browser for the hosted pages ----

    /** Cookie jar per host, manual redirects, form posts. */
    static final class Browser {
        final HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> get(String url) throws IOException, InterruptedException {
            return client.send(HttpRequest.newBuilder(URI.create(url)).header("User-Agent", "9in-java-e2e/1.0").timeout(Duration.ofSeconds(30)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
        }

        HttpResponse<String> post(String url, Map<String, String> form) throws IOException, InterruptedException {
            URI uri = URI.create(url);
            StringBuilder body = new StringBuilder();
            for (Map.Entry<String, String> e : form.entrySet()) {
                if (body.length() > 0) body.append('&');
                body.append(URLEncoder.encode(e.getKey(), "UTF-8")).append('=').append(URLEncoder.encode(e.getValue(), "UTF-8"));
            }
            return client.send(HttpRequest.newBuilder(uri)
                    .header("User-Agent", "9in-java-e2e/1.0")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Origin", uri.getScheme() + "://" + uri.getRawAuthority())
                    .header("Referer", url)
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build(), HttpResponse.BodyHandlers.ofString());
        }

        /** Follows redirects until one points at {@code stopAt} (returned, not requested) or a page is reached. */
        Result follow(String url, String stopAt) throws IOException, InterruptedException {
            String current = url;
            for (int hops = 0; hops < 20; hops++) {
                if (stopAt != null && current.startsWith(stopAt)) return new Result(current, 302, null);
                HttpResponse<String> r = get(current);
                String location = r.headers().firstValue("location").orElse(null);
                if (r.statusCode() >= 300 && r.statusCode() < 400 && location != null) {
                    current = URI.create(current).resolve(location).toString();
                    continue;
                }
                return new Result(current, r.statusCode(), r.body());
            }
            throw new IllegalStateException("too many redirects");
        }
    }

    /** Where a browser ended: the callback URL (html null) or a page. */
    static final class Result {
        final String url;
        final int status;
        final String html;

        Result(String url, int status, String html) {
            this.url = url;
            this.status = status;
            this.html = html;
        }

        String callback() {
            return html == null ? url : null;
        }

        String text() {
            return html == null ? null : pageText(html);
        }
    }

    /** Signs in on the hosted page with identifier and password, starting from an authorization URL. */
    static Result signIn(Browser browser, String authorizeUrl, String redirectUri, String identifier, String password) throws Exception {
        Result start = browser.follow(authorizeUrl, redirectUri);
        if (start.html == null) return start;
        if (!start.html.contains("name=\"identifier\"")) return start;
        Map<String, String> form = hiddenFields(start.html);
        form.put("identifier", identifier);
        form.put("password", password);
        form.put("action", "password");
        HttpResponse<String> submitted = browser.post(formAction(start.html, start.url), form);
        String location = submitted.headers().firstValue("location").orElse(null);
        if (location == null) return new Result(start.url, submitted.statusCode(), submitted.body());
        return browser.follow(URI.create(start.url).resolve(location).toString(), redirectUri);
    }

    static Result signIn(String authorizeUrl, String redirectUri, String identifier, String password) throws Exception {
        return signIn(new Browser(), authorizeUrl, redirectUri, identifier, password);
    }

    /** Opens a login link like a browser (the GET shows a page whose form posts the token back). */
    static Result openLoginLink(Browser browser, String linkUrl, String redirectUri) throws Exception {
        HttpResponse<String> shown = browser.get(linkUrl);
        if (shown.statusCode() != 200 || !shown.body().contains("data-autosubmit")) return new Result(linkUrl, shown.statusCode(), shown.body());
        HttpResponse<String> posted = browser.post(formAction(shown.body(), linkUrl), hiddenFields(shown.body()));
        String location = posted.headers().firstValue("location").orElse(null);
        if (location == null) return new Result(linkUrl, posted.statusCode(), posted.body());
        return browser.follow(URI.create(linkUrl).resolve(location).toString(), redirectUri);
    }

    static Map<String, String> hiddenFields(String html) {
        Map<String, String> fields = new LinkedHashMap<>();
        String form = firstForm(html);
        Matcher inputs = Pattern.compile("<input\\b[^>]*>").matcher(form);
        while (inputs.find()) {
            String input = inputs.group();
            if (!input.contains("type=\"hidden\"")) continue;
            Matcher name = Pattern.compile("name=\"([^\"]+)\"").matcher(input);
            Matcher value = Pattern.compile("value=\"([^\"]*)\"").matcher(input);
            if (name.find()) fields.put(name.group(1), value.find() ? unescape(value.group(1)) : "");
        }
        return fields;
    }

    static String formAction(String html, String pageUrl) {
        Matcher action = Pattern.compile("action=\"([^\"]*)\"").matcher(firstForm(html));
        String a = action.find() ? unescape(action.group(1)) : "";
        return a.isEmpty() ? pageUrl : URI.create(pageUrl).resolve(a).toString();
    }

    private static String firstForm(String html) {
        int start = html.indexOf("<form");
        if (start < 0) return "";
        int end = html.indexOf("</form>", start);
        return end < 0 ? html.substring(start) : html.substring(start, end);
    }

    private static String unescape(String s) {
        return s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#x27;", "'").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">");
    }

    static String pageText(String html) {
        return html.replaceAll("<script[\\s\\S]*?</script>", " ").replaceAll("<style[\\s\\S]*?</style>", " ").replaceAll("<[^>]+>", " ")
                .replace("&#x27;", "'").replace("&#39;", "'").replace("&amp;", "&").replaceAll("\\s+", " ").trim();
    }

    /** The query parameters of a URL. */
    static Map<String, String> query(String url) throws Exception {
        Map<String, String> out = new LinkedHashMap<>();
        String q = URI.create(url).getRawQuery();
        if (q == null) return out;
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            out.put(URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), "UTF-8"), eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), "UTF-8"));
        }
        return out;
    }

    // ---- the receiver Worker (records of real webhook deliveries and adapter calls) ----

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> records(String kind) throws Exception {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
        HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(env("RECEIVER_URL") + "/records?kind=" + kind + "&t=" + URLEncoder.encode(env("RECEIVER_TOKEN"), "UTF-8")))
                .timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) throw new IllegalStateException("receiver answered " + r.statusCode());
        return (List<Map<String, Object>>) Json.parse(r.body());
    }

    /** Polls the receiver until a record matches (webhooks arrive asynchronously). */
    static Map<String, Object> waitFor(String kind, Predicate<Map<String, Object>> match) throws Exception {
        long deadline = System.currentTimeMillis() + 90_000;
        while (System.currentTimeMillis() < deadline) {
            for (Map<String, Object> record : records(kind)) if (match.test(record)) return record;
            Thread.sleep(2000);
        }
        throw new AssertionError("timed out waiting for a " + kind + " record");
    }
}
