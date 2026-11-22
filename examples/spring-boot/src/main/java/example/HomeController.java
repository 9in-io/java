package example;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class HomeController {
    /** The signed-in user (from the verified ID token) and a sign-out button. */
    @GetMapping(value = "/", produces = "text/html")
    String home(@AuthenticationPrincipal OidcUser user, CsrfToken csrf) {
        return "<h1>Signed in</h1><p>User <code>" + HtmlUtils.htmlEscape(user.getSubject()) + "</code>, email <code>"
            + HtmlUtils.htmlEscape(String.valueOf(user.getEmail())) + "</code></p>"
            + "<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"" + csrf.getParameterName()
            + "\" value=\"" + csrf.getToken() + "\"/><button>Sign out</button></form>";
    }

    /** Any valid access token for NINE_API_AUDIENCE. */
    @GetMapping("/api/me")
    Map<String, Object> me(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", principal.getName());
        out.put("client_id", principal.getAttribute("client_id"));
        out.put("scope", principal.getAttribute("scope"));
        return out;
    }

    /** Needs the read:things scope (SCOPE_read:things). */
    @GetMapping("/api/orders")
    Map<String, Object> orders(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("orders", new String[0]);
        out.put("for", principal.getName());
        return out;
    }
}
