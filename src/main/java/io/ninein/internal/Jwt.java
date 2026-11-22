package io.ninein.internal;

import io.ninein.NineException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.Map;

/** A decoded (not yet verified) compact JWS. Internal to the SDK. */
public final class Jwt {
    private static final int MAX_LENGTH = 64 * 1024;

    public final Map<String, Object> header;
    public final Map<String, Object> payload;
    public final String signingInput;
    public final byte[] signature;

    private Jwt(Map<String, Object> header, Map<String, Object> payload, String signingInput, byte[] signature) {
        this.header = header;
        this.payload = payload;
        this.signingInput = signingInput;
        this.signature = signature;
    }

    /** Decodes a compact JWS; throws {@code invalid_token} (401) when it isn't one. */
    public static Jwt decode(String token, String what) {
        if (token == null || token.isEmpty()) throw new NineException("invalid_token", "missing " + what, 401);
        if (token.length() > MAX_LENGTH) throw new NineException("invalid_token", "malformed " + what, 401);
        int first = token.indexOf('.');
        int second = first < 0 ? -1 : token.indexOf('.', first + 1);
        if (first <= 0 || second < 0 || token.indexOf('.', second + 1) >= 0 || second == first + 1) {
            throw new NineException("invalid_token", "malformed " + what, 401);
        }
        try {
            Map<String, Object> header = Json.parseObject(utf8Strict(Codec.base64UrlDecode(token.substring(0, first))));
            Map<String, Object> payload = Json.parseObject(utf8Strict(Codec.base64UrlDecode(token.substring(first + 1, second))));
            byte[] signature = Codec.base64UrlDecode(token.substring(second + 1));
            return new Jwt(header, payload, token.substring(0, second), signature);
        } catch (IllegalArgumentException | NineException | CharacterCodingException e) {
            throw new NineException("invalid_token", "malformed " + what, 401);
        }
    }

    public String alg() {
        Object alg = header.get("alg");
        return alg instanceof String ? (String) alg : "";
    }

    public String kid() {
        Object kid = header.get("kid");
        return kid instanceof String ? (String) kid : null;
    }

    public String typ() {
        Object typ = header.get("typ");
        return typ instanceof String ? (String) typ : "";
    }

    private static String utf8Strict(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
    }
}
