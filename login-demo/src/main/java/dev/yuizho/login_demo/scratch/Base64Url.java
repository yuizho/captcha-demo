package dev.yuizho.login_demo.scratch;

import java.util.Base64;

/** WebAuthn の JSON ではバイト列をパディングなしの base64url で表す */
public final class Base64Url {
    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
