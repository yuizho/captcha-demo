package dev.yuizho.login_demo.scratch.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dev.yuizho.login_demo.WebAuthnProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/** 登録とログインで共通の検証 (clientDataJSON と authenticatorData) */
@Component
class ScratchVerifier {
    private static final Logger log = LoggerFactory.getLogger(ScratchVerifier.class);

    private final JsonMapper jsonMapper;
    private final WebAuthnProperties properties;

    ScratchVerifier(JsonMapper jsonMapper, WebAuthnProperties properties) {
        this.jsonMapper = jsonMapper;
        this.properties = properties;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record ClientData(String type, String challenge, String origin) {
    }

    /** ブラウザが作った clientDataJSON を検証する (どのページで、どの challenge に対して作られたか) */
    void verifyClientData(byte[] clientDataJSON, String expectedType, String expectedChallenge) {
        log.info("[scratch] clientDataJSON={}", new String(clientDataJSON, StandardCharsets.UTF_8));
        ClientData clientData = jsonMapper.readValue(clientDataJSON, ClientData.class);
        check(expectedType.equals(clientData.type()), "type が " + expectedType + " ではない: " + clientData.type());
        check(Objects.equals(expectedChallenge, clientData.challenge()), "challenge がセッションの値と一致しない");
        check(properties.allowedOrigins().contains(clientData.origin()), "許可されていない origin: " + clientData.origin());
        log.info("[scratch] clientDataJSON OK (type, challenge, origin)");
    }

    /** 認証器が作った authenticatorData を検証する (どの RP 向けか、ユーザー確認したか) */
    void verifyAuthenticatorData(AuthenticatorData authData) {
        log.info("[scratch] authData flags={} signCount={}",
                String.format("%8s", Integer.toBinaryString(authData.flags())).replace(' ', '0'), authData.signCount());
        check(Arrays.equals(sha256(properties.rpId().getBytes(StandardCharsets.UTF_8)), authData.rpIdHash()),
                "rpIdHash が SHA-256(\"" + properties.rpId() + "\") と一致しない");
        check(authData.has(AuthenticatorData.UP), "UP (ユーザーの存在確認) フラグがない");
        check(authData.has(AuthenticatorData.UV), "UV (ユーザー確認) フラグがない");
        log.info("[scratch] authData OK (rpIdHash, UP, UV)");
    }

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 勉強用なので、検証に失敗したら IllegalArgumentException を投げるだけ */
    static void check(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
