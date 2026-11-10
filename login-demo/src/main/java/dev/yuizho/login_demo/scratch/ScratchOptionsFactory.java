package dev.yuizho.login_demo.scratch;

import dev.yuizho.login_demo.WebAuthnProperties;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

/**
 * navigator.credentials.create() / get() に渡す options の JSON を作る (自前版と webauthn4j 版で共有)
 * <p>
 * options はプロトコル上ただの JSON なので、webauthn4j も作ってくれない。
 * challenge はセッションに保存し、検証時に一度だけ取り出す。
 */
@Component
public class ScratchOptionsFactory {
    private static final Logger log = LoggerFactory.getLogger(ScratchOptionsFactory.class);
    private static final String REGISTRATION_CHALLENGE = "scratch.registration.challenge";
    private static final String AUTHENTICATION_CHALLENGE = "scratch.authentication.challenge";
    public static final long ES256 = -7;

    private final SecureRandom random = new SecureRandom();
    private final ScratchCredentialRepository repository;
    private final WebAuthnProperties properties;

    ScratchOptionsFactory(ScratchCredentialRepository repository, WebAuthnProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    /** PublicKeyCredential.parseCreationOptionsFromJSON() に渡せる形の options を作る */
    public Map<String, Object> creationOptions(String username, HttpSession session) {
        String userHandle = repository.findUserHandle(username).orElseGet(() -> {
            // 初回だけ WebAuthn 用のユーザーIDを作る (個人を特定できない、ランダムな値にする)
            String created = Base64Url.encode(randomBytes(32));
            repository.saveUserHandle(username, created);
            log.info("[scratch] userHandle を新規作成 username={} userHandle={}", username, created);
            return created;
        });

        String challenge = Base64Url.encode(randomBytes(32));
        session.setAttribute(REGISTRATION_CHALLENGE, challenge);
        log.info("[scratch] 登録の challenge をセッションに保存 challenge={}", challenge);

        // 登録済みのパスキーは除外して、同じ認証器に二重登録させない
        List<Map<String, Object>> excludeCredentials = repository.findCredentialsByUserHandle(userHandle).stream()
                .map(c -> Map.<String, Object>of("type", "public-key", "id", c.credentialId()))
                .toList();

        return Map.of(
                "challenge", challenge,
                "rp", Map.of("name", properties.rpName(), "id", properties.rpId()),
                "user", Map.of("id", userHandle, "name", username, "displayName", username),
                "pubKeyCredParams", List.of(Map.of("type", "public-key", "alg", ES256)),
                "timeout", 300_000,
                "excludeCredentials", excludeCredentials,
                "authenticatorSelection", Map.of("residentKey", "required", "userVerification", "required"),
                "attestation", "none");
    }

    /** PublicKeyCredential.parseRequestOptionsFromJSON() に渡せる形の options を作る */
    public Map<String, Object> requestOptions(HttpSession session) {
        String challenge = Base64Url.encode(randomBytes(32));
        session.setAttribute(AUTHENTICATION_CHALLENGE, challenge);
        log.info("[scratch] ログインの challenge をセッションに保存 challenge={}", challenge);

        // allowCredentials を空にすると、認証器が持っているこのサイト向けのパスキーから選ばせる (ユーザー名の入力不要)
        return Map.of(
                "challenge", challenge,
                "rpId", properties.rpId(),
                "timeout", 300_000,
                "userVerification", "required",
                "allowCredentials", List.of());
    }

    /** 登録の challenge を取り出す (challenge は使い捨てなので、取り出したらセッションから消す) */
    public String consumeRegistrationChallenge(HttpSession session) {
        return consume(session, REGISTRATION_CHALLENGE);
    }

    /** ログインの challenge を取り出す */
    public String consumeAuthenticationChallenge(HttpSession session) {
        return consume(session, AUTHENTICATION_CHALLENGE);
    }

    private static String consume(HttpSession session, String attribute) {
        String challenge = (String) session.getAttribute(attribute);
        session.removeAttribute(attribute);
        return challenge;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
