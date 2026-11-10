package dev.yuizho.login_demo.scratch.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dev.yuizho.login_demo.WebAuthnProperties;
import dev.yuizho.login_demo.scratch.webauthn.ScratchCredentialRepository.ScratchCredential;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static dev.yuizho.login_demo.scratch.webauthn.ScratchVerifier.check;

/** パスキーの登録 (navigator.credentials.create() の前後) */
@Service
class ScratchRegistrationService {
    private static final Logger log = LoggerFactory.getLogger(ScratchRegistrationService.class);
    private static final String CHALLENGE_ATTRIBUTE = "scratch.webauthn.registration.challenge";
    private static final long ES256 = -7;

    private final SecureRandom random = new SecureRandom();
    private final ScratchCredentialRepository repository;
    private final ScratchVerifier verifier;
    private final WebAuthnProperties properties;

    ScratchRegistrationService(ScratchCredentialRepository repository, ScratchVerifier verifier,
                               WebAuthnProperties properties) {
        this.repository = repository;
        this.verifier = verifier;
        this.properties = properties;
    }

    // credential.toJSON() のうち、使う項目だけ受け取る
    @JsonIgnoreProperties(ignoreUnknown = true)
    record RegistrationRequest(String label, Credential credential) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Credential(String id, Response response) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Response(String clientDataJSON, String attestationObject) {
    }

    /** PublicKeyCredential.parseCreationOptionsFromJSON() に渡せる形の options を作る */
    Map<String, Object> options(String username, HttpSession session) {
        String userHandle = repository.findUserHandle(username).orElseGet(() -> {
            // 初回だけ WebAuthn 用のユーザーIDを作る (個人を特定できない、ランダムな値にする)
            String created = Base64Url.encode(randomBytes(32));
            repository.saveUserHandle(username, created);
            log.info("[scratch] userHandle を新規作成 username={} userHandle={}", username, created);
            return created;
        });

        String challenge = Base64Url.encode(randomBytes(32));
        session.setAttribute(CHALLENGE_ATTRIBUTE, challenge);
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

    /** create() の結果を検証して保存する */
    void register(String username, RegistrationRequest request, HttpSession session) {
        check(request.label() != null && !request.label().isBlank(), "ラベルが空");
        String challenge = (String) session.getAttribute(CHALLENGE_ATTRIBUTE);
        session.removeAttribute(CHALLENGE_ATTRIBUTE); // challenge は使い捨て

        // 1. clientDataJSON: 登録 (webauthn.create) で、こちらが出した challenge に対して、許可した origin で作られたか
        verifier.verifyClientData(Base64Url.decode(request.credential().response().clientDataJSON()),
                "webauthn.create", challenge);

        // 2. attestationObject: CBOR の {fmt, attStmt, authData}
        @SuppressWarnings("unchecked")
        Map<Object, Object> attestationObject =
                (Map<Object, Object>) Cbor.decode(Base64Url.decode(request.credential().response().attestationObject()));
        log.info("[scratch] attestationObject fmt={} attStmt={}", attestationObject.get("fmt"), attestationObject.get("attStmt"));

        // 3. authData: rpIdHash とフラグを確認し、credentialId と公開鍵を取り出す
        AuthenticatorData authData = AuthenticatorData.parse((byte[]) attestationObject.get("authData"));
        verifier.verifyAuthenticatorData(authData);
        check(authData.has(AuthenticatorData.AT), "AT (資格情報データ) フラグがない");
        String credentialId = Base64Url.encode(authData.credentialId());
        check(credentialId.equals(request.credential().id()), "credentialId が credential.id と一致しない");

        // 4. 公開鍵 (COSE): ES256 だけ受け付ける
        Map<?, ?> coseKey = (Map<?, ?>) Cbor.decode(authData.credentialPublicKey());
        log.info("[scratch] 公開鍵 (COSE) kty={} alg={} crv={}", coseKey.get(1L), coseKey.get(3L), coseKey.get(-1L));
        check(Long.valueOf(ES256).equals(coseKey.get(3L)), "ES256 (alg=-7) 以外の公開鍵: " + coseKey.get(3L));

        // 5. 保存 (ユーザーとの紐づけは、セッションのユーザー名 → userHandle)
        String userHandle = repository.findUserHandle(username).orElseThrow();
        Instant now = Instant.now();
        repository.saveCredential(new ScratchCredential(credentialId, userHandle, authData.credentialPublicKey(),
                authData.signCount(), request.label(), now, now));
        log.info("[scratch] パスキーを保存 username={} credentialId={} label={}", username, credentialId, request.label());
    }

    List<ScratchCredential> credentials(String username) {
        return repository.findUserHandle(username)
                .map(repository::findCredentialsByUserHandle)
                .orElse(List.of());
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
