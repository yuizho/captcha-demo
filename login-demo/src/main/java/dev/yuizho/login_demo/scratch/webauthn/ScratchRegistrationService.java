package dev.yuizho.login_demo.scratch.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dev.yuizho.login_demo.scratch.Base64Url;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository.ScratchCredential;
import dev.yuizho.login_demo.scratch.ScratchOptionsFactory;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

import static dev.yuizho.login_demo.scratch.webauthn.ScratchVerifier.check;

/** パスキーの登録 (navigator.credentials.create() の前後) */
@Service
class ScratchRegistrationService {
    private static final Logger log = LoggerFactory.getLogger(ScratchRegistrationService.class);

    private final ScratchCredentialRepository repository;
    private final ScratchOptionsFactory optionsFactory;
    private final ScratchVerifier verifier;

    ScratchRegistrationService(ScratchCredentialRepository repository, ScratchOptionsFactory optionsFactory,
                               ScratchVerifier verifier) {
        this.repository = repository;
        this.optionsFactory = optionsFactory;
        this.verifier = verifier;
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

    Map<String, Object> options(String username, HttpSession session) {
        return optionsFactory.creationOptions(username, session);
    }

    /** create() の結果を検証して保存する */
    void register(String username, RegistrationRequest request, HttpSession session) {
        check(request.label() != null && !request.label().isBlank(), "ラベルが空");
        String challenge = optionsFactory.consumeRegistrationChallenge(session);

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
        check(Long.valueOf(ScratchOptionsFactory.ES256).equals(coseKey.get(3L)), "ES256 (alg=-7) 以外の公開鍵: " + coseKey.get(3L));

        // 5. 保存 (ユーザーとの紐づけは、セッションのユーザー名 → userHandle)
        String userHandle = repository.findUserHandle(username).orElseThrow();
        Instant now = Instant.now();
        repository.saveCredential(new ScratchCredential(credentialId, userHandle, authData.credentialPublicKey(),
                authData.signCount(), request.label(), now, now));
        log.info("[scratch] パスキーを保存 username={} credentialId={} label={}", username, credentialId, request.label());
    }
}
