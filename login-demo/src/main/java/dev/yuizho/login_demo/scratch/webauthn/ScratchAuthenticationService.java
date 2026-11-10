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

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.time.Instant;
import java.util.Map;

import static dev.yuizho.login_demo.scratch.webauthn.ScratchVerifier.check;

/** パスキーでのログイン (navigator.credentials.get() の前後) */
@Service
class ScratchAuthenticationService {
    private static final Logger log = LoggerFactory.getLogger(ScratchAuthenticationService.class);

    private final ScratchCredentialRepository repository;
    private final ScratchOptionsFactory optionsFactory;
    private final ScratchVerifier verifier;

    ScratchAuthenticationService(ScratchCredentialRepository repository, ScratchOptionsFactory optionsFactory,
                                 ScratchVerifier verifier) {
        this.repository = repository;
        this.optionsFactory = optionsFactory;
        this.verifier = verifier;
    }

    // credential.toJSON() のうち、使う項目だけ受け取る
    @JsonIgnoreProperties(ignoreUnknown = true)
    record AuthenticationRequest(String id, Response response) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Response(String clientDataJSON, String authenticatorData, String signature, String userHandle) {
    }

    Map<String, Object> options(HttpSession session) {
        return optionsFactory.requestOptions(session);
    }

    /** get() の結果 (署名) を検証して、ユーザー名を返す */
    String authenticate(AuthenticationRequest request, HttpSession session) {
        String challenge = optionsFactory.consumeAuthenticationChallenge(session);

        // 1. credential ID から、登録時に保存した公開鍵を探す
        ScratchCredential credential = repository.findCredential(request.id())
                .orElseThrow(() -> new IllegalArgumentException("未登録の credentialId: " + request.id()));
        log.info("[scratch] パスキーを取得 credentialId={} label={}", credential.credentialId(), credential.label());
        check(credential.userHandle().equals(request.response().userHandle()), "userHandle が保存済みの値と一致しない");

        // 2. clientDataJSON: ログイン (webauthn.get) で、こちらが出した challenge に対して作られたか
        byte[] clientDataJSON = Base64Url.decode(request.response().clientDataJSON());
        verifier.verifyClientData(clientDataJSON, "webauthn.get", challenge);

        // 3. authData: rpIdHash とフラグ
        byte[] authDataBytes = Base64Url.decode(request.response().authenticatorData());
        AuthenticatorData authData = AuthenticatorData.parse(authDataBytes);
        verifier.verifyAuthenticatorData(authData);

        // 4. 署名: 認証器は authData || SHA-256(clientDataJSON) に秘密鍵で署名している
        //    clientDataJSON に challenge が入っているので、この署名は今回のログインでしか使えない
        check(verifySignature(credential.credentialPublicKey(), authDataBytes, clientDataJSON,
                Base64Url.decode(request.response().signature())), "署名の検証に失敗");
        log.info("[scratch] 署名 OK");

        // 5. 署名カウンタ: 増えていなければ、認証器が複製された可能性がある
        //    (1Password のような同期パスキーは常に 0 を返すので、両方 0 のときは見ない)
        log.info("[scratch] signCount 保存済み={} 今回={}", credential.signCount(), authData.signCount());
        if (credential.signCount() != 0 || authData.signCount() != 0) {
            check(authData.signCount() > credential.signCount(), "signCount が増えていない");
        }
        repository.updateSignCount(credential.credentialId(), authData.signCount(), Instant.now());

        // 6. userHandle → ユーザー名
        String username = repository.findUsername(credential.userHandle()).orElseThrow();
        log.info("[scratch] 認証成功 username={}", username);
        return username;
    }

    private static boolean verifySignature(byte[] cose, byte[] authData, byte[] clientDataJSON, byte[] signature) {
        try {
            // SHA256withECDSA が内部で SHA-256 をかけるので、渡すのは authData || SHA-256(clientDataJSON)
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(CoseConverter.toPublicKey(cose));
            verifier.update(authData);
            verifier.update(ScratchVerifier.sha256(clientDataJSON));
            return verifier.verify(signature); // WebAuthn の ES256 の署名は ASN.1 DER 形式で、Java と同じ
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("署名を検証できない", e);
        }
    }
}
