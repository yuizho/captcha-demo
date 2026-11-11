package dev.yuizho.login_demo.scratch.yubico;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;

/** パスキーでのログイン (options の生成と検証は Yubico に任せる) */
@Service
class YubicoAuthenticationService {
    private static final Logger log = LoggerFactory.getLogger(YubicoAuthenticationService.class);
    private static final String AUTHENTICATION_REQUEST = "yubico.authentication.request";

    private final RelyingParty relyingParty;
    private final ScratchCredentialRepository repository;
    private final JsonMapper jsonMapper;

    YubicoAuthenticationService(RelyingParty relyingParty, ScratchCredentialRepository repository,
                                JsonMapper jsonMapper) {
        this.relyingParty = relyingParty;
        this.repository = repository;
        this.jsonMapper = jsonMapper;
    }

    /** PublicKeyCredential.parseRequestOptionsFromJSON() に渡せる JSON を返す */
    JsonNode options(HttpSession session) {
        // username を指定しないので allowCredentials は空になる (認証器が持っているパスキーから選ばせる)
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.REQUIRED)
                .timeout(300_000)
                .build());

        try {
            session.setAttribute(AUTHENTICATION_REQUEST, request.toJson());
            log.info("[yubico] ログインの AssertionRequest をセッションに保存 challenge={}",
                    request.getPublicKeyCredentialRequestOptions().getChallenge().getBase64Url());
            // toCredentialsGetJson() は {"publicKey": ...} で包まれていて、中身だけを返すメソッドはないので外す
            return jsonMapper.readTree(request.getPublicKeyCredentialRequestOptions().toCredentialsGetJson())
                    .get("publicKey");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** credential.toJSON() の JSON 文字列を受け取って検証し、ユーザー名を返す */
    String authenticate(String credentialJson, HttpSession session) {
        String requestJson = (String) session.getAttribute(AUTHENTICATION_REQUEST);
        session.removeAttribute(AUTHENTICATION_REQUEST);
        if (requestJson == null) {
            throw new IllegalArgumentException("セッションに AssertionRequest がない");
        }

        AssertionResult result;
        try {
            // 1. パース
            AssertionRequest request = AssertionRequest.fromJson(requestJson);
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    PublicKeyCredential.parseAssertionResponseJson(credentialJson);

            // 2. 検証 (clientDataJSON, rpIdHash, フラグ, 署名, 署名カウンタ, userHandle)
            //    公開鍵は YubicoCredentialRepository.lookup() 経由で Yubico が自分で取りにいく
            //    webauthn4j 版で自分で書いていた「パースして credentialId で DB を引く」「userHandle の照合」もここに入っている
            result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(credential)
                    .build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (AssertionFailedException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        if (!result.isSuccess()) {
            throw new IllegalArgumentException("検証に失敗");
        }
        String credentialId = result.getCredentialId().getBase64Url();
        log.info("[yubico] 検証 OK credentialId={} signCount 保存済み={} 今回={}",
                credentialId, result.getCredential().getSignatureCount(), result.getSignatureCount());

        // 3. 署名カウンタの保存は自分でやる (Yubico は検証するだけ)
        repository.updateSignCount(credentialId, result.getSignatureCount(), Instant.now());
        log.info("[yubico] 認証成功 username={}", result.getUsername());
        return result.getUsername();
    }
}
