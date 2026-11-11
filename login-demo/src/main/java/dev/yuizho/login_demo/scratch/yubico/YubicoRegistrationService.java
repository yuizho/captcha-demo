package dev.yuizho.login_demo.scratch.yubico;

import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;
import dev.yuizho.login_demo.scratch.Base64Url;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository.ScratchCredential;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Instant;

/** パスキーの登録 (options の生成と検証は Yubico に任せる) */
@Service
class YubicoRegistrationService {
    private static final Logger log = LoggerFactory.getLogger(YubicoRegistrationService.class);
    private static final String REGISTRATION_REQUEST = "yubico.registration.request";

    private final SecureRandom random = new SecureRandom();
    private final RelyingParty relyingParty;
    private final ScratchCredentialRepository repository;
    private final JsonMapper jsonMapper;

    YubicoRegistrationService(RelyingParty relyingParty, ScratchCredentialRepository repository, JsonMapper jsonMapper) {
        this.relyingParty = relyingParty;
        this.repository = repository;
        this.jsonMapper = jsonMapper;
    }

    /** credential は credential.toJSON() の結果をそのまま Yubico に渡すので、JsonNode のまま受け取る */
    record RegistrationRequest(String label, JsonNode credential) {
    }

    /** PublicKeyCredential.parseCreationOptionsFromJSON() に渡せる JSON 文字列を返す */
    String options(String username, HttpSession session) {
        ByteArray userHandle = new ByteArray(Base64Url.decode(findOrCreateUserHandle(username)));

        // challenge の生成, excludeCredentials (YubicoCredentialRepository 経由) も含めて Yubico が options を作る
        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(StartRegistrationOptions.builder()
                .user(UserIdentity.builder().name(username).displayName(username).id(userHandle).build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .residentKey(ResidentKeyRequirement.REQUIRED)
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .build())
                .timeout(300_000)
                .build());

        try {
            // challenge だけでなく options を丸ごとセッションに保存する (finishRegistration() に同じものを渡すため)
            String json = options.toJson();
            session.setAttribute(REGISTRATION_REQUEST, json);
            log.info("[yubico] 登録の options をセッションに保存 challenge={}", options.getChallenge().getBase64Url());
            // toCredentialsCreateJson() は {"publicKey": ...} で包まれるので、中身だけの toJson() を返す
            return json;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    void register(String username, RegistrationRequest request, HttpSession session) {
        if (request.label() == null || request.label().isBlank()) {
            throw new IllegalArgumentException("ラベルが空");
        }
        String requestJson = (String) session.getAttribute(REGISTRATION_REQUEST);
        session.removeAttribute(REGISTRATION_REQUEST);
        if (requestJson == null) {
            throw new IllegalArgumentException("セッションに options がない");
        }

        RegistrationResult result;
        try {
            // 1. パース (base64url・CBOR のデコード)
            PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.fromJson(requestJson);
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential =
                    PublicKeyCredential.parseRegistrationResponseJson(jsonMapper.writeValueAsString(request.credential()));

            // 2. 検証 (clientDataJSON, rpIdHash, フラグ, アルゴリズム, credentialId の重複)
            //    期待する challenge や UV 要否は、保存しておいた options から Yubico が読み取る
            result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                    .request(options)
                    .response(credential)
                    .build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (RegistrationFailedException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        String credentialId = result.getKeyId().getId().getBase64Url();
        log.info("[yubico] 登録の検証 OK attestationType={} aaguid={} credentialId={}",
                result.getAttestationType(), result.getAaguid().getHex(), credentialId);

        // 3. 公開鍵は COSE で返ってくるので、そのまま保存する (自前版・webauthn4j 版と同じテーブル・同じ形式)
        String userHandle = repository.findUserHandle(username).orElseThrow();
        Instant now = Instant.now();
        repository.saveCredential(new ScratchCredential(credentialId, userHandle, result.getPublicKeyCose().getBytes(),
                result.getSignatureCount(), request.label(), now, now));
        log.info("[yubico] パスキーを保存 username={} credentialId={} label={}", username, credentialId, request.label());
    }

    /** ScratchOptionsFactory と同じルールで userHandle を用意する (Yubico は userHandle を作ってくれない) */
    private String findOrCreateUserHandle(String username) {
        return repository.findUserHandle(username).orElseGet(() -> {
            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            String created = Base64Url.encode(bytes);
            repository.saveUserHandle(username, created);
            log.info("[yubico] userHandle を新規作成 username={} userHandle={}", username, created);
            return created;
        });
    }
}
