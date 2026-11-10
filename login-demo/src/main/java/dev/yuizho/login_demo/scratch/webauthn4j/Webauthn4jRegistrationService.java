package dev.yuizho.login_demo.scratch.webauthn4j;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import dev.yuizho.login_demo.WebAuthnProperties;
import dev.yuizho.login_demo.scratch.Base64Url;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository.ScratchCredential;
import dev.yuizho.login_demo.scratch.ScratchOptionsFactory;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** パスキーの登録 (検証は webauthn4j に任せる) */
@Service
class Webauthn4jRegistrationService {
    private static final Logger log = LoggerFactory.getLogger(Webauthn4jRegistrationService.class);

    // COSE の公開鍵を CBOR に戻すのに使う (WebAuthnManager の内部と同じ設定)
    private final ObjectConverter objectConverter = new ObjectConverter();
    // NonStrict: attestation statement の証明書チェーンなどを検証しない (attestation: "none" なら十分)
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    private final ScratchCredentialRepository repository;
    private final ScratchOptionsFactory optionsFactory;
    private final WebAuthnProperties properties;
    private final JsonMapper jsonMapper;

    Webauthn4jRegistrationService(ScratchCredentialRepository repository, ScratchOptionsFactory optionsFactory,
                                  WebAuthnProperties properties, JsonMapper jsonMapper) {
        this.repository = repository;
        this.optionsFactory = optionsFactory;
        this.properties = properties;
        this.jsonMapper = jsonMapper;
    }

    /** credential は credential.toJSON() の結果をそのまま webauthn4j に渡すので、JsonNode のまま受け取る */
    record RegistrationRequest(String label, JsonNode credential) {
    }

    Map<String, Object> options(String username, HttpSession session) {
        return optionsFactory.creationOptions(username, session);
    }

    void register(String username, RegistrationRequest request, HttpSession session) {
        if (request.label() == null || request.label().isBlank()) {
            throw new IllegalArgumentException("ラベルが空");
        }
        String challenge = optionsFactory.consumeRegistrationChallenge(session);
        if (challenge == null) {
            throw new IllegalArgumentException("セッションに challenge がない");
        }

        // 1. サーバー側で「正しい値」として期待するもの (origin, rpId, challenge)
        ServerProperty serverProperty = ServerProperty.builder()
                .origins(properties.allowedOrigins().stream().map(Origin::new).collect(Collectors.toSet()))
                .rpId(properties.rpId())
                .challenge(new DefaultChallenge(challenge))
                .build();
        RegistrationParameters parameters = new RegistrationParameters(
                serverProperty,
                List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                true, // userVerificationRequired
                true); // userPresenceRequired

        // 2. パース (base64url・CBOR のデコード) と検証 (clientDataJSON, rpIdHash, フラグ, アルゴリズム) をまとめて実行
        //    自前版の Cbor, AuthenticatorData, ScratchVerifier でやっていたことが、この1行に入っている
        String credentialJson = jsonMapper.writeValueAsString(request.credential());
        RegistrationData registrationData = webAuthnManager.verifyRegistrationResponseJSON(credentialJson, parameters);
        log.info("[webauthn4j] 登録の検証 OK fmt={}", registrationData.getAttestationObject().getFormat());

        // 3. 検証済みのデータから credentialId と公開鍵を取り出す
        AuthenticatorData<?> authData = registrationData.getAttestationObject().getAuthenticatorData();
        AttestedCredentialData attestedCredentialData = authData.getAttestedCredentialData();
        String credentialId = Base64Url.encode(attestedCredentialData.getCredentialId());
        log.info("[webauthn4j] aaguid={} credentialId={} COSEKey={}",
                attestedCredentialData.getAaguid(), credentialId, attestedCredentialData.getCOSEKey());

        // 4. 公開鍵は COSE (CBOR) に戻して保存する (自前版と同じテーブル・同じ形式なので、どちらからでもログインできる)
        byte[] cose = objectConverter.getCborMapper().writeValueAsBytes(attestedCredentialData.getCOSEKey());
        String userHandle = repository.findUserHandle(username).orElseThrow();
        Instant now = Instant.now();
        repository.saveCredential(new ScratchCredential(credentialId, userHandle, cose,
                authData.getSignCount(), request.label(), now, now));
        log.info("[webauthn4j] パスキーを保存 username={} credentialId={} label={}", username, credentialId, request.label());
    }
}
