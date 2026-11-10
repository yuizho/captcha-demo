package dev.yuizho.login_demo.scratch.webauthn4j;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
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

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

/** パスキーでのログイン (検証は webauthn4j に任せる) */
@Service
class Webauthn4jAuthenticationService {
    private static final Logger log = LoggerFactory.getLogger(Webauthn4jAuthenticationService.class);

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    private final ScratchCredentialRepository repository;
    private final ScratchOptionsFactory optionsFactory;
    private final WebAuthnProperties properties;

    Webauthn4jAuthenticationService(ScratchCredentialRepository repository, ScratchOptionsFactory optionsFactory,
                                    WebAuthnProperties properties) {
        this.repository = repository;
        this.optionsFactory = optionsFactory;
        this.properties = properties;
    }

    Map<String, Object> options(HttpSession session) {
        return optionsFactory.requestOptions(session);
    }

    /** credential.toJSON() の JSON 文字列を受け取って検証し、ユーザー名を返す */
    String authenticate(String credentialJson, HttpSession session) {
        String challenge = optionsFactory.consumeAuthenticationChallenge(session);
        if (challenge == null) {
            throw new IllegalArgumentException("セッションに challenge がない");
        }

        // 1. パースだけ先にする (どの公開鍵で検証するかを決めるため、credentialId が要る)
        AuthenticationData authenticationData = webAuthnManager.parseAuthenticationResponseJSON(credentialJson);
        String credentialId = Base64Url.encode(authenticationData.getCredentialId());
        ScratchCredential credential = repository.findCredential(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("未登録の credentialId: " + credentialId));
        log.info("[webauthn4j] パスキーを取得 credentialId={} label={}", credentialId, credential.label());

        // 2. DB の値から webauthn4j の CredentialRecord を組み立て直す
        //    検証に要るのは公開鍵 (COSE) と署名カウンタだけなので、それ以外は null (= チェックしない)
        COSEKey coseKey = objectConverter.getCborMapper().readValue(credential.credentialPublicKey(), COSEKey.class);
        CredentialRecordImpl credentialRecord = new CredentialRecordImpl(
                null, // attestationStatement
                null, // uvInitialized
                null, // backupEligible
                null, // backupState
                credential.signCount(),
                new AttestedCredentialData(AAGUID.ZERO, authenticationData.getCredentialId(), coseKey),
                null, // authenticatorExtensions
                null, // clientData
                null, // clientExtensions
                null); // transports

        // 3. 検証 (clientDataJSON, rpIdHash, フラグ, 署名, 署名カウンタ)
        //    自前版の ScratchVerifier, CoseConverter, Signature での検証, signCount のチェックがここに入っている
        ServerProperty serverProperty = ServerProperty.builder()
                .origins(properties.allowedOrigins().stream().map(Origin::new).collect(Collectors.toSet()))
                .rpId(properties.rpId())
                .challenge(new DefaultChallenge(challenge))
                .build();
        webAuthnManager.verify(authenticationData, new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null, // allowCredentials (options で空にしているので、どのパスキーでも可)
                true, // userVerificationRequired
                true)); // userPresenceRequired
        long signCount = authenticationData.getAuthenticatorData().getSignCount();
        log.info("[webauthn4j] 検証 OK signCount 保存済み={} 今回={}", credential.signCount(), signCount);

        // 4. userHandle は webauthn4j が見ないので自分で確認する
        String userHandle = Base64Url.encode(authenticationData.getUserHandle());
        if (!credential.userHandle().equals(userHandle)) {
            throw new IllegalArgumentException("userHandle が保存済みの値と一致しない");
        }

        repository.updateSignCount(credentialId, signCount, Instant.now());
        String username = repository.findUsername(credential.userHandle()).orElseThrow();
        log.info("[webauthn4j] 認証成功 username={}", username);
        return username;
    }
}
