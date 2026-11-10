package dev.yuizho.login_demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jdbc.test.autoconfigure.DataJdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

// H2 (schema.sql 適用済み) を使い、テストごとにロールバックされる
@DataJdbcTest
@Import(WebAuthnCredentialServiceImpl.class)
class WebAuthnCredentialServiceImplTests {

    @Autowired
    WebAuthnCredentialServiceImpl service;

    @Test
    void 保存したパスキーをcredentialIDで取得できる() {
        CredentialRecord credential = credential(Bytes.random(), "passkey-1");
        service.save(credential);

        CredentialRecord found = service.findByCredentialId(credential.getCredentialId());

        assertThat(found).isNotNull();
        assertThat(found.getCredentialId()).isEqualTo(credential.getCredentialId());
        assertThat(found.getUserEntityUserId()).isEqualTo(credential.getUserEntityUserId());
        assertThat(found.getPublicKey().getBytes()).isEqualTo(credential.getPublicKey().getBytes());
        assertThat(found.getLabel()).isEqualTo("passkey-1");
        assertThat(found.getCreated()).isEqualTo(credential.getCreated());
    }

    @Test
    void ユーザーIDに紐づくパスキーだけを取得できる() {
        Bytes userId = Bytes.random();
        service.save(credential(userId, "passkey-1"));
        service.save(credential(userId, "passkey-2"));
        service.save(credential(Bytes.random(), "other-user-passkey"));

        assertThat(service.findByUserId(userId))
                .extracting(CredentialRecord::getLabel)
                .containsExactlyInAnyOrder("passkey-1", "passkey-2");
    }

    @Test
    void 同じcredentialIDで保存すると上書きされる() {
        CredentialRecord credential = credential(Bytes.random(), "passkey-1");
        service.save(credential);

        // パスキーでのログイン時と同様に署名カウンタを更新して保存する
        CredentialRecord updated = ImmutableCredentialRecord.fromCredentialRecord(credential)
                .signatureCount(1)
                .build();
        service.save(updated);

        assertThat(service.findByCredentialId(credential.getCredentialId()))
                .extracting(CredentialRecord::getSignatureCount)
                .isEqualTo(1L);
        assertThat(service.findByUserId(credential.getUserEntityUserId())).hasSize(1);
    }

    @Test
    void 存在しないパスキーはnullや空リストを返す() {
        assertThat(service.findByCredentialId(Bytes.random())).isNull();
        assertThat(service.findByUserId(Bytes.random())).isEmpty();
    }

    @Test
    void 削除したパスキーは取得できない() {
        CredentialRecord credential = credential(Bytes.random(), "passkey-1");
        service.save(credential);

        service.delete(credential.getCredentialId());

        assertThat(service.findByCredentialId(credential.getCredentialId())).isNull();
        assertThat(service.findByUserId(credential.getUserEntityUserId())).isEmpty();
    }

    private static CredentialRecord credential(Bytes userId, String label) {
        // DB の timestamp に合わせて精度を落としておく
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        return ImmutableCredentialRecord.builder()
                .credentialType(PublicKeyCredentialType.PUBLIC_KEY)
                .credentialId(Bytes.random())
                .userEntityUserId(userId)
                .publicKey(new ImmutablePublicKeyCose(new byte[]{1, 2, 3}))
                .signatureCount(0)
                .uvInitialized(true)
                .transports(Set.of())
                .backupEligible(false)
                .backupState(false)
                .attestationObject(new Bytes(new byte[]{4, 5, 6}))
                .attestationClientDataJSON(new Bytes(new byte[]{7, 8, 9}))
                .label(label)
                .created(now)
                .lastUsed(now)
                .build();
    }
}
