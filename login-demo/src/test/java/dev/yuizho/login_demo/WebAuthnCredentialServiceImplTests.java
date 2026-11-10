package dev.yuizho.login_demo;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class WebAuthnCredentialServiceImplTests {

    WebAuthnCredentialServiceImpl service = new WebAuthnCredentialServiceImpl();

    @Test
    void 保存したパスキーをcredentialIDで取得できる() {
        CredentialRecord credential = credential(Bytes.random(), "passkey-1");
        service.save(credential);

        assertThat(service.findByCredentialId(credential.getCredentialId())).isEqualTo(credential);
    }

    @Test
    void ユーザーIDに紐づくパスキーだけを取得できる() {
        Bytes userId = Bytes.random();
        CredentialRecord credential1 = credential(userId, "passkey-1");
        CredentialRecord credential2 = credential(userId, "passkey-2");
        service.save(credential1);
        service.save(credential2);
        service.save(credential(Bytes.random(), "other-user-passkey"));

        assertThat(service.findByUserId(userId)).containsExactlyInAnyOrder(credential1, credential2);
    }

    @Test
    void 同じcredentialIDで保存すると上書きされる() {
        CredentialRecord credential = credential(Bytes.random(), "passkey-1");
        service.save(credential);

        // パスキーでのログイン時と同様に署名カウンタを更新して保存する
        CredentialRecord updated = ImmutableCredentialRecord.fromCredentialRecord(credential)
                .signatureCount(1)
                .lastUsed(Instant.now())
                .build();
        service.save(updated);

        assertThat(service.findByCredentialId(credential.getCredentialId())).isEqualTo(updated);
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
        Instant now = Instant.now();
        return ImmutableCredentialRecord.builder()
                .credentialType(PublicKeyCredentialType.PUBLIC_KEY)
                .credentialId(Bytes.random())
                .userEntityUserId(userId)
                .publicKey(new ImmutablePublicKeyCose(new byte[]{1, 2, 3}))
                .signatureCount(0)
                .label(label)
                .created(now)
                .lastUsed(now)
                .build();
    }
}
