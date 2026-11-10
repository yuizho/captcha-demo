package dev.yuizho.login_demo;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import static org.assertj.core.api.Assertions.assertThat;

class WebAuthnUserEntityServiceImplTests {

    WebAuthnUserEntityServiceImpl service = new WebAuthnUserEntityServiceImpl();

    @Test
    void 保存したユーザーをIDで取得できる() {
        PublicKeyCredentialUserEntity user1 = userEntity("user1");
        service.save(user1);

        assertThat(service.findById(user1.getId())).isEqualTo(user1);
    }

    @Test
    void 保存したユーザーをユーザー名で取得できる() {
        PublicKeyCredentialUserEntity user1 = userEntity("user1");
        service.save(user1);
        service.save(userEntity("user2"));

        assertThat(service.findByUsername("user1")).isEqualTo(user1);
    }

    @Test
    void 存在しないユーザーはnullを返す() {
        assertThat(service.findById(Bytes.random())).isNull();
        assertThat(service.findByUsername("unknown")).isNull();
    }

    @Test
    void 削除したユーザーは取得できない() {
        PublicKeyCredentialUserEntity user1 = userEntity("user1");
        service.save(user1);

        service.delete(user1.getId());

        assertThat(service.findById(user1.getId())).isNull();
        assertThat(service.findByUsername("user1")).isNull();
    }

    private static PublicKeyCredentialUserEntity userEntity(String username) {
        return ImmutablePublicKeyCredentialUserEntity.builder()
                .name(username)
                .id(Bytes.random())
                .displayName(username)
                .build();
    }
}
