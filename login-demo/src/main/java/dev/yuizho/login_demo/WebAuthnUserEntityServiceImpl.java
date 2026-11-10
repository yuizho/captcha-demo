package dev.yuizho.login_demo;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Service;

/**
 * パスキー用のユーザー情報 (ユーザー名 ↔ WebAuthn 用ユーザーID) を H2 の user_entities テーブルに保持する
 * (SQL は Spring Security の JdbcPublicKeyCredentialUserEntityRepository に任せ、ここでは呼び出しをログに出す)
 */
@Service
public class WebAuthnUserEntityServiceImpl implements PublicKeyCredentialUserEntityRepository {
    private static final Logger log = LoggerFactory.getLogger(WebAuthnUserEntityServiceImpl.class);

    private final JdbcPublicKeyCredentialUserEntityRepository delegate;

    public WebAuthnUserEntityServiceImpl(JdbcOperations jdbcOperations) {
        this.delegate = new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    @Override
    public @Nullable PublicKeyCredentialUserEntity findById(Bytes id) {
        PublicKeyCredentialUserEntity userEntity = delegate.findById(id);
        log.info("findById id={} -> {}", id.toBase64UrlString(), describe(userEntity));
        return userEntity;
    }

    @Override
    public @Nullable PublicKeyCredentialUserEntity findByUsername(String username) {
        PublicKeyCredentialUserEntity userEntity = delegate.findByUsername(username);
        log.info("findByUsername username={} -> {}", username, describe(userEntity));
        return userEntity;
    }

    @Override
    public void save(PublicKeyCredentialUserEntity userEntity) {
        delegate.save(userEntity);
        log.info("save {}", describe(userEntity));
    }

    @Override
    public void delete(Bytes id) {
        delegate.delete(id);
        log.info("delete id={}", id.toBase64UrlString());
    }

    private static String describe(@Nullable PublicKeyCredentialUserEntity userEntity) {
        if (userEntity == null) {
            return "not found";
        }
        return "UserEntity[name=%s, id=%s, displayName=%s]".formatted(
                userEntity.getName(), userEntity.getId().toBase64UrlString(), userEntity.getDisplayName());
    }
}
