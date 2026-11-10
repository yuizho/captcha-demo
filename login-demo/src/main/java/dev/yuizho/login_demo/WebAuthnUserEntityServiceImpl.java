package dev.yuizho.login_demo;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * パスキー用のユーザー情報 (ユーザー名 ↔ WebAuthn 用ユーザーID) をメモリに保持する
 */
@Service
public class WebAuthnUserEntityServiceImpl implements PublicKeyCredentialUserEntityRepository {
    private static final Logger log = LoggerFactory.getLogger(WebAuthnUserEntityServiceImpl.class);

    // key: WebAuthn 用ユーザーID (userHandle)
    private final Map<Bytes, PublicKeyCredentialUserEntity> userEntities = new ConcurrentHashMap<>();

    @Override
    public @Nullable PublicKeyCredentialUserEntity findById(Bytes id) {
        PublicKeyCredentialUserEntity userEntity = userEntities.get(id);
        log.info("findById id={} -> {}", id.toBase64UrlString(), describe(userEntity));
        return userEntity;
    }

    @Override
    public @Nullable PublicKeyCredentialUserEntity findByUsername(String username) {
        PublicKeyCredentialUserEntity userEntity = userEntities.values().stream()
                .filter(u -> u.getName().equals(username))
                .findFirst()
                .orElse(null);
        log.info("findByUsername username={} -> {}", username, describe(userEntity));
        return userEntity;
    }

    @Override
    public void save(PublicKeyCredentialUserEntity userEntity) {
        userEntities.put(userEntity.getId(), userEntity);
        log.info("save {} (size={})", describe(userEntity), userEntities.size());
    }

    @Override
    public void delete(Bytes id) {
        PublicKeyCredentialUserEntity removed = userEntities.remove(id);
        log.info("delete id={} -> {} (size={})", id.toBase64UrlString(), describe(removed), userEntities.size());
    }

    private static String describe(@Nullable PublicKeyCredentialUserEntity userEntity) {
        if (userEntity == null) {
            return "not found";
        }
        return "UserEntity[name=%s, id=%s, displayName=%s]".formatted(
                userEntity.getName(), userEntity.getId().toBase64UrlString(), userEntity.getDisplayName());
    }
}
