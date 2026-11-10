package dev.yuizho.login_demo;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * パスキー本体の情報 (credential ID, 公開鍵, 署名カウンタなど) を H2 の user_credentials テーブルに保持する
 * (SQL は Spring Security の JdbcUserCredentialRepository に任せ、ここでは呼び出しをログに出す)
 */
@Service
public class WebAuthnCredentialServiceImpl implements UserCredentialRepository {
    private static final Logger log = LoggerFactory.getLogger(WebAuthnCredentialServiceImpl.class);

    private final JdbcUserCredentialRepository delegate;

    public WebAuthnCredentialServiceImpl(JdbcOperations jdbcOperations) {
        this.delegate = new JdbcUserCredentialRepository(jdbcOperations);
    }

    @Override
    public void delete(Bytes credentialId) {
        delegate.delete(credentialId);
        log.info("delete credentialId={}", credentialId.toBase64UrlString());
    }

    @Override
    public void save(CredentialRecord credentialRecord) {
        // 登録時だけでなく、パスキーでのログインのたびに署名カウンタ・最終利用日時の更新で呼ばれる
        // (JdbcUserCredentialRepository は UPDATE して 0 件なら INSERT する)
        delegate.save(credentialRecord);
        log.info("save {}", describe(credentialRecord));
    }

    @Override
    public @Nullable CredentialRecord findByCredentialId(Bytes credentialId) {
        CredentialRecord credentialRecord = delegate.findByCredentialId(credentialId);
        log.info("findByCredentialId credentialId={} -> {}",
                credentialId.toBase64UrlString(), describe(credentialRecord));
        return credentialRecord;
    }

    @Override
    public List<CredentialRecord> findByUserId(Bytes userId) {
        List<CredentialRecord> found = delegate.findByUserId(userId);
        log.info("findByUserId userId={} -> {} credential(s)", userId.toBase64UrlString(), found.size());
        return found;
    }

    private static String describe(@Nullable CredentialRecord credentialRecord) {
        if (credentialRecord == null) {
            return "not found";
        }
        // 公開鍵は長いのでログに出さない
        return "Credential[label=%s, credentialId=%s, userId=%s, signatureCount=%d, created=%s, lastUsed=%s]".formatted(
                credentialRecord.getLabel(),
                credentialRecord.getCredentialId().toBase64UrlString(),
                credentialRecord.getUserEntityUserId().toBase64UrlString(),
                credentialRecord.getSignatureCount(),
                credentialRecord.getCreated(),
                credentialRecord.getLastUsed());
    }
}
