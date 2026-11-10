package dev.yuizho.login_demo;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * パスキー本体の情報 (credential ID, 公開鍵, 署名カウンタなど) をメモリに保持する
 */
@Service
public class WebAuthnCredentialServiceImpl implements UserCredentialRepository {
    private static final Logger log = LoggerFactory.getLogger(WebAuthnCredentialServiceImpl.class);

    // key: credential ID
    private final Map<Bytes, CredentialRecord> credentials = new ConcurrentHashMap<>();

    @Override
    public void delete(Bytes credentialId) {
        CredentialRecord removed = credentials.remove(credentialId);
        log.info("delete credentialId={} -> {} (size={})",
                credentialId.toBase64UrlString(), describe(removed), credentials.size());
    }

    @Override
    public void save(CredentialRecord credentialRecord) {
        // 登録時だけでなく、パスキーでのログインのたびに署名カウンタ・最終利用日時の更新で呼ばれる
        CredentialRecord previous = credentials.put(credentialRecord.getCredentialId(), credentialRecord);
        log.info("save ({}) {} (size={})",
                previous == null ? "new" : "update", describe(credentialRecord), credentials.size());
    }

    @Override
    public @Nullable CredentialRecord findByCredentialId(Bytes credentialId) {
        CredentialRecord credentialRecord = credentials.get(credentialId);
        log.info("findByCredentialId credentialId={} -> {}",
                credentialId.toBase64UrlString(), describe(credentialRecord));
        return credentialRecord;
    }

    @Override
    public List<CredentialRecord> findByUserId(Bytes userId) {
        List<CredentialRecord> found = credentials.values().stream()
                .filter(c -> c.getUserEntityUserId().equals(userId))
                .toList();
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
