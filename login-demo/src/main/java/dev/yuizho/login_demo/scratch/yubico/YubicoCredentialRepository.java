package dev.yuizho.login_demo.scratch.yubico;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import dev.yuizho.login_demo.scratch.Base64Url;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import dev.yuizho.login_demo.scratch.ScratchCredentialRepository.ScratchCredential;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Yubico の RelyingParty が DB を引くときに使うアダプタ (中身は ScratchCredentialRepository に委譲)
 * <p>
 * webauthn4j 版では Service から repository を直接呼んでいたが、Yubico ではライブラリがこのインターフェース経由で引きにくる。
 * DB の ID は base64url の文字列、Yubico 側は ByteArray なので、ここで変換する。
 */
@Component
class YubicoCredentialRepository implements CredentialRepository {
    private final ScratchCredentialRepository repository;

    YubicoCredentialRepository(ScratchCredentialRepository repository) {
        this.repository = repository;
    }

    /** startRegistration() の excludeCredentials に使われる */
    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return repository.findCredentialsByUsername(username).stream()
                .map(c -> PublicKeyCredentialDescriptor.builder().id(toByteArray(c.credentialId())).build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return repository.findUserHandle(username).map(YubicoCredentialRepository::toByteArray);
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return repository.findUsername(userHandle.getBase64Url());
    }

    /** finishAssertion() が公開鍵と署名カウンタを取りにくる (userHandle が違えば見つからない扱い) */
    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return repository.findCredential(credentialId.getBase64Url())
                .filter(c -> c.userHandle().equals(userHandle.getBase64Url()))
                .map(YubicoCredentialRepository::toRegisteredCredential);
    }

    /** finishRegistration() が credentialId の重複チェックに使う */
    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return repository.findCredential(credentialId.getBase64Url())
                .map(YubicoCredentialRepository::toRegisteredCredential)
                .stream()
                .collect(Collectors.toSet());
    }

    /** 公開鍵は COSE のまま保存しているので、そのまま渡せる (webauthn4j 版のように組み立て直さなくてよい) */
    private static RegisteredCredential toRegisteredCredential(ScratchCredential credential) {
        return RegisteredCredential.builder()
                .credentialId(toByteArray(credential.credentialId()))
                .userHandle(toByteArray(credential.userHandle()))
                .publicKeyCose(new ByteArray(credential.credentialPublicKey()))
                .signatureCount(credential.signCount())
                .build();
    }

    private static ByteArray toByteArray(String base64Url) {
        return new ByteArray(Base64Url.decode(base64Url));
    }
}
