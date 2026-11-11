package dev.yuizho.login_demo.scratch.yubico;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import dev.yuizho.login_demo.WebAuthnProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/** 登録とログインで同じ RelyingParty を使う */
@Configuration
class YubicoRelyingPartyConfig {

    // rpId, origin, 使うアルゴリズム, attestation の扱いをまとめて持つ (webauthn4j 版の ServerProperty + RegistrationParameters に当たる)
    @Bean
    RelyingParty yubicoRelyingParty(YubicoCredentialRepository credentialRepository, WebAuthnProperties properties) {
        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder().id(properties.rpId()).name(properties.rpName()).build())
                .credentialRepository(credentialRepository)
                .origins(properties.allowedOrigins())
                .preferredPubkeyParams(List.of(PublicKeyCredentialParameters.ES256))
                .attestationConveyancePreference(AttestationConveyancePreference.NONE)
                .build();
    }
}
