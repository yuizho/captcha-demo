package dev.yuizho.login_demo;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Set;

/**
 * パスキー (WebAuthn) の Relying Party 設定
 *
 * @param rpName         Relying Party の表示名
 * @param rpId           Relying Party の ID (ドメイン名)
 * @param allowedOrigins 許可するオリジン
 */
@Validated
@ConfigurationProperties("app.webauthn")
public record WebAuthnProperties(
        @NotBlank String rpName,
        @NotBlank String rpId,
        @NotEmpty Set<@NotBlank String> allowedOrigins
) {
}
