package dev.yuizho.login_demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/webauthn/register")
public class WebAuthnRegisterController {
    private final PublicKeyCredentialUserEntityRepository userEntities;
    private final UserCredentialRepository userCredentials;

    public WebAuthnRegisterController(PublicKeyCredentialUserEntityRepository userEntities,
                                      UserCredentialRepository userCredentials) {
        this.userEntities = userEntities;
        this.userCredentials = userCredentials;
    }

    // POST /webauthn/register/options と POST /webauthn/register は Spring Security のフィルタが処理する
    @GetMapping
    String register(Authentication authentication, Model model) {
        // ユーザー名 → WebAuthn 用ユーザーID → パスキー一覧 の順にたどる
        PublicKeyCredentialUserEntity userEntity = userEntities.findByUsername(authentication.getName());
        List<CredentialRecord> credentials = userEntity == null
                ? List.of()
                : userCredentials.findByUserId(userEntity.getId());
        model.addAttribute("credentials", credentials);
        return "webauthn-register";
    }
}
