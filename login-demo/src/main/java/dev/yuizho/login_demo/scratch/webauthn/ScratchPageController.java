package dev.yuizho.login_demo.scratch.webauthn;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** フルスクラッチ版パスキーの画面 */
@Controller
@RequestMapping("/scratch")
class ScratchPageController {
    private final ScratchRegistrationService registrationService;

    ScratchPageController(ScratchRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @GetMapping("/login")
    String login() {
        return "scratch-login";
    }

    @GetMapping("/register")
    String register(Authentication authentication, Model model) {
        model.addAttribute("credentials", registrationService.credentials(authentication.getName()));
        return "scratch-register";
    }
}
