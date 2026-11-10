package dev.yuizho.login_demo.scratch.webauthn4j;

import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** webauthn4j 版パスキーの画面 (テンプレートは自前版と共有し、API の URL を model で渡す) */
@Controller
@RequestMapping("/scratch/webauthn4j")
class Webauthn4jPageController {
    private static final String IMPLEMENTATION = "webauthn4j 版";
    private static final String API_BASE = "/scratch/webauthn4j";

    private final ScratchCredentialRepository repository;

    Webauthn4jPageController(ScratchCredentialRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/login")
    String login(Model model) {
        model.addAttribute("implementation", IMPLEMENTATION);
        model.addAttribute("apiBase", API_BASE);
        model.addAttribute("pageUrl", "/scratch/webauthn4j/login");
        return "scratch-login";
    }

    // POST /scratch/webauthn4j/register は Webauthn4jRegistrationController が受ける (GET だけここ)
    @GetMapping("/register")
    String register(Authentication authentication, Model model) {
        model.addAttribute("implementation", IMPLEMENTATION);
        model.addAttribute("apiBase", API_BASE);
        model.addAttribute("pageUrl", "/scratch/webauthn4j/register");
        model.addAttribute("credentials", repository.findCredentialsByUsername(authentication.getName()));
        return "scratch-register";
    }
}
