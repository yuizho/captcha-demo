package dev.yuizho.login_demo.scratch.webauthn;

import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** フルスクラッチ版パスキーの画面 (テンプレートは webauthn4j 版と共有し、API の URL を model で渡す) */
@Controller
@RequestMapping("/scratch")
class ScratchPageController {
    private static final String IMPLEMENTATION = "フルスクラッチ版";
    private static final String API_BASE = "/scratch/webauthn";

    private final ScratchCredentialRepository repository;

    ScratchPageController(ScratchCredentialRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/login")
    String login(Model model) {
        model.addAttribute("implementation", IMPLEMENTATION);
        model.addAttribute("apiBase", API_BASE);
        model.addAttribute("pageUrl", "/scratch/login");
        return "scratch-login";
    }

    @GetMapping("/register")
    String register(Authentication authentication, Model model) {
        model.addAttribute("implementation", IMPLEMENTATION);
        model.addAttribute("apiBase", API_BASE);
        model.addAttribute("pageUrl", "/scratch/register");
        model.addAttribute("credentials", repository.findCredentialsByUsername(authentication.getName()));
        return "scratch-register";
    }
}
