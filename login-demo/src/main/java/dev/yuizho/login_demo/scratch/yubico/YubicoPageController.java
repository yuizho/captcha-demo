package dev.yuizho.login_demo.scratch.yubico;

import dev.yuizho.login_demo.scratch.ScratchCredentialRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** Yubico 版パスキーの画面 (テンプレートは自前版と共有し、API の URL を model で渡す) */
@Controller
@RequestMapping("/scratch/yubico")
class YubicoPageController {
    private static final String IMPLEMENTATION = "Yubico 版";
    private static final String API_BASE = "/scratch/yubico";

    private final ScratchCredentialRepository repository;

    YubicoPageController(ScratchCredentialRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/login")
    String login(Model model) {
        model.addAttribute("implementation", IMPLEMENTATION);
        model.addAttribute("apiBase", API_BASE);
        model.addAttribute("pageUrl", "/scratch/yubico/login");
        return "scratch-login";
    }

    // POST /scratch/yubico/register は YubicoRegistrationController が受ける (GET だけここ)
    @GetMapping("/register")
    String register(Authentication authentication, Model model) {
        model.addAttribute("implementation", IMPLEMENTATION);
        model.addAttribute("apiBase", API_BASE);
        model.addAttribute("pageUrl", "/scratch/yubico/register");
        model.addAttribute("credentials", repository.findCredentialsByUsername(authentication.getName()));
        return "scratch-register";
    }
}
