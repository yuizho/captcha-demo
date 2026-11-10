package dev.yuizho.login_demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/login")
public class LoginController {
    // POST /login (パスワード認証) と POST /login/webauthn (パスキー認証) は Spring Security のフィルタが処理する
    @GetMapping
    String login() {
        return "login";
    }
}
