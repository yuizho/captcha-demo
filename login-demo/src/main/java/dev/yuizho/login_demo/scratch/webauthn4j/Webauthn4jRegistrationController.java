package dev.yuizho.login_demo.scratch.webauthn4j;

import dev.yuizho.login_demo.scratch.webauthn4j.Webauthn4jRegistrationService.RegistrationRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/scratch/webauthn4j/register")
class Webauthn4jRegistrationController {
    private static final Logger log = LoggerFactory.getLogger(Webauthn4jRegistrationController.class);

    private final Webauthn4jRegistrationService service;

    Webauthn4jRegistrationController(Webauthn4jRegistrationService service) {
        this.service = service;
    }

    @PostMapping("/options")
    Map<String, Object> options(Authentication authentication, HttpSession session) {
        return service.options(authentication.getName(), session);
    }

    @PostMapping
    Map<String, Object> register(Authentication authentication, @RequestBody RegistrationRequest request,
                                 HttpSession session) {
        service.register(authentication.getName(), request, session);
        return Map.of("success", true);
    }

    // 勉強用なので、何が起きても 400 とメッセージを返すだけ (webauthn4j の例外は検証の失敗理由がクラス名でわかる)
    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<Map<String, Object>> handle(RuntimeException e) {
        log.warn("[webauthn4j] 登録に失敗", e);
        return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
    }
}
