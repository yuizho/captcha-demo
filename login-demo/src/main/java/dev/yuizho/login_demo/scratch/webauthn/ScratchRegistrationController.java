package dev.yuizho.login_demo.scratch.webauthn;

import dev.yuizho.login_demo.scratch.webauthn.ScratchRegistrationService.RegistrationRequest;
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
@RequestMapping("/scratch/webauthn/register")
class ScratchRegistrationController {
    private static final Logger log = LoggerFactory.getLogger(ScratchRegistrationController.class);

    private final ScratchRegistrationService service;

    ScratchRegistrationController(ScratchRegistrationService service) {
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

    // 勉強用なので、何が起きても 400 とメッセージを返すだけ
    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<Map<String, Object>> handle(RuntimeException e) {
        log.warn("[scratch] 登録に失敗", e);
        return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
    }
}
