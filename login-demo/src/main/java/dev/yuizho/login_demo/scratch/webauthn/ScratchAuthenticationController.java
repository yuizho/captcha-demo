package dev.yuizho.login_demo.scratch.webauthn;

import dev.yuizho.login_demo.scratch.ScratchLoginSupport;
import dev.yuizho.login_demo.scratch.webauthn.ScratchAuthenticationService.AuthenticationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/scratch/webauthn/authenticate")
class ScratchAuthenticationController {
    private static final Logger log = LoggerFactory.getLogger(ScratchAuthenticationController.class);

    private final ScratchAuthenticationService service;
    private final ScratchLoginSupport loginSupport;

    ScratchAuthenticationController(ScratchAuthenticationService service, ScratchLoginSupport loginSupport) {
        this.service = service;
        this.loginSupport = loginSupport;
    }

    @PostMapping("/options")
    Map<String, Object> options(HttpSession session) {
        return service.options(session);
    }

    @PostMapping
    Map<String, Object> authenticate(@RequestBody AuthenticationRequest body, HttpSession session,
                                     HttpServletRequest request, HttpServletResponse response) {
        String username = service.authenticate(body, session);
        loginSupport.login(username, request, response);
        return Map.of("authenticated", true, "redirectUrl", "/loggedin");
    }

    // 勉強用なので、何が起きても 400 とメッセージを返すだけ
    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<Map<String, Object>> handle(RuntimeException e) {
        log.warn("[scratch] ログインに失敗", e);
        return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
    }
}
