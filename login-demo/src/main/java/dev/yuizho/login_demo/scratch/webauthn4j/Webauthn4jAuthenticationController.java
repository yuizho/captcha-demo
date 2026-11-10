package dev.yuizho.login_demo.scratch.webauthn4j;

import dev.yuizho.login_demo.scratch.ScratchLoginSupport;
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
@RequestMapping("/scratch/webauthn4j/authenticate")
class Webauthn4jAuthenticationController {
    private static final Logger log = LoggerFactory.getLogger(Webauthn4jAuthenticationController.class);

    private final Webauthn4jAuthenticationService service;
    private final ScratchLoginSupport loginSupport;

    Webauthn4jAuthenticationController(Webauthn4jAuthenticationService service, ScratchLoginSupport loginSupport) {
        this.service = service;
        this.loginSupport = loginSupport;
    }

    @PostMapping("/options")
    Map<String, Object> options(HttpSession session) {
        return service.options(session);
    }

    // body は credential.toJSON() そのものなので、文字列のまま webauthn4j に渡す
    @PostMapping
    Map<String, Object> authenticate(@RequestBody String body, HttpSession session,
                                     HttpServletRequest request, HttpServletResponse response) {
        String username = service.authenticate(body, session);
        loginSupport.login(username, request, response);
        return Map.of("authenticated", true, "redirectUrl", "/loggedin");
    }

    // 勉強用なので、何が起きても 400 とメッセージを返すだけ (webauthn4j の例外は検証の失敗理由がクラス名でわかる)
    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<Map<String, Object>> handle(RuntimeException e) {
        log.warn("[webauthn4j] ログインに失敗", e);
        return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
    }
}
