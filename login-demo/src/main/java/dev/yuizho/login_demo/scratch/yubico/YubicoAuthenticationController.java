package dev.yuizho.login_demo.scratch.yubico;

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
import tools.jackson.databind.JsonNode;

import java.util.Map;

@RestController
@RequestMapping("/scratch/yubico/authenticate")
class YubicoAuthenticationController {
    private static final Logger log = LoggerFactory.getLogger(YubicoAuthenticationController.class);

    private final YubicoAuthenticationService service;
    private final ScratchLoginSupport loginSupport;

    YubicoAuthenticationController(YubicoAuthenticationService service, ScratchLoginSupport loginSupport) {
        this.service = service;
        this.loginSupport = loginSupport;
    }

    @PostMapping("/options")
    JsonNode options(HttpSession session) {
        return service.options(session);
    }

    // body は credential.toJSON() そのものなので、文字列のまま Yubico に渡す
    @PostMapping
    Map<String, Object> authenticate(@RequestBody String body, HttpSession session,
                                     HttpServletRequest request, HttpServletResponse response) {
        String username = service.authenticate(body, session);
        loginSupport.login(username, request, response);
        return Map.of("authenticated", true, "redirectUrl", "/loggedin");
    }

    // 勉強用なので、何が起きても 400 とメッセージを返すだけ
    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<Map<String, Object>> handle(RuntimeException e) {
        log.warn("[yubico] ログインに失敗", e);
        return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
    }
}
