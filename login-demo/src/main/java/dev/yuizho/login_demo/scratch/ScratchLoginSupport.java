package dev.yuizho.login_demo.scratch;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

/**
 * パスキーの検証が通った後、ログイン済みのセッションを作る (自前版と webauthn4j 版で共有)
 * <p>
 * ここだけ Spring Security に頼る。SecurityContext をセッションに保存しておけば、
 * 以降のリクエストは既存のフォームログインと同じようにログイン済みとして扱われる。
 */
@Component
public class ScratchLoginSupport {
    private static final Logger log = LoggerFactory.getLogger(ScratchLoginSupport.class);

    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final UserDetailsService userDetailsService;

    ScratchLoginSupport(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void login(String username, HttpServletRequest request, HttpServletResponse response) {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (!user.isEnabled()) {
            throw new IllegalArgumentException("無効なアカウント: " + username);
        }

        // セッション固定攻撃の対策として、ログイン前後でセッションIDを変える
        request.changeSessionId();

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        log.info("[scratch] セッションにログイン情報を保存 username={} authorities={}", username, user.getAuthorities());
    }
}
