package dev.yuizho.login_demo.scratch.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dev.yuizho.login_demo.WebAuthnProperties;
import dev.yuizho.login_demo.scratch.webauthn.ScratchCredentialRepository.ScratchCredential;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static dev.yuizho.login_demo.scratch.webauthn.ScratchVerifier.check;

/** パスキーでのログイン (navigator.credentials.get() の前後) */
@Service
class ScratchAuthenticationService {
    private static final Logger log = LoggerFactory.getLogger(ScratchAuthenticationService.class);
    private static final String CHALLENGE_ATTRIBUTE = "scratch.webauthn.authentication.challenge";

    private final SecureRandom random = new SecureRandom();
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final ScratchCredentialRepository repository;
    private final ScratchVerifier verifier;
    private final UserDetailsService userDetailsService;
    private final WebAuthnProperties properties;

    ScratchAuthenticationService(ScratchCredentialRepository repository, ScratchVerifier verifier,
                                 UserDetailsService userDetailsService, WebAuthnProperties properties) {
        this.repository = repository;
        this.verifier = verifier;
        this.userDetailsService = userDetailsService;
        this.properties = properties;
    }

    // credential.toJSON() のうち、使う項目だけ受け取る
    @JsonIgnoreProperties(ignoreUnknown = true)
    record AuthenticationRequest(String id, Response response) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Response(String clientDataJSON, String authenticatorData, String signature, String userHandle) {
    }

    /** PublicKeyCredential.parseRequestOptionsFromJSON() に渡せる形の options を作る */
    Map<String, Object> options(HttpSession session) {
        byte[] challengeBytes = new byte[32];
        random.nextBytes(challengeBytes);
        String challenge = Base64Url.encode(challengeBytes);
        session.setAttribute(CHALLENGE_ATTRIBUTE, challenge);
        log.info("[scratch] ログインの challenge をセッションに保存 challenge={}", challenge);

        // allowCredentials を空にすると、認証器が持っているこのサイト向けのパスキーから選ばせる (ユーザー名の入力不要)
        return Map.of(
                "challenge", challenge,
                "rpId", properties.rpId(),
                "timeout", 300_000,
                "userVerification", "required",
                "allowCredentials", List.of());
    }

    /** get() の結果 (署名) を検証して、ユーザー名を返す */
    String authenticate(AuthenticationRequest request, HttpSession session) {
        String challenge = (String) session.getAttribute(CHALLENGE_ATTRIBUTE);
        session.removeAttribute(CHALLENGE_ATTRIBUTE); // challenge は使い捨て

        // 1. credential ID から、登録時に保存した公開鍵を探す
        ScratchCredential credential = repository.findCredential(request.id())
                .orElseThrow(() -> new IllegalArgumentException("未登録の credentialId: " + request.id()));
        log.info("[scratch] パスキーを取得 credentialId={} label={}", credential.credentialId(), credential.label());
        check(credential.userHandle().equals(request.response().userHandle()), "userHandle が保存済みの値と一致しない");

        // 2. clientDataJSON: ログイン (webauthn.get) で、こちらが出した challenge に対して作られたか
        byte[] clientDataJSON = Base64Url.decode(request.response().clientDataJSON());
        verifier.verifyClientData(clientDataJSON, "webauthn.get", challenge);

        // 3. authData: rpIdHash とフラグ
        byte[] authDataBytes = Base64Url.decode(request.response().authenticatorData());
        AuthenticatorData authData = AuthenticatorData.parse(authDataBytes);
        verifier.verifyAuthenticatorData(authData);

        // 4. 署名: 認証器は authData || SHA-256(clientDataJSON) に秘密鍵で署名している
        //    clientDataJSON に challenge が入っているので、この署名は今回のログインでしか使えない
        check(verifySignature(credential.credentialPublicKey(), authDataBytes, clientDataJSON,
                Base64Url.decode(request.response().signature())), "署名の検証に失敗");
        log.info("[scratch] 署名 OK");

        // 5. 署名カウンタ: 増えていなければ、認証器が複製された可能性がある
        //    (1Password のような同期パスキーは常に 0 を返すので、両方 0 のときは見ない)
        log.info("[scratch] signCount 保存済み={} 今回={}", credential.signCount(), authData.signCount());
        if (credential.signCount() != 0 || authData.signCount() != 0) {
            check(authData.signCount() > credential.signCount(), "signCount が増えていない");
        }
        repository.updateSignCount(credential.credentialId(), authData.signCount(), Instant.now());

        // 6. userHandle → ユーザー名
        String username = repository.findUsername(credential.userHandle()).orElseThrow();
        log.info("[scratch] 認証成功 username={}", username);
        return username;
    }

    /** ここだけ Spring Security に頼る: ログイン済みの SecurityContext を作ってセッションに保存する */
    void login(String username, HttpServletRequest request, HttpServletResponse response) {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        check(user.isEnabled(), "無効なアカウント: " + username);

        // セッション固定攻撃の対策として、ログイン前後でセッションIDを変える
        request.changeSessionId();

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        log.info("[scratch] セッションにログイン情報を保存 username={} authorities={}", username, user.getAuthorities());
    }

    private static boolean verifySignature(byte[] cose, byte[] authData, byte[] clientDataJSON, byte[] signature) {
        try {
            // SHA256withECDSA が内部で SHA-256 をかけるので、渡すのは authData || SHA-256(clientDataJSON)
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(CoseConverter.toPublicKey(cose));
            verifier.update(authData);
            verifier.update(ScratchVerifier.sha256(clientDataJSON));
            return verifier.verify(signature); // WebAuthn の ES256 の署名は ASN.1 DER 形式で、Java と同じ
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("署名を検証できない", e);
        }
    }
}
