package dev.yuizho.login_demo;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(WebAuthnProperties.class)
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, WebAuthnProperties webAuthnProperties) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // 1. ルート (welcome page) と /loggedin/** は認証済みユーザーのみアクセス許可
                        .requestMatchers("/", "/loggedin/**").authenticated()
                        // パスキーの登録はログイン済みユーザーのみ
                        .requestMatchers("/webauthn/register/**").authenticated()
                        // フルスクラッチ版パスキーの登録もログイン済みユーザーのみ
                        .requestMatchers("/scratch/register", "/scratch/webauthn/register/**").authenticated()
                        .anyRequest().permitAll()
                )
                // ログインフォームを有効化 (画面は LoginController の自前のものを使う)
                .formLogin(login -> login
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/loggedin", false)
                        .permitAll() // ログイン画面自体へのアクセスは許可する
                )
                // ログアウト (CSRF 保護のため POST のみ受け付ける)
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .permitAll()
                )
                // パスキー (WebAuthn) 認証を有効化 (登録画面は WebAuthnRegisterController の自前のものを使う)
                .webAuthn(webAuthn -> webAuthn
                        .disableDefaultRegistrationPage(true)
                        .rpName(webAuthnProperties.rpName())
                        .rpId(webAuthnProperties.rpId())
                        .allowedOrigins(webAuthnProperties.allowedOrigins())
                )
                // 実験用: H2 Console は CSRF トークンを送らず、画面を iframe で組み立てるため
                .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
