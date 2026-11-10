package dev.yuizho.login_demo;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

/**
 * アカウント (ユーザー名, パスワード, ロール) を H2 の users / authorities テーブルから読み込む
 * (SQL は Spring Security の JdbcUserDetailsManager に任せ、ここでは呼び出しをログに出す)
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    private final JdbcUserDetailsManager delegate;

    public UserDetailsServiceImpl(DataSource dataSource) {
        this.delegate = new JdbcUserDetailsManager(dataSource);
    }

    @Override
    @NonNull
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        try {
            UserDetails user = delegate.loadUserByUsername(username);
            log.info("loadUserByUsername username={} -> authorities={}", username, user.getAuthorities());
            return user;
        } catch (UsernameNotFoundException e) {
            log.info("loadUserByUsername username={} -> not found", username);
            throw e;
        }
    }
}
