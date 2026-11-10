package dev.yuizho.login_demo.scratch;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** scratch_user_handles / scratch_credentials テーブルの読み書き (自前版と webauthn4j 版で共有) */
@Repository
public class ScratchCredentialRepository {
    private final JdbcClient jdbcClient;

    ScratchCredentialRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** ID はすべて base64url の文字列で持つ (JS の credential.id やログと見比べやすいように) */
    public record ScratchCredential(String credentialId, String userHandle, byte[] credentialPublicKey,
                                    long signCount, String label, Instant created, Instant lastUsed) {
    }

    private static final RowMapper<ScratchCredential> CREDENTIAL_ROW_MAPPER = (rs, rowNum) -> new ScratchCredential(
            rs.getString("credential_id"),
            rs.getString("user_handle"),
            rs.getBytes("public_cose"),
            rs.getLong("sign_count"),
            rs.getString("label"),
            toInstant(rs.getTimestamp("created")),
            toInstant(rs.getTimestamp("last_used")));

    public Optional<String> findUserHandle(String username) {
        return jdbcClient.sql("select user_handle from scratch_user_handles where username = ?")
                .param(username)
                .query(String.class)
                .optional();
    }

    public void saveUserHandle(String username, String userHandle) {
        jdbcClient.sql("insert into scratch_user_handles (username, user_handle) values (?, ?)")
                .params(username, userHandle)
                .update();
    }

    public Optional<String> findUsername(String userHandle) {
        return jdbcClient.sql("select username from scratch_user_handles where user_handle = ?")
                .param(userHandle)
                .query(String.class)
                .optional();
    }

    public Optional<ScratchCredential> findCredential(String credentialId) {
        return jdbcClient.sql("select * from scratch_credentials where credential_id = ?")
                .param(credentialId)
                .query(CREDENTIAL_ROW_MAPPER)
                .optional();
    }

    public void updateSignCount(String credentialId, long signCount, Instant lastUsed) {
        jdbcClient.sql("update scratch_credentials set sign_count = ?, last_used = ? where credential_id = ?")
                .params(signCount, Timestamp.from(lastUsed), credentialId)
                .update();
    }

    public List<ScratchCredential> findCredentialsByUserHandle(String userHandle) {
        return jdbcClient.sql("select * from scratch_credentials where user_handle = ? order by created")
                .param(userHandle)
                .query(CREDENTIAL_ROW_MAPPER)
                .list();
    }

    /** 画面の一覧表示用 */
    public List<ScratchCredential> findCredentialsByUsername(String username) {
        return findUserHandle(username)
                .map(this::findCredentialsByUserHandle)
                .orElse(List.of());
    }

    public void saveCredential(ScratchCredential credential) {
        jdbcClient.sql("""
                        insert into scratch_credentials
                            (credential_id, user_handle, public_cose, sign_count, label, created, last_used)
                        values (?, ?, ?, ?, ?, ?, ?)
                        """)
                .params(credential.credentialId(), credential.userHandle(), credential.credentialPublicKey(),
                        credential.signCount(), credential.label(),
                        Timestamp.from(credential.created()), Timestamp.from(credential.lastUsed()))
                .update();
    }

    private static Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
