-- アプリ起動時に組み込み H2 (メモリ) に対して自動で実行される
-- テーブル定義は Spring Security 同梱のスキーマと同じ
-- (spring-security-core の org/springframework/security/core/userdetails/jdbc/users.ddl,
--  spring-security-web の org/springframework/security/user-entities-schema.sql, user-credentials-schema.sql)

-- アカウント (ユーザー名, パスワード)
create table users
(
    username varchar_ignorecase(50)  not null primary key,
    password varchar_ignorecase(500) not null,
    enabled  boolean                 not null
);

-- アカウントの権限 (ロール)
create table authorities
(
    username  varchar_ignorecase(50) not null,
    authority varchar_ignorecase(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);
create unique index ix_auth_username on authorities (username, authority);

-- ユーザー名 ↔ WebAuthn 用ユーザーID
create table user_entities
(
    id           varchar(1000) not null,
    name         varchar(100)  not null,
    display_name varchar(200),
    primary key (id)
);

-- パスキー本体 (credential ID, 公開鍵, 署名カウンタなど)
create table user_credentials
(
    credential_id                varchar(1000) not null,
    user_entity_user_id          varchar(1000) not null,
    public_key                   blob          not null,
    signature_count              bigint,
    uv_initialized               boolean,
    backup_eligible              boolean       not null,
    authenticator_transports     varchar(1000),
    public_key_credential_type   varchar(100),
    backup_state                 boolean       not null,
    attestation_object           blob,
    attestation_client_data_json blob,
    created                      timestamp,
    last_used                    timestamp,
    label                        varchar(1000) not null,
    primary key (credential_id)
);
