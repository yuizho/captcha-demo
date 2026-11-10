# login-demo

## パスキーの処理の流れ

画面と JS は自前 (`login.html` / `webauthn-register.html`)。サーバー側のエンドポイントと検証は Spring Security (`http.webAuthn(...)`) が処理する。

### 登録

```mermaid
sequenceDiagram
    autonumber
    actor User as ユーザー(ログイン済み)
    participant JS as ブラウザ(webauthn-register.html)
    participant Auth as 認証器(Touch ID/1Password等)
    participant Server as Spring Security
    participant UE as WebAuthnUserEntityServiceImpl<br/>(user_entities)
    participant Cred as WebAuthnCredentialServiceImpl<br/>(user_credentials)

    User->>JS: ラベルを入力して「登録」
    alt ラベルが空
        JS-->>User: alert で中断 (認証器にパスキーを作らせない)
    end
    JS->>Server: POST /webauthn/register/options (X-CSRF-TOKEN)
    Server->>UE: findByUsername("user1")
    alt 初回
        Server->>Server: Bytes.random() で32バイトのユーザーIDを生成
        Server->>UE: save(UserEntity(name=user1, id=ランダム))
    end
    Server->>Server: challenge を生成してセッションに保存
    Server-->>JS: options (challenge, rp, user.id, residentKey=required)
    JS->>JS: PublicKeyCredential.parseCreationOptionsFromJSON() (base64url → ArrayBuffer)
    JS->>Auth: navigator.credentials.create(options)
    Auth->>User: ユーザー確認
    Auth-->>JS: 新しい鍵ペアの公開鍵 (attestationObject)
    JS->>JS: credential.toJSON() (ArrayBuffer → base64url)
    JS->>Server: POST /webauthn/register {publicKey: {credential, label}}
    Server->>Server: challenge・origin などを検証
    Server->>Cred: save(CredentialRecord)
    Server-->>JS: {"success": true}
    JS->>JS: location.href = "/webauthn/register?success"
```

### ログイン

```mermaid
sequenceDiagram
    autonumber
    actor User as ユーザー
    participant JS as ブラウザ(login.html)
    participant Auth as 認証器(Touch ID/1Password等)
    participant Server as Spring Security
    participant Cred as WebAuthnCredentialServiceImpl<br/>(user_credentials)
    participant UE as WebAuthnUserEntityServiceImpl<br/>(user_entities)
    participant UDS as UserDetailsServiceImpl<br/>(users/authorities)

    User->>JS: 「パスキーでログイン」をクリック
    JS->>Server: POST /webauthn/authenticate/options (X-CSRF-TOKEN)
    Server->>Server: challenge を生成してセッションに保存
    Server-->>JS: options (challenge, rpId, allowCredentials=[])
    JS->>JS: PublicKeyCredential.parseRequestOptionsFromJSON() (base64url → ArrayBuffer)
    JS->>Auth: navigator.credentials.get(options)
    Auth->>User: 生体認証などでユーザー確認
    Auth-->>JS: 秘密鍵で署名したアサーション
    JS->>JS: credential.toJSON() (ArrayBuffer → base64url)
    JS->>Server: POST /login/webauthn (id, clientDataJSON, authenticatorData, signature, userHandle)
    Server->>Cred: findByCredentialId(credentialId)
    Cred-->>Server: CredentialRecord (公開鍵, userEntityUserId)
    Server->>Server: challenge・origin・rpIdハッシュ・署名を検証
    Server->>Cred: save (signatureCount, lastUsed を更新)
    Server->>UE: findById(userEntityUserId)
    UE-->>Server: UserEntity(name=user1)
    Server->>UDS: loadUserByUsername("user1")
    UDS-->>Server: UserDetails (ロール)
    Server-->>JS: {"authenticated": true, "redirectUrl": "/"}
    JS->>JS: location.href = redirectUrl (失敗時は /login?error)
```

- ユーザーを特定するキーは、ブラウザが送る `userHandle` ではなく、credential ID で取得した `CredentialRecord` の `userEntityUserId`
- WebAuthn 用ユーザーIDは `user1` のハッシュではなく `SecureRandom` の32バイト (仕様上、個人を特定できる情報を入れないことが推奨されている)

## H2 データベースの確認

データはアプリ起動時に組み込み H2 (メモリ) に作られ、アプリを停止すると消える。

- テーブル定義: `src/main/resources/schema.sql`
- 初期データ (`user1` / `password`): `src/main/resources/data.sql`

| テーブル | 内容 |
|---|---|
| `users` / `authorities` | アカウント (ユーザー名, パスワード, ロール) |
| `user_entities` | ユーザー名 ↔ WebAuthn 用ユーザーID |
| `user_credentials` | パスキー (credential ID, 公開鍵, 署名カウンタ, ラベルなど) |

### H2 Console で中身を見る

1. アプリを起動し、ログから JDBC URL を探す (URL は起動のたびに変わる)

   ```
   H2 console available at '/h2-console'. Database available at 'jdbc:h2:mem:xxxxxxxx-...'
   ```

2. http://localhost:8080/h2-console を開き、次の値で「Connect」を押す
   - JDBC URL: 1. の `jdbc:h2:mem:...`
   - User Name: `sa`
   - Password: (空)

3. SQL を実行する。例えばアカウントからパスキーまでの紐づきは次のとおり

   ```sql
   select u.username, e.id as webauthn_user_id, c.label, c.signature_count, c.last_used
   from users u
   left join user_entities e on e.name = u.username
   left join user_credentials c on c.user_entity_user_id = e.id;
   ```

### 実行される SQL をログで見る

`application.properties` で次のログを有効にしている。

- `org.springframework.jdbc.core=DEBUG`: 実行される SQL
- `org.springframework.jdbc.core.StatementCreatorUtils=TRACE`: バインドされるパラメータ

パスキーでログインすると、おおよそ次の順に SQL が出る。

1. `SELECT ... FROM user_credentials WHERE credential_id = ?` (パスキーを検索)
2. `UPDATE user_credentials ...` (署名カウンタ・最終利用日時を更新)
3. `SELECT ... FROM user_entities WHERE id = ?` (WebAuthn 用ユーザーID からユーザー名を取得)
4. `users` / `authorities` の SELECT (アカウントとロールを取得)

### 注意

- H2 Console はログインなしで開ける実験用の設定 (`SecurityConfig` で `/h2-console/**` の CSRF チェックを無効化し、X-Frame-Options を `SAMEORIGIN` にしている)。ローカル以外では有効にしないこと

## 自前のパスキー実装 (フルスクラッチ版 / webauthn4j 版)

Spring Security のパスキー実装 (`/webauthn/**`) とは別に、サーバー側の処理を自分で書いたもの。Spring Security には CSRF チェックと、最後にログイン済みのセッションを作る部分 (`ScratchLoginSupport`) だけを任せている。

```
dev.yuizho.login_demo.scratch
├── (共通) ScratchCredentialRepository, ScratchOptionsFactory, ScratchLoginSupport, Base64Url
├── webauthn     … フルスクラッチ版: JDK の java.security と自前の CBOR デコーダだけで検証
└── webauthn4j   … webauthn4j 版: パースと検証を WebAuthnManager に任せる
```

| | フルスクラッチ版 | webauthn4j 版 |
|---|---|---|
| 登録画面 (ログイン必須) | `GET /scratch/register` | `GET /scratch/webauthn4j/register` |
| ログイン画面 | `GET /scratch/login` | `GET /scratch/webauthn4j/login` |
| 登録 API | `POST /scratch/webauthn/register/options`, `/scratch/webauthn/register` | `POST /scratch/webauthn4j/register/options`, `/scratch/webauthn4j/register` |
| ログイン API | `POST /scratch/webauthn/authenticate/options`, `/scratch/webauthn/authenticate` | `POST /scratch/webauthn4j/authenticate/options`, `/scratch/webauthn4j/authenticate` |
| ログの接頭辞 | `[scratch]` | `[webauthn4j]` |

- 画面のテンプレート (`scratch-register.html` / `scratch-login.html`) は共有し、API の URL を model で渡している
- options の JSON (challenge, rp, user など) はプロトコル上ただの JSON で webauthn4j も作らないので、共通の `ScratchOptionsFactory` で作る
- データは両方とも `scratch_user_handles` / `scratch_credentials` テーブルに保存する (Spring 版とは別のテーブル)。公開鍵を標準の COSE 形式で保存しているので、片方で登録したパスキーでもう片方からログインできる

### サーバーで検証していること

- 登録
  1. clientDataJSON: `type` が `webauthn.create`、`challenge` がセッションの値と一致、`origin` が許可したもの
  2. attestationObject を CBOR でデコード (`fmt` = `none` 前提で、attStmt は検証しない)
  3. authData: rpIdHash = SHA-256(rpId)、UP / UV / AT フラグ、credentialId = `credential.id`
  4. 公開鍵 (COSE) が ES256 (alg = -7) であること。COSE のまま保存する
- ログイン
  1. credential ID で保存済みの公開鍵を探し、userHandle が一致すること
  2. clientDataJSON: `type` が `webauthn.get`、`challenge`、`origin`
  3. authData: rpIdHash、UP / UV フラグ
  4. 署名: `authData || SHA-256(clientDataJSON)` に対する ECDSA の署名を、COSE から変換した公開鍵で検証
  5. 署名カウンタが増えていること (保存済みも今回も 0 なら見ない。同期パスキーは常に 0)
  6. userHandle → ユーザー名 → `UserDetailsService` でアカウントを取得し、`SecurityContext` をセッションに保存

### 実装の対応

| 処理 | フルスクラッチ版 (`scratch.webauthn`) | webauthn4j 版 (`scratch.webauthn4j`) |
|---|---|---|
| base64url・CBOR のデコード | `Base64Url`, `Cbor`, `AuthenticatorData` | `WebAuthnManager.verifyRegistrationResponseJSON` / `parseAuthenticationResponseJSON` |
| 登録の検証 (1〜4) | `ScratchVerifier` + `ScratchRegistrationService` | `verifyRegistrationResponseJSON` + `RegistrationParameters` |
| COSE → 公開鍵 | `CoseConverter` | `COSEKey` (CBOR から `readValue`) |
| ログインの検証 (2〜5) | `ScratchVerifier` + `Signature` + signCount のチェック | `verify` + `AuthenticationParameters` (DB の値から `CredentialRecordImpl` を組み立てる) |
| userHandle の一致 (ログイン 1) | 自前 | 自前 (webauthn4j はチェックしない) |

- webauthn4j 版は `createNonStrictWebAuthnManager()` を使っている (attestation の証明書チェーンを検証しない。`attestation: "none"` なら十分)
- webauthn4j の例外は失敗の理由がクラス名でわかる (例: `BadChallengeException`, `MaliciousCounterValueException`)。レスポンスの `error` にクラス名を入れている

勉強用なので、検証に失敗したら例外を投げて 400 を返し、ログに WARN を出すだけ。
