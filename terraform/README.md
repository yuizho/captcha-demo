# login-demo infrastructure

```
Internet --> ALB (HTTP:80) --> ECS on Fargate (login-demo:8080)
```

- リージョン: `ap-northeast-1`
- ECS タスクは public subnet に配置 (NAT Gateway なし)。受信は ALB からのみ許可
- state はローカル管理

## 前提

- Terraform (`.terraform-version` のバージョン。tfenv 利用時は自動で選択される)
- AWS CLI v2
- Docker
- AWS の認証情報が環境変数 (`AWS_ACCESS_KEY_ID` など) で設定されていること

## 初回デプロイ

ECR にイメージが無いと ECS タスクが起動できないため、ECR だけ先に作成してからイメージを push する。

```sh
cd terraform
terraform init

# 1. ECR リポジトリだけ先に作成
terraform apply -target=aws_ecr_repository.app

# 2. イメージをビルドして push
REPO_URL=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password --region ap-northeast-1 \
  | docker login --username AWS --password-stdin "${REPO_URL%%/*}"
docker build --platform linux/amd64 -t "${REPO_URL}:latest" ../login-demo
docker push "${REPO_URL}:latest"

# 3. 残りのリソースを作成
terraform apply
```

完了後、`terraform output -raw alb_dns_name` の URL にアクセスする (タスク起動とヘルスチェック通過まで数分かかる)。

- `http://<alb_dns_name>/loggedin` → ログイン画面へリダイレクト
- ユーザー `user1` / パスワード `password` でログイン

## CAPTCHA (AWS WAF)

ALB に Web ACL を関連付け、URI パスが `/login` のリクエスト (GET / POST) に CAPTCHA アクションを適用している。

- ブラウザで `http://<alb_dns_name>/login` を開くと CAPTCHA パズルが表示され、解くと `aws-waf-token` cookie が発行される
- トークンを持たない POST は 405 で弾かれる

```sh
curl -i -X POST "http://$(terraform output -raw alb_dns_name)/login"
# => HTTP/1.1 405 / x-amzn-waf-action: captcha
```

パズルを解いてから `captcha_immunity_time` 秒 (デフォルト 60 秒、最小 60 秒) 経過すると再度 CAPTCHA が求められる。
すぐに再度パズルを表示したい場合はブラウザの `aws-waf-token` cookie を削除する。

## アプリの更新

`latest` タグで push し直した場合、タスク定義は変わらないため強制的に再デプロイする。

```sh
docker build --platform linux/amd64 -t "${REPO_URL}:latest" ../login-demo
docker push "${REPO_URL}:latest"
aws ecs update-service \
  --cluster "$(terraform output -raw ecs_cluster_name)" \
  --service "$(terraform output -raw ecs_service_name)" \
  --force-new-deployment
```

別タグで push した場合は `terraform apply -var image_tag=<tag>` でタスク定義ごと更新する。

## ログ

```sh
aws logs tail /ecs/login-demo --follow
```

## 削除

```sh
terraform destroy
```

## 注意

- セッションはアプリのインメモリで管理しているため、`desired_count` を 2 以上にするとログイン状態が維持されない
- HTTP のみ (HTTPS 未対応)
