variable "region" {
  description = "デプロイ先の AWS リージョン"
  type        = string
  default     = "ap-northeast-1"
}

variable "project" {
  description = "リソース名のプレフィックスに使うプロジェクト名"
  type        = string
  default     = "login-demo"
}

variable "vpc_cidr" {
  description = "VPC の CIDR ブロック"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "public subnet の CIDR ブロック (AZ ごとに 1 つ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "container_port" {
  description = "コンテナが listen するポート"
  type        = number
  default     = 8080
}

variable "image_tag" {
  description = "デプロイするコンテナイメージのタグ"
  type        = string
  default     = "latest"
}

variable "task_cpu" {
  description = "Fargate タスクの CPU ユニット"
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate タスクのメモリ (MiB)"
  type        = number
  default     = 512
}

variable "captcha_immunity_time" {
  description = "CAPTCHA を解いてから再度 CAPTCHA を求めるまでの秒数"
  type        = number
  default     = 60

  validation {
    condition     = var.captcha_immunity_time >= 60 && var.captcha_immunity_time <= 259200
    error_message = "captcha_immunity_time は 60〜259200 秒の範囲で指定してください。"
  }
}

variable "desired_count" {
  description = "起動するタスク数 (セッションがインメモリのため 1 を推奨)"
  type        = number
  default     = 1
}
