resource "aws_wafv2_web_acl" "main" {
  name  = "${var.project}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  captcha_config {
    immunity_time_property {
      immunity_time = var.captcha_immunity_time
    }
  }

  # GET /login でパズルを解かせてトークンを発行し、
  # トークンを持たない POST /login (bot による直接送信など) は 405 で弾く
  rule {
    name     = "captcha-login"
    priority = 0

    action {
      captcha {}
    }

    statement {
      byte_match_statement {
        search_string         = "/login"
        positional_constraint = "EXACTLY"

        field_to_match {
          uri_path {}
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-captcha-login"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
