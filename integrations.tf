################################################################################
# Integrations — Chat & Alerting
#
# This file contains optional notification integrations for the malware-alert
# SNS topic.  Other agents may append additional integration blocks below.
################################################################################

################################################################################
# AWS Chatbot — IAM Role (shared by Slack and Teams)
################################################################################

resource "aws_iam_role" "chatbot" {
  count = var.enable_slack_integration || var.enable_teams_integration ? 1 : 0

  name = "${var.name_prefix}-chatbot"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowChatbotAssume"
        Effect = "Allow"
        Principal = {
          Service = "chatbot.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "chatbot" {
  count = var.enable_slack_integration || var.enable_teams_integration ? 1 : 0

  name = "${var.name_prefix}-chatbot"
  role = aws_iam_role.chatbot[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchReadOnly"
        Effect = "Allow"
        Action = [
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Get*",
          "logs:List*",
          "logs:Describe*",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:FilterLogEvents",
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSTopicAccess"
        Effect = "Allow"
        Action = [
          "sns:GetTopicAttributes",
          "sns:ListSubscriptionsByTopic",
        ]
        Resource = module.file_router.sns_topic_arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "chatbot_resource_explorer" {
  count = var.enable_slack_integration || var.enable_teams_integration ? 1 : 0

  role       = aws_iam_role.chatbot[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSResourceExplorerReadOnlyAccess"
}

################################################################################
# AWS Chatbot — Slack Channel Configuration
################################################################################

resource "aws_chatbot_slack_channel_configuration" "this" {
  count = var.enable_slack_integration ? 1 : 0

  configuration_name = "${var.name_prefix}-malware-alerts"
  iam_role_arn       = aws_iam_role.chatbot[0].arn
  slack_team_id      = var.slack_workspace_id
  slack_channel_id   = var.slack_channel_id
  sns_topic_arns     = [module.file_router.sns_topic_arn]

  tags = var.tags
}

################################################################################
# AWS Chatbot — Microsoft Teams Channel Configuration
################################################################################

resource "aws_chatbot_teams_channel_configuration" "this" {
  count = var.enable_teams_integration ? 1 : 0

  configuration_name = "${var.name_prefix}-malware-alerts"
  iam_role_arn       = aws_iam_role.chatbot[0].arn
  tenant_id          = var.teams_tenant_id
  team_id            = var.teams_team_id
  channel_id         = var.teams_channel_id
  sns_topic_arns     = [module.file_router.sns_topic_arn]

  tags = var.tags
}

################################################################################
# PagerDuty Integration (SNS HTTPS Subscription)
################################################################################

resource "aws_sns_topic_subscription" "pagerduty" {
  count = var.pagerduty_integration_url != null ? 1 : 0

  topic_arn                       = module.file_router.sns_topic_arn
  protocol                        = "https"
  endpoint                        = var.pagerduty_integration_url
  endpoint_auto_confirms          = true
  raw_message_delivery            = false
  confirmation_timeout_in_minutes = 5

  delivery_policy = jsonencode({
    healthyRetryPolicy = {
      numRetries         = 3
      minDelayTarget     = 20
      maxDelayTarget     = 20
      backoffFunction    = "linear"
      numNoDelayRetries  = 0
      numMinDelayRetries = 0
      numMaxDelayRetries = 0
    }
  })
}

################################################################################
# VictorOps / Splunk On-Call Integration (SNS HTTPS Subscription)
################################################################################

resource "aws_sns_topic_subscription" "victorops" {
  count = var.victorops_integration_url != null ? 1 : 0

  topic_arn                       = module.file_router.sns_topic_arn
  protocol                        = "https"
  endpoint                        = var.victorops_integration_url
  endpoint_auto_confirms          = true
  raw_message_delivery            = false
  confirmation_timeout_in_minutes = 5

  delivery_policy = jsonencode({
    healthyRetryPolicy = {
      numRetries         = 3
      minDelayTarget     = 20
      maxDelayTarget     = 20
      backoffFunction    = "linear"
      numNoDelayRetries  = 0
      numMinDelayRetries = 0
      numMaxDelayRetries = 0
    }
  })
}

################################################################################
# Discord & ServiceNow — Webhook Forwarder Lambda
################################################################################

locals {
  enable_webhook_forwarder = var.enable_discord_integration || var.enable_servicenow_integration
}

resource "aws_ssm_parameter" "discord_webhook_url" {
  count = var.enable_discord_integration && var.discord_webhook_url != null ? 1 : 0

  name   = "/${var.name_prefix}/discord-webhook-url"
  type   = "SecureString"
  value  = var.discord_webhook_url
  key_id = local.kms_key_arn

  tags = var.tags
}

data "archive_file" "webhook_forwarder" {
  count = local.enable_webhook_forwarder ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/functions/webhook_forwarder/webhook_forwarder.py"
  output_path = "${path.module}/.build/webhook_forwarder.zip"
}

resource "aws_cloudwatch_log_group" "webhook_forwarder" {
  count = local.enable_webhook_forwarder ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-webhook-forwarder"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn
  tags              = var.tags
}

resource "aws_iam_role" "webhook_forwarder" {
  count = local.enable_webhook_forwarder ? 1 : 0

  name = "${var.name_prefix}-webhook-forwarder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "webhook_forwarder" {
  count = local.enable_webhook_forwarder ? 1 : 0

  name = "${var.name_prefix}-webhook-forwarder"
  role = aws_iam_role.webhook_forwarder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "CloudWatchLogs"
          Effect = "Allow"
          Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Resource = "${aws_cloudwatch_log_group.webhook_forwarder[0].arn}:*"
        },
        {
          Sid    = "KMSDecrypt"
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey",
          ]
          Resource = local.kms_key_arn
        },
      ],
      var.enable_discord_integration && var.discord_webhook_url != null ? [
        {
          Sid    = "SSMGetDiscordWebhook"
          Effect = "Allow"
          Action = [
            "ssm:GetParameter",
          ]
          Resource = aws_ssm_parameter.discord_webhook_url[0].arn
        },
      ] : [],
      var.enable_servicenow_integration && var.servicenow_credentials_secret_arn != null ? [
        {
          Sid    = "SecretsManagerRead"
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue",
          ]
          Resource = var.servicenow_credentials_secret_arn
        },
      ] : [],
    )
  })
}

resource "aws_lambda_function" "webhook_forwarder" {
  count = local.enable_webhook_forwarder ? 1 : 0

  function_name    = "${var.name_prefix}-webhook-forwarder"
  description      = "Forwards malware alert SNS notifications to Discord and/or ServiceNow"
  filename         = data.archive_file.webhook_forwarder[0].output_path
  source_code_hash = data.archive_file.webhook_forwarder[0].output_base64sha256
  handler          = "webhook_forwarder.handler"
  runtime          = var.lambda_runtime
  role             = aws_iam_role.webhook_forwarder[0].arn
  memory_size      = 128
  timeout          = 30

  kms_key_arn = local.kms_key_arn

  environment {
    variables = merge(
      var.enable_discord_integration && var.discord_webhook_url != null ? {
        DISCORD_WEBHOOK_SSM_PARAMETER = aws_ssm_parameter.discord_webhook_url[0].name
      } : {},
      var.enable_servicenow_integration && var.servicenow_instance_url != null ? {
        SERVICENOW_INSTANCE_URL           = var.servicenow_instance_url
        SERVICENOW_CREDENTIALS_SECRET_ARN = var.servicenow_credentials_secret_arn
      } : {},
    )
  }

  depends_on = [
    aws_iam_role_policy.webhook_forwarder,
    aws_cloudwatch_log_group.webhook_forwarder,
  ]

  tags = var.tags
}

resource "aws_sns_topic_subscription" "webhook_forwarder" {
  count = local.enable_webhook_forwarder ? 1 : 0

  topic_arn = module.file_router.sns_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.webhook_forwarder[0].arn
}

resource "aws_lambda_permission" "webhook_forwarder_sns" {
  count = local.enable_webhook_forwarder ? 1 : 0

  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.webhook_forwarder[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = module.file_router.sns_topic_arn
}
