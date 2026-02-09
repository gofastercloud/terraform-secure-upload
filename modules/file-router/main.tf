data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ------------------------------------------------------------------------------
# Lambda Package
# ------------------------------------------------------------------------------

data "archive_file" "file_router" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/file_router.py"
  output_path = "${path.module}/../../.build/file_router.zip"
}

# ------------------------------------------------------------------------------
# CloudWatch Log Group
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "file_router" {
  name              = "/aws/lambda/${var.name_prefix}-file-router"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# ------------------------------------------------------------------------------
# SQS Dead Letter Queue
# ------------------------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name                       = "${var.name_prefix}-file-router-dlq"
  kms_master_key_id          = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  tags                       = var.tags
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambdaDLQ"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.dlq.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_lambda_function.file_router.arn
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# SNS Topic
# ------------------------------------------------------------------------------

resource "aws_sns_topic" "malware_alerts" {
  name              = "${var.name_prefix}-malware-alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic_policy" "malware_alerts" {
  arn = aws_sns_topic.malware_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountOnly"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = [
          "SNS:Publish",
          "SNS:Subscribe",
          "SNS:GetTopicAttributes",
        ]
        Resource = aws_sns_topic.malware_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.sns_subscription_emails)

  topic_arn = aws_sns_topic.malware_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# ------------------------------------------------------------------------------
# IAM Role for Lambda
# ------------------------------------------------------------------------------

resource "aws_iam_role" "file_router" {
  name = "${var.name_prefix}-file-router"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "file_router" {
  name = "${var.name_prefix}-file-router"
  role = aws_iam_role.file_router.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StagingBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectTagging",
          "s3:DeleteObject",
        ]
        Resource = "${var.staging_bucket_arn}/*"
      },
      {
        Sid    = "CleanBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectTagging",
        ]
        Resource = "${var.clean_bucket_arn}/*"
      },
      {
        Sid    = "QuarantineBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectTagging",
        ]
        Resource = "${var.quarantine_bucket_arn}/*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.malware_alerts.arn
      },
      {
        Sid      = "DLQSend"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.dlq.arn
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.file_router.arn}:*"
      },
    ]
  })
}

# ------------------------------------------------------------------------------
# Lambda Function
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "file_router" {
  function_name    = "${var.name_prefix}-file-router"
  description      = "Routes files based on GuardDuty Malware Protection scan results"
  filename         = data.archive_file.file_router.output_path
  source_code_hash = data.archive_file.file_router.output_base64sha256
  handler          = "file_router.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.file_router.arn
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  kms_key_arn = var.kms_key_arn

  environment {
    variables = {
      CLEAN_BUCKET      = var.clean_bucket_name
      QUARANTINE_BUCKET = var.quarantine_bucket_name
      SNS_TOPIC_ARN     = aws_sns_topic.malware_alerts.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.file_router,
    aws_cloudwatch_log_group.file_router,
  ]

  tags = var.tags
}

# ------------------------------------------------------------------------------
# EventBridge Rule
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "scan_result" {
  name        = "${var.name_prefix}-malware-scan-result"
  description = "Captures GuardDuty Malware Protection scan results"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Malware Protection Object Scan Result"]
    detail = {
      s3ObjectDetails = {
        bucketName = [var.staging_bucket_name]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.scan_result.name
  arn  = aws_lambda_function.file_router.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.file_router.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_result.arn
}
