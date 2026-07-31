data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "file_router" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/file_router.py"
  output_path = "${path.module}/../../.build/file_router.zip"
}

resource "aws_cloudwatch_log_group" "file_router" {
  name              = "/aws/lambda/${var.name_prefix}-scan-router"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sqs_queue" "dlq" {
  name                              = "${var.name_prefix}-scan-router-dlq"
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  tags                              = var.tags
}

resource "aws_sns_topic" "notifications" {
  name              = "${var.name_prefix}-notifications"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "file_router_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "file_router" {
  name               = "${var.name_prefix}-scan-router"
  assume_role_policy = data.aws_iam_policy_document.file_router_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "file_router" {
  name = "${var.name_prefix}-scan-router"
  role = aws_iam_role.file_router.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IngressObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:DeleteObjectVersion",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectVersionTagging",
        ]
        Resource = "${var.ingress_bucket_arn}/*"
      },
      {
        Sid    = "DestinationObjectWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectTagging",
        ]
        Resource = [
          "${var.clean_bucket_arn}/*",
          "${var.quarantine_bucket_arn}/*",
        ]
      },
      {
        Sid      = "PublishNotifications"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.notifications.arn
      },
      {
        Sid      = "SendToDeadLetterQueue"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.dlq.arn
      },
      {
        Sid    = "UseKmsKey"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid      = "CreateLogGroup"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup"]
        Resource = "*"
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.file_router.arn}:*"
      },
    ]
  })
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambdaDeadLetterDelivery"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.dlq.arn
        Condition = { ArnEquals = { "aws:SourceArn" = aws_lambda_function.file_router.arn } }
      },
      {
        Sid       = "AllowEventBridgeDeadLetterDelivery"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.dlq.arn
        Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.scan_result.arn } }
      },
    ]
  })
}

resource "aws_sns_topic_policy" "notifications" {
  arn = aws_sns_topic.notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAccountPublishAndSubscribe"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = ["SNS:GetTopicAttributes", "SNS:Publish", "SNS:Subscribe"]
      Resource  = aws_sns_topic.notifications.arn
    }]
  })
}

resource "aws_lambda_function" "file_router" {
  function_name                  = "${var.name_prefix}-scan-router"
  description                    = "Routes GuardDuty Malware Protection scan results"
  filename                       = data.archive_file.file_router.output_path
  source_code_hash               = data.archive_file.file_router.output_base64sha256
  handler                        = "file_router.handler"
  runtime                        = var.lambda_runtime
  role                           = aws_iam_role.file_router.arn
  memory_size                    = var.lambda_memory_size
  timeout                        = var.lambda_timeout
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  kms_key_arn                    = var.kms_key_arn

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      INGRESS_BUCKET    = var.ingress_bucket_name
      CLEAN_BUCKET      = var.clean_bucket_name
      QUARANTINE_BUCKET = var.quarantine_bucket_name
      SNS_TOPIC_ARN     = aws_sns_topic.notifications.arn
      KMS_KEY_ARN       = var.kms_key_arn
    }
  }

  depends_on = [
    aws_iam_role_policy.file_router,
    aws_cloudwatch_log_group.file_router,
  ]

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "scan_result" {
  name        = "${var.name_prefix}-malware-scan-result"
  description = "Routes GuardDuty Malware Protection for S3 scan results"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Malware Protection Object Scan Result"]
    detail = {
      s3ObjectDetails = {
        bucketName = [var.ingress_bucket_name]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.scan_result.name
  arn  = aws_lambda_function.file_router.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.file_router.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_result.arn
}
