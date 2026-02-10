data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Lambda Package
################################################################################

data "archive_file" "file_router" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/file_router.py"
  output_path = "${path.module}/../../.build/file_router.zip"
}

################################################################################
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "file_router" {
  name              = "/aws/lambda/${var.name_prefix}-file-router"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

################################################################################
# SQS Dead Letter Queue
################################################################################

resource "aws_sqs_queue" "dlq" {
  name                              = "${var.name_prefix}-file-router-dlq"
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = var.sqs_kms_data_key_reuse_seconds
  tags                              = var.tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "${var.name_prefix}-file-router-dlq-alarm"
  alarm_description   = "Alert when file-router Lambda dead letter queue has messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  alarm_actions = [aws_sns_topic.malware_alerts.arn]
  ok_actions    = [aws_sns_topic.malware_alerts.arn]

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name_prefix}-file-router-errors-alarm"
  alarm_description   = "Alert when file-router Lambda function has invocation errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.file_router.function_name
  }

  alarm_actions = [aws_sns_topic.malware_alerts.arn]
  ok_actions    = [aws_sns_topic.malware_alerts.arn]

  tags = var.tags
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

################################################################################
# SNS Topic
################################################################################

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

################################################################################
# IAM Role for Lambda
################################################################################

resource "aws_iam_role" "file_router" {
  name = "${var.name_prefix}-file-router"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
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
    Statement = concat(
      [
        {
          Sid    = "IngressBucketRead"
          Effect = "Allow"
          Action = [
            "s3:GetObject",
            "s3:GetObjectTagging",
            "s3:HeadObject",
            "s3:DeleteObject",
          ]
          Resource = "${var.ingress_bucket_arn}/*"
        },
        {
          Sid    = "EgressBucketWrite"
          Effect = "Allow"
          Action = [
            "s3:PutObject",
            "s3:PutObjectTagging",
          ]
          Resource = "${var.egress_bucket_arn}/*"
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
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Resource = "${aws_cloudwatch_log_group.file_router.arn}:*"
        },
      ],
      var.prompt_injection_scanner_function_arn != null ? [
        {
          Sid      = "InvokeScannerLambda"
          Effect   = "Allow"
          Action   = "lambda:InvokeFunction"
          Resource = var.prompt_injection_scanner_function_arn
        },
      ] : [],
    )
  })
}

################################################################################
# Lambda Function
################################################################################

resource "aws_lambda_function" "file_router" {
  function_name    = "${var.name_prefix}-file-router"
  description      = "Routes files based on GuardDuty Malware Protection scan results"
  filename         = data.archive_file.file_router.output_path
  source_code_hash = data.archive_file.file_router.output_base64sha256
  handler          = "file_router.handler"
  runtime          = var.lambda_runtime
  role             = aws_iam_role.file_router.arn
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  kms_key_arn = var.kms_key_arn

  environment {
    variables = merge(
      {
        INGRESS_BUCKET    = var.ingress_bucket_name
        EGRESS_BUCKET     = var.egress_bucket_name
        QUARANTINE_BUCKET = var.quarantine_bucket_name
        SNS_TOPIC_ARN     = aws_sns_topic.malware_alerts.arn
        KMS_KEY_ARN       = var.kms_key_arn
      },
      var.prompt_injection_scanner_function_arn != null ? {
        SCANNER_FUNCTION_NAME      = regex("function:(.+)$", var.prompt_injection_scanner_function_arn)[0]
        PROMPT_INJECTION_THRESHOLD = tostring(var.prompt_injection_threshold)
      } : {},
    )
  }

  depends_on = [
    aws_iam_role_policy.file_router,
    aws_cloudwatch_log_group.file_router,
  ]

  tags = var.tags
}

################################################################################
# EventBridge Rule
################################################################################

resource "aws_cloudwatch_event_rule" "scan_result" {
  name        = "${var.name_prefix}-malware-scan-result"
  description = "Captures GuardDuty Malware Protection scan results"

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

################################################################################
# CloudWatch Dashboard (optional)
################################################################################

locals {
  dashboard_namespace = "${var.name_prefix}/SecureUpload"
}

resource "aws_cloudwatch_log_metric_filter" "files_routed_to_egress" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  name           = "${var.name_prefix}-files-routed-to-egress"
  log_group_name = aws_cloudwatch_log_group.file_router.name
  pattern        = "\"File routed to egress bucket\""

  metric_transformation {
    name      = "FilesRoutedToEgress"
    namespace = local.dashboard_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "files_quarantined" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  name           = "${var.name_prefix}-files-quarantined"
  log_group_name = aws_cloudwatch_log_group.file_router.name
  pattern        = "\"File routed to quarantine bucket\""

  metric_transformation {
    name      = "FilesQuarantined"
    namespace = local.dashboard_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "files_left_for_review" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  name           = "${var.name_prefix}-files-left-for-review"
  log_group_name = aws_cloudwatch_log_group.file_router.name
  pattern        = "\"leaving for manual review\""

  metric_transformation {
    name      = "FilesLeftForReview"
    namespace = local.dashboard_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "scan_events_skipped" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  name           = "${var.name_prefix}-scan-events-skipped"
  log_group_name = aws_cloudwatch_log_group.file_router.name
  pattern        = "\"Unexpected scanStatus\""

  metric_transformation {
    name      = "ScanEventsSkipped"
    namespace = local.dashboard_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "prompt_injection_scans" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  name           = "${var.name_prefix}-prompt-injection-scans"
  log_group_name = aws_cloudwatch_log_group.file_router.name
  pattern        = "\"Prompt injection scan result\""

  metric_transformation {
    name      = "PromptInjectionScans"
    namespace = local.dashboard_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "prompt_injection_detections" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  name           = "${var.name_prefix}-prompt-injection-detections"
  log_group_name = aws_cloudwatch_log_group.file_router.name
  pattern        = "\"Prompt injection detected\""

  metric_transformation {
    name      = "PromptInjectionDetections"
    namespace = local.dashboard_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_dashboard" "pipeline" {
  count = var.enable_cloudwatch_dashboard ? 1 : 0

  dashboard_name = "${var.name_prefix}-secure-upload"

  dashboard_body = jsonencode({
    widgets = concat(
      [
        {
          type   = "metric"
          x      = 0
          y      = 0
          width  = 12
          height = 6
          properties = {
            title  = "File Routing Outcomes"
            region = data.aws_region.current.name
            metrics = [
              [local.dashboard_namespace, "FilesRoutedToEgress", { label = "Egress (clean)", color = "#2ca02c" }],
              [local.dashboard_namespace, "FilesQuarantined", { label = "Quarantined (malware)", color = "#d62728" }],
              [local.dashboard_namespace, "FilesLeftForReview", { label = "Left for Review", color = "#ff7f0e" }],
              [local.dashboard_namespace, "ScanEventsSkipped", { label = "Skipped (unexpected)", color = "#9467bd" }],
            ]
            view    = "timeSeries"
            stacked = false
            period  = 300
            stat    = "Sum"
          }
        },
        {
          type   = "metric"
          x      = 12
          y      = 0
          width  = 12
          height = 6
          properties = {
            title  = "Routing Summary (24h)"
            region = data.aws_region.current.name
            metrics = [
              [local.dashboard_namespace, "FilesRoutedToEgress", { label = "Egress", color = "#2ca02c" }],
              [local.dashboard_namespace, "FilesQuarantined", { label = "Quarantined", color = "#d62728" }],
              [local.dashboard_namespace, "FilesLeftForReview", { label = "Review", color = "#ff7f0e" }],
            ]
            view   = "singleValue"
            period = 86400
            stat   = "Sum"
          }
        },
        {
          type   = "metric"
          x      = 0
          y      = 6
          width  = 12
          height = 6
          properties = {
            title  = "Lambda Invocations & Errors"
            region = data.aws_region.current.name
            metrics = [
              ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.file_router.function_name, { label = "Invocations", color = "#1f77b4" }],
              ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.file_router.function_name, { label = "Errors", color = "#d62728" }],
              ["AWS/Lambda", "Throttles", "FunctionName", aws_lambda_function.file_router.function_name, { label = "Throttles", color = "#ff7f0e" }],
            ]
            view    = "timeSeries"
            stacked = false
            period  = 300
            stat    = "Sum"
          }
        },
        {
          type   = "metric"
          x      = 12
          y      = 6
          width  = 12
          height = 6
          properties = {
            title  = "Lambda Duration"
            region = data.aws_region.current.name
            metrics = [
              ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.file_router.function_name, { label = "Average", stat = "Average", color = "#1f77b4" }],
              ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.file_router.function_name, { label = "p99", stat = "p99", color = "#d62728" }],
            ]
            view    = "timeSeries"
            stacked = false
            period  = 300
          }
        },
      ],
      var.prompt_injection_scanner_function_name != null ? [
        {
          type   = "metric"
          x      = 0
          y      = 12
          width  = 12
          height = 6
          properties = {
            title  = "Prompt Injection Scan Outcomes"
            region = data.aws_region.current.name
            metrics = [
              [local.dashboard_namespace, "PromptInjectionScans", { label = "Files Scanned", color = "#1f77b4" }],
              [local.dashboard_namespace, "PromptInjectionDetections", { label = "Injections Detected", color = "#d62728" }],
            ]
            view    = "timeSeries"
            stacked = false
            period  = 300
            stat    = "Sum"
          }
        },
      ] : [],
      var.prompt_injection_scanner_function_name != null ? [
        {
          type   = "metric"
          x      = 12
          y      = 12
          width  = 12
          height = 6
          properties = {
            title  = "Prompt Injection Summary (24h)"
            region = data.aws_region.current.name
            metrics = [
              [local.dashboard_namespace, "PromptInjectionScans", { label = "Files Scanned", color = "#1f77b4" }],
              [local.dashboard_namespace, "PromptInjectionDetections", { label = "Injections Detected", color = "#d62728" }],
            ]
            view   = "singleValue"
            period = 86400
            stat   = "Sum"
          }
        },
      ] : [],
      var.prompt_injection_scanner_function_name != null ? [
        {
          type   = "metric"
          x      = 0
          y      = 18
          width  = 12
          height = 6
          properties = {
            title  = "Scanner Lambda Performance"
            region = data.aws_region.current.name
            metrics = [
              ["AWS/Lambda", "Invocations", "FunctionName", var.prompt_injection_scanner_function_name, { label = "Invocations", color = "#1f77b4" }],
              ["AWS/Lambda", "Errors", "FunctionName", var.prompt_injection_scanner_function_name, { label = "Errors", color = "#d62728" }],
              ["AWS/Lambda", "Duration", "FunctionName", var.prompt_injection_scanner_function_name, { label = "Avg Duration", stat = "Average", color = "#2ca02c" }],
              ["AWS/Lambda", "Duration", "FunctionName", var.prompt_injection_scanner_function_name, { label = "p99 Duration", stat = "p99", color = "#ff7f0e" }],
            ]
            view    = "timeSeries"
            stacked = false
            period  = 300
            stat    = "Sum"
          }
        },
      ] : [],
      [
        {
          type   = "metric"
          x      = 0
          y      = var.prompt_injection_scanner_function_name != null ? 24 : 12
          width  = 8
          height = 6
          properties = {
            title  = "Dead Letter Queue"
            region = data.aws_region.current.name
            metrics = [
              ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.dlq.name, { label = "Messages Visible", color = "#d62728" }],
              ["AWS/SQS", "NumberOfMessagesSent", "QueueName", aws_sqs_queue.dlq.name, { label = "Messages Sent", color = "#ff7f0e" }],
            ]
            view    = "timeSeries"
            stacked = false
            period  = 300
            stat    = "Sum"
          }
        },
        {
          type   = "metric"
          x      = 8
          y      = var.prompt_injection_scanner_function_name != null ? 24 : 12
          width  = 8
          height = 6
          properties = {
            title  = "S3 Object Counts"
            region = data.aws_region.current.name
            metrics = [
              ["AWS/S3", "NumberOfObjects", "BucketName", var.ingress_bucket_name, "StorageType", "AllStorageTypes", { label = "Ingress", color = "#1f77b4" }],
              ["AWS/S3", "NumberOfObjects", "BucketName", var.egress_bucket_name, "StorageType", "AllStorageTypes", { label = "Egress", color = "#2ca02c" }],
              ["AWS/S3", "NumberOfObjects", "BucketName", var.quarantine_bucket_name, "StorageType", "AllStorageTypes", { label = "Quarantine", color = "#d62728" }],
            ]
            view    = "timeSeries"
            stacked = false
            stat    = "Average"
          }
        },
        {
          type   = "metric"
          x      = 16
          y      = var.prompt_injection_scanner_function_name != null ? 24 : 12
          width  = 8
          height = 6
          properties = {
            title  = "S3 Bucket Sizes"
            region = data.aws_region.current.name
            metrics = [
              ["AWS/S3", "BucketSizeBytes", "BucketName", var.ingress_bucket_name, "StorageType", "StandardStorage", { label = "Ingress", color = "#1f77b4" }],
              ["AWS/S3", "BucketSizeBytes", "BucketName", var.egress_bucket_name, "StorageType", "StandardStorage", { label = "Egress", color = "#2ca02c" }],
              ["AWS/S3", "BucketSizeBytes", "BucketName", var.quarantine_bucket_name, "StorageType", "StandardStorage", { label = "Quarantine", color = "#d62728" }],
            ]
            view    = "timeSeries"
            stacked = false
            stat    = "Average"
          }
        },
      ],
    )
  })
}
