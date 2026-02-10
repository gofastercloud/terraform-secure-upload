################################################################################
# KMS Key (created only when the caller does not supply one)
################################################################################

resource "aws_kms_key" "this" {
  count = var.create_kms_key && var.kms_key_arn == null ? 1 : 0

  description             = "${var.name_prefix} secure-upload encryption key"
  deletion_window_in_days = var.kms_key_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow the owning account key management
      {
        Sid    = "AllowAccountManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      # Allow AWS services that need to use this key (scoped to this account)
      {
        Sid    = "AllowServiceUsage"
        Effect = "Allow"
        Principal = {
          Service = [
            "guardduty.amazonaws.com",
            "lambda.amazonaws.com",
            "s3.amazonaws.com",
            "transfer.amazonaws.com",
            "sns.amazonaws.com",
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      # CloudWatch Logs uses a regional service principal and requires
      # a different condition key (encryption context) than other services.
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${local.region}:${local.account_id}:log-group:*"
          }
        }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }

  tags = local.default_tags
}

resource "aws_kms_alias" "this" {
  count = var.create_kms_key && var.kms_key_arn == null ? 1 : 0

  name          = "alias/${var.name_prefix}-secure-upload"
  target_key_id = aws_kms_key.this[0].key_id
}

################################################################################
# S3 Buckets — ingress, egress, quarantine, and access-log buckets
################################################################################

module "s3_buckets" {
  source = "./modules/s3-buckets"

  name_prefix                = var.name_prefix
  tags                       = local.default_tags
  kms_key_arn                = local.kms_key_arn
  create_log_bucket          = var.create_log_bucket
  external_log_bucket_id     = var.log_bucket_name
  ingress_lifecycle_days     = var.ingress_lifecycle_days
  egress_lifecycle_days      = var.egress_lifecycle_days
  quarantine_lifecycle_days  = var.quarantine_lifecycle_days
  log_retention_days         = var.s3_log_retention_days
  enable_object_lock         = var.enable_object_lock
  object_lock_retention_days = var.object_lock_retention_days
  object_lock_retention_mode = var.object_lock_retention_mode
}

################################################################################
# GuardDuty Malware Protection for S3
################################################################################

module "guardduty_protection" {
  source = "./modules/guardduty-protection"

  name_prefix         = var.name_prefix
  ingress_bucket_name = module.s3_buckets.ingress_bucket_id
  ingress_bucket_arn  = module.s3_buckets.ingress_bucket_arn
  kms_key_arn         = local.kms_key_arn
  tags                = local.default_tags
}

################################################################################
# File Router — Lambda that moves objects based on scan results
################################################################################

module "file_router" {
  source = "./modules/file-router"

  name_prefix                 = var.name_prefix
  tags                        = local.default_tags
  kms_key_arn                 = local.kms_key_arn
  ingress_bucket_name         = module.s3_buckets.ingress_bucket_id
  ingress_bucket_arn          = module.s3_buckets.ingress_bucket_arn
  egress_bucket_name          = module.s3_buckets.egress_bucket_id
  egress_bucket_arn           = module.s3_buckets.egress_bucket_arn
  quarantine_bucket_name      = module.s3_buckets.quarantine_bucket_id
  quarantine_bucket_arn       = module.s3_buckets.quarantine_bucket_arn
  lambda_runtime              = var.lambda_runtime
  lambda_memory_size          = var.lambda_memory_size
  lambda_timeout              = var.enable_prompt_injection_scanning ? max(var.lambda_timeout, var.prompt_injection_timeout + 30) : var.lambda_timeout
  lambda_reserved_concurrency = var.lambda_reserved_concurrency
  sns_subscription_emails     = var.sns_subscription_emails
  log_retention_days          = var.log_retention_days
  enable_cloudwatch_dashboard = var.enable_cloudwatch_dashboard

  prompt_injection_scanner_function_arn = var.enable_prompt_injection_scanning ? aws_lambda_function.prompt_injection_scanner[0].arn : null
  prompt_injection_threshold            = var.prompt_injection_threshold
}

################################################################################
# SFTP — AWS Transfer Family (conditional)
################################################################################

module "sftp_ingress" {
  source = "./modules/sftp"
  count  = var.enable_sftp_ingress ? 1 : 0

  name_prefix        = "${var.name_prefix}-ingress"
  tags               = merge(local.default_tags, { Direction = "ingress" })
  kms_key_arn        = local.kms_key_arn
  create_sftp_server = var.create_sftp_ingress_server
  existing_server_id = var.sftp_ingress_server_id
  endpoint_type      = var.sftp_ingress_endpoint_type
  vpc_id             = var.sftp_ingress_vpc_id
  subnet_ids         = var.sftp_ingress_subnet_ids
  allowed_cidrs      = var.sftp_ingress_allowed_cidrs
  bucket_name        = module.s3_buckets.ingress_bucket_id
  bucket_arn         = module.s3_buckets.ingress_bucket_arn
  sftp_users         = var.sftp_ingress_users
}

################################################################################
# SFTP Egress — Read-only access to the egress bucket
################################################################################

module "sftp_egress" {
  source = "./modules/sftp"
  count  = var.enable_sftp_egress ? 1 : 0

  name_prefix        = "${var.name_prefix}-egress"
  tags               = merge(local.default_tags, { Direction = "egress" })
  kms_key_arn        = local.kms_key_arn
  create_sftp_server = var.create_sftp_egress_server
  existing_server_id = var.sftp_egress_server_id
  endpoint_type      = var.sftp_egress_endpoint_type
  vpc_id             = var.sftp_egress_vpc_id
  subnet_ids         = var.sftp_egress_subnet_ids
  allowed_cidrs      = var.sftp_egress_allowed_cidrs
  bucket_name        = module.s3_buckets.egress_bucket_id
  bucket_arn         = module.s3_buckets.egress_bucket_arn
  read_only          = true
  sftp_users         = var.sftp_egress_users
}
