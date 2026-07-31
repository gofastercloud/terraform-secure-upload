resource "aws_kms_key" "this" {
  count = var.create_kms_key && var.kms_key_arn == null ? 1 : 0

  description             = "${var.name_prefix} secure upload encryption key"
  deletion_window_in_days = var.kms_key_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowServiceUsage"
        Effect = "Allow"
        Principal = {
          Service = [
            "guardduty.amazonaws.com",
            "lambda.amazonaws.com",
            "s3.amazonaws.com",
            "sns.amazonaws.com",
            "sqs.amazonaws.com",
            "events.amazonaws.com",
            "transfer.amazonaws.com",
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
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

  tags = local.default_tags
}

resource "aws_kms_alias" "this" {
  count = var.create_kms_key && var.kms_key_arn == null ? 1 : 0

  name          = "alias/${var.name_prefix}-secure-upload"
  target_key_id = aws_kms_key.this[0].key_id
}

module "s3_buckets" {
  source = "./modules/s3-buckets"

  name_prefix        = var.name_prefix
  tags               = local.default_tags
  kms_key_arn        = local.kms_key_arn
  log_retention_days = var.log_retention_days

  ingress_object_expiration_days             = var.ingress_object_expiration_days
  ingress_noncurrent_version_expiration_days = var.ingress_noncurrent_version_expiration_days
}

module "guardduty_protection" {
  source = "./modules/guardduty-protection"

  name_prefix         = var.name_prefix
  ingress_bucket_name = module.s3_buckets.ingress_bucket_id
  ingress_bucket_arn  = module.s3_buckets.ingress_bucket_arn
  kms_key_arn         = local.kms_key_arn
  tags                = local.default_tags
}

module "file_router" {
  source = "./modules/file-router"

  name_prefix                 = var.name_prefix
  tags                        = local.default_tags
  kms_key_arn                 = local.kms_key_arn
  ingress_bucket_name         = module.s3_buckets.ingress_bucket_id
  ingress_bucket_arn          = module.s3_buckets.ingress_bucket_arn
  clean_bucket_name           = module.s3_buckets.clean_bucket_id
  clean_bucket_arn            = module.s3_buckets.clean_bucket_arn
  quarantine_bucket_name      = module.s3_buckets.quarantine_bucket_id
  quarantine_bucket_arn       = module.s3_buckets.quarantine_bucket_arn
  lambda_runtime              = var.lambda_runtime
  lambda_memory_size          = var.lambda_memory_size
  lambda_timeout              = var.lambda_timeout
  lambda_reserved_concurrency = var.lambda_reserved_concurrency
  log_retention_days          = var.log_retention_days
}

module "sftp" {
  source = "./modules/sftp"
  count  = var.enable_sftp ? 1 : 0

  name_prefix            = var.name_prefix
  tags                   = local.default_tags
  kms_key_arn            = local.kms_key_arn
  vpc_id                 = var.sftp_vpc_id
  subnet_ids             = var.sftp_subnet_ids
  address_allocation_ids = var.sftp_address_allocation_ids
  allowed_cidrs          = var.sftp_allowed_cidrs
  custom_hostname        = var.sftp_custom_hostname
  route53_hosted_zone_id = var.sftp_route53_hosted_zone_id
  bucket_name            = module.s3_buckets.ingress_bucket_id
  bucket_arn             = module.s3_buckets.ingress_bucket_arn
  sftp_users             = var.sftp_users
}
