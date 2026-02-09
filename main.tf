##############################################################################
# KMS Key (created only when the caller does not supply one)
##############################################################################

resource "aws_kms_key" "this" {
  count = var.kms_key_arn == null ? 1 : 0

  description             = "${var.name_prefix} secure-upload encryption key"
  deletion_window_in_days = 30
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
      # Allow AWS services that need to use this key
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
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = local.default_tags
}

resource "aws_kms_alias" "this" {
  count = var.kms_key_arn == null ? 1 : 0

  name          = "alias/${var.name_prefix}-secure-upload"
  target_key_id = aws_kms_key.this[0].key_id
}

##############################################################################
# S3 Buckets — staging, clean, quarantine, and access-log buckets
##############################################################################

module "s3_buckets" {
  source = "./modules/s3-buckets"

  name_prefix              = var.name_prefix
  tags                     = local.default_tags
  kms_key_arn              = local.kms_key_arn
  staging_lifecycle_days   = var.staging_lifecycle_days
  clean_lifecycle_days     = var.clean_lifecycle_days
  quarantine_lifecycle_days = var.quarantine_lifecycle_days
  enable_object_lock       = var.enable_object_lock
}

##############################################################################
# GuardDuty Malware Protection for S3
##############################################################################

module "guardduty_protection" {
  source = "./modules/guardduty-protection"

  name_prefix         = var.name_prefix
  staging_bucket_name = module.s3_buckets.staging_bucket_id
  staging_bucket_arn  = module.s3_buckets.staging_bucket_arn
  kms_key_arn         = local.kms_key_arn
  tags                = local.default_tags
}

##############################################################################
# File Router — Lambda that moves objects based on scan results
##############################################################################

module "file_router" {
  source = "./modules/file-router"

  name_prefix             = var.name_prefix
  tags                    = local.default_tags
  kms_key_arn             = local.kms_key_arn
  staging_bucket_name     = module.s3_buckets.staging_bucket_id
  staging_bucket_arn      = module.s3_buckets.staging_bucket_arn
  clean_bucket_name       = module.s3_buckets.clean_bucket_id
  clean_bucket_arn        = module.s3_buckets.clean_bucket_arn
  quarantine_bucket_name  = module.s3_buckets.quarantine_bucket_id
  quarantine_bucket_arn   = module.s3_buckets.quarantine_bucket_arn
  lambda_memory_size      = var.lambda_memory_size
  lambda_timeout          = var.lambda_timeout
  lambda_reserved_concurrency = var.lambda_reserved_concurrency
  sns_subscription_emails = var.sns_subscription_emails
  log_retention_days      = var.log_retention_days
}

##############################################################################
# SFTP — AWS Transfer Family (conditional)
##############################################################################

module "sftp" {
  source = "./modules/sftp"
  count  = var.enable_sftp ? 1 : 0

  name_prefix        = var.name_prefix
  tags               = local.default_tags
  kms_key_arn        = local.kms_key_arn
  create_sftp_server = var.create_sftp_server
  existing_server_id  = var.sftp_server_id
  endpoint_type       = var.sftp_endpoint_type
  vpc_id              = var.sftp_vpc_id
  subnet_ids          = var.sftp_subnet_ids
  allowed_cidrs       = var.sftp_allowed_cidrs
  staging_bucket_name = module.s3_buckets.staging_bucket_id
  staging_bucket_arn  = module.s3_buckets.staging_bucket_arn
  sftp_users         = var.sftp_users
}
