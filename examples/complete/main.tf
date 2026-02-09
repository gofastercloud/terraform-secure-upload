provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix = var.name_prefix

  # KMS — bring your own key
  kms_key_arn = var.kms_key_arn

  # S3 lifecycle
  staging_lifecycle_days    = var.staging_lifecycle_days
  clean_lifecycle_days      = var.clean_lifecycle_days
  quarantine_lifecycle_days = var.quarantine_lifecycle_days
  enable_object_lock        = var.enable_object_lock

  # Lambda tuning
  lambda_memory_size          = var.lambda_memory_size
  lambda_timeout              = var.lambda_timeout
  lambda_reserved_concurrency = var.lambda_reserved_concurrency

  # Notifications
  sns_subscription_emails = var.sns_subscription_emails

  # Logging
  log_retention_days = var.log_retention_days

  # SFTP with VPC endpoint
  enable_sftp        = true
  create_sftp_server = true
  sftp_endpoint_type = "VPC"
  sftp_vpc_id        = var.vpc_id
  sftp_subnet_ids    = var.subnet_ids
  sftp_users         = var.sftp_users

  tags = var.tags
}
