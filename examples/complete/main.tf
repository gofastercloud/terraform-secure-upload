provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix = var.name_prefix

  # KMS — bring your own key or let the module create one
  create_kms_key = var.kms_key_arn != null ? false : true
  kms_key_arn    = var.kms_key_arn

  # S3 lifecycle
  ingress_lifecycle_days    = var.ingress_lifecycle_days
  egress_lifecycle_days     = var.egress_lifecycle_days
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
  enable_sftp_ingress        = true
  create_sftp_ingress_server = true
  sftp_ingress_endpoint_type = "VPC"
  sftp_ingress_vpc_id        = var.vpc_id
  sftp_ingress_subnet_ids    = var.subnet_ids
  sftp_ingress_allowed_cidrs = var.sftp_ingress_allowed_cidrs
  sftp_ingress_users         = var.sftp_ingress_users

  # SFTP Egress — read-only access to egress bucket
  enable_sftp_egress        = var.enable_sftp_egress
  create_sftp_egress_server = var.create_sftp_egress_server
  sftp_egress_endpoint_type = "PUBLIC"
  sftp_egress_users         = var.sftp_egress_users

  tags = var.tags
}
