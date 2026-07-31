provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix = var.name_prefix

  # KMS — bring your own key or let the module create one
  create_kms_key = var.kms_key_arn != null ? false : true
  kms_key_arn    = var.kms_key_arn

  lambda_memory_size          = var.lambda_memory_size
  lambda_timeout              = var.lambda_timeout
  lambda_reserved_concurrency = var.lambda_reserved_concurrency

  log_retention_days = var.log_retention_days

  enable_sftp                 = true
  sftp_vpc_id                 = var.vpc_id
  sftp_subnet_ids             = var.subnet_ids
  sftp_address_allocation_ids = var.address_allocation_ids
  sftp_allowed_cidrs          = var.sftp_allowed_cidrs
  sftp_custom_hostname        = var.sftp_custom_hostname
  sftp_route53_hosted_zone_id = var.sftp_route53_hosted_zone_id
  sftp_users                  = var.sftp_users

  tags = var.tags
}
