terraform {
  required_version = ">= 1.9"
}

provider "aws" {
  region = var.aws_region
}

locals {
  name_prefix = "terratest-full-${var.test_id}"
}

module "secure_upload" {
  source = "../../../"

  name_prefix                 = local.name_prefix
  create_kms_key              = false
  kms_key_arn                 = var.kms_key_arn
  enable_sftp                 = true
  sftp_vpc_id                 = var.sftp_vpc_id
  sftp_subnet_ids             = var.sftp_subnet_ids
  sftp_address_allocation_ids = var.sftp_address_allocation_ids
  sftp_allowed_cidrs          = var.sftp_allowed_cidrs
  sftp_custom_hostname        = var.sftp_custom_hostname
  sftp_route53_hosted_zone_id = var.sftp_route53_hosted_zone_id
  sftp_users                  = jsondecode(var.sftp_users_json)

  tags = {
    Environment = "integration-test"
    ManagedBy   = "terratest"
    TestID      = var.test_id
  }
}

output "name_prefix" {
  value = local.name_prefix
}

output "ingress_bucket_id" {
  value = module.secure_upload.ingress_bucket_id
}

output "clean_bucket_id" {
  value = module.secure_upload.clean_bucket_id
}

output "quarantine_bucket_id" {
  value = module.secure_upload.quarantine_bucket_id
}

output "s3_access_log_group_name" {
  value = module.secure_upload.s3_access_log_group_name
}

output "sns_topic_arn" {
  value = module.secure_upload.sns_topic_arn
}

output "lambda_function_arn" {
  value = module.secure_upload.lambda_function_arn
}

output "sftp_server_id" {
  value = module.secure_upload.sftp_server_id
}

output "sftp_server_endpoint" {
  value = module.secure_upload.sftp_server_endpoint
}

output "sftp_hostname" {
  value = module.secure_upload.sftp_hostname
}

output "sftp_user_arns" {
  value = module.secure_upload.sftp_user_arns
}
