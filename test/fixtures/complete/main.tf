terraform {
  required_version = ">= 1.9"
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "test_id" {
  type = string
}

module "secure_upload" {
  source = "../../../"

  name_prefix                 = "terratest-full-${var.test_id}"
  enable_sftp                 = false
  lambda_memory_size          = 512
  lambda_timeout              = 120
  lambda_reserved_concurrency = -1
  log_retention_days          = 30

  tags = {
    Environment = "test"
    ManagedBy   = "terratest"
    TestID      = var.test_id
  }
}

output "ingress_bucket_id" {
  value = module.secure_upload.ingress_bucket_id
}

output "ingress_bucket_arn" {
  value = module.secure_upload.ingress_bucket_arn
}

output "clean_bucket_id" {
  value = module.secure_upload.clean_bucket_id
}

output "clean_bucket_arn" {
  value = module.secure_upload.clean_bucket_arn
}

output "quarantine_bucket_id" {
  value = module.secure_upload.quarantine_bucket_id
}

output "quarantine_bucket_arn" {
  value = module.secure_upload.quarantine_bucket_arn
}

output "log_bucket_id" {
  value = module.secure_upload.log_bucket_id
}

output "log_bucket_arn" {
  value = module.secure_upload.log_bucket_arn
}

output "kms_key_arn" {
  value = module.secure_upload.kms_key_arn
}

output "sns_topic_arn" {
  value = module.secure_upload.sns_topic_arn
}

output "lambda_function_arn" {
  value = module.secure_upload.lambda_function_arn
}

output "guardduty_protection_plan_arn" {
  value = module.secure_upload.guardduty_protection_plan_arn
}

output "sftp_server_id" {
  value = module.secure_upload.sftp_server_id
}

output "sftp_server_endpoint" {
  value = module.secure_upload.sftp_server_endpoint
}

output "sftp_user_arns" {
  value = module.secure_upload.sftp_user_arns
}

output "dlq_arn" {
  value = module.secure_upload.dlq_arn
}

output "eventbridge_rule_arn" {
  value = module.secure_upload.eventbridge_rule_arn
}
