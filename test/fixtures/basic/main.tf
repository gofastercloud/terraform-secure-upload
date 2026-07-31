################################################################################
# Basic Test Fixture — Minimal configuration (no SFTP)
################################################################################

terraform {
  required_version = ">= 1.9"
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for test deployment"
  type        = string
  default     = "us-east-1"
}

variable "test_id" {
  description = "Unique identifier for this test run"
  type        = string
}

module "secure_upload" {
  source = "../../../"

  name_prefix = "terratest-basic-${var.test_id}"

  tags = {
    Environment = "test"
    ManagedBy   = "terratest"
    TestID      = var.test_id
  }
}

################################################################################
# Outputs
################################################################################

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

output "s3_access_log_group_name" {
  value = module.secure_upload.s3_access_log_group_name
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

output "s3_access_log_group_arn" {
  value = module.secure_upload.s3_access_log_group_arn
}

output "dlq_arn" {
  value = module.secure_upload.dlq_arn
}

output "eventbridge_rule_arn" {
  value = module.secure_upload.eventbridge_rule_arn
}
