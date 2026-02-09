################################################################################
# Basic Test Fixture — Minimal configuration (no SFTP)
################################################################################

terraform {
  required_version = ">= 1.5"
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
  enable_sftp = false

  tags = {
    Environment = "test"
    ManagedBy   = "terratest"
    TestID      = var.test_id
  }
}

################################################################################
# Outputs
################################################################################

output "staging_bucket_id" {
  value = module.secure_upload.staging_bucket_id
}

output "staging_bucket_arn" {
  value = module.secure_upload.staging_bucket_arn
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
