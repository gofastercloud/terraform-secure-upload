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
  enable_sftp_ingress = false

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

output "egress_bucket_id" {
  value = module.secure_upload.egress_bucket_id
}

output "egress_bucket_arn" {
  value = module.secure_upload.egress_bucket_arn
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

output "log_bucket_arn" {
  value = module.secure_upload.log_bucket_arn
}

output "dlq_arn" {
  value = module.secure_upload.dlq_arn
}

output "eventbridge_rule_arn" {
  value = module.secure_upload.eventbridge_rule_arn
}
