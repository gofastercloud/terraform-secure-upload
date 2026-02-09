################################################################################
# Complete Test Fixture — Full configuration with SFTP enabled
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

  name_prefix        = "terratest-full-${var.test_id}"
  enable_sftp        = true
  create_sftp_server = true
  sftp_endpoint_type = "PUBLIC"

  staging_lifecycle_days   = 2
  clean_lifecycle_days     = 60
  quarantine_lifecycle_days = 180

  lambda_memory_size          = 512
  lambda_timeout              = 120
  lambda_reserved_concurrency = 5

  log_retention_days = 30

  sftp_users = [
    {
      username              = "test-user-1"
      ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example1 test-user-1@example.com"
      home_directory_prefix = "/uploads/user1/"
    },
    {
      username              = "test-user-2"
      ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example2 test-user-2@example.com"
      home_directory_prefix = "/uploads/user2/"
    },
  ]

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

output "sftp_server_id" {
  value = module.secure_upload.sftp_server_id
}

output "sftp_server_endpoint" {
  value = module.secure_upload.sftp_server_endpoint
}
