##############################################################################
# S3 Buckets
##############################################################################

output "staging_bucket_id" {
  description = "Name of the staging (upload) S3 bucket."
  value       = module.s3_buckets.staging_bucket_id
}

output "staging_bucket_arn" {
  description = "ARN of the staging (upload) S3 bucket."
  value       = module.s3_buckets.staging_bucket_arn
}

output "clean_bucket_id" {
  description = "Name of the clean (scan-passed) S3 bucket."
  value       = module.s3_buckets.clean_bucket_id
}

output "clean_bucket_arn" {
  description = "ARN of the clean (scan-passed) S3 bucket."
  value       = module.s3_buckets.clean_bucket_arn
}

output "quarantine_bucket_id" {
  description = "Name of the quarantine (malware-detected) S3 bucket."
  value       = module.s3_buckets.quarantine_bucket_id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine (malware-detected) S3 bucket."
  value       = module.s3_buckets.quarantine_bucket_arn
}

output "log_bucket_id" {
  description = "Name of the S3 access-log bucket."
  value       = module.s3_buckets.logs_bucket_id
}

##############################################################################
# KMS
##############################################################################

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption."
  value       = local.kms_key_arn
}

##############################################################################
# SFTP / Transfer Family
##############################################################################

output "sftp_server_id" {
  description = "ID of the AWS Transfer Family SFTP server."
  value       = var.enable_sftp ? module.sftp[0].server_id : null
}

output "sftp_server_endpoint" {
  description = "Endpoint hostname of the AWS Transfer Family SFTP server."
  value       = var.enable_sftp ? module.sftp[0].server_endpoint : null
}

##############################################################################
# Notifications
##############################################################################

output "sns_topic_arn" {
  description = "ARN of the SNS topic for malware alert notifications."
  value       = module.file_router.sns_topic_arn
}

##############################################################################
# GuardDuty
##############################################################################

output "guardduty_protection_plan_arn" {
  description = "ARN of the GuardDuty Malware Protection plan for the staging bucket."
  value       = module.guardduty_protection.protection_plan_arn
}

##############################################################################
# Lambda
##############################################################################

output "lambda_function_arn" {
  description = "ARN of the file-router Lambda function."
  value       = module.file_router.lambda_function_arn
}
