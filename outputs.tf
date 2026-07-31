output "ingress_bucket_id" {
  description = "Name of the S3 upload bucket."
  value       = module.s3_buckets.ingress_bucket_id
}

output "ingress_bucket_arn" {
  description = "ARN of the S3 upload bucket."
  value       = module.s3_buckets.ingress_bucket_arn
}

output "clean_bucket_id" {
  description = "Name of the S3 bucket containing objects that passed malware scanning."
  value       = module.s3_buckets.clean_bucket_id
}

output "clean_bucket_arn" {
  description = "ARN of the clean S3 bucket."
  value       = module.s3_buckets.clean_bucket_arn
}

output "quarantine_bucket_id" {
  description = "Name of the S3 bucket containing quarantined objects."
  value       = module.s3_buckets.quarantine_bucket_id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine S3 bucket."
  value       = module.s3_buckets.quarantine_bucket_arn
}

output "s3_access_log_group_name" {
  description = "Name of the CloudWatch Logs group receiving S3 server access logs."
  value       = module.s3_buckets.s3_access_log_group_name
}

output "s3_access_log_group_arn" {
  description = "ARN of the CloudWatch Logs group receiving S3 server access logs."
  value       = module.s3_buckets.s3_access_log_group_arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption."
  value       = local.kms_key_arn
}

output "sftp_server_id" {
  description = "ID of the optional VPC-hosted Transfer Family SFTP server."
  value       = var.enable_sftp ? module.sftp[0].server_id : null
}

output "sftp_server_endpoint" {
  description = "Endpoint hostname of the optional Transfer Family SFTP server."
  value       = var.enable_sftp ? module.sftp[0].server_endpoint : null
}

output "sftp_hostname" {
  description = "Configured custom SFTP hostname, or the AWS endpoint when no custom hostname is configured."
  value       = var.enable_sftp ? module.sftp[0].hostname : null
}

output "sftp_user_arns" {
  description = "Map of SFTP username to Transfer Family user ARN."
  value       = var.enable_sftp ? module.sftp[0].user_arns : {}
}

output "sns_topic_arn" {
  description = "SNS topic for malware and scan-failure alerts."
  value       = module.file_router.sns_topic_arn
}

output "guardduty_protection_plan_arn" {
  description = "ARN of the GuardDuty Malware Protection for S3 plan."
  value       = module.guardduty_protection.protection_plan_arn
}

output "lambda_function_arn" {
  description = "ARN of the scan result router Lambda."
  value       = module.file_router.lambda_function_arn
}

output "dlq_arn" {
  description = "ARN of the scan result router dead-letter queue."
  value       = module.file_router.dlq_arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for GuardDuty scan results."
  value       = module.file_router.eventbridge_rule_arn
}
