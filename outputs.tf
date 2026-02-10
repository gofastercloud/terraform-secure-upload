################################################################################
# S3 Buckets
################################################################################

output "ingress_bucket_id" {
  description = "Name of the ingress (upload) S3 bucket."
  value       = module.s3_buckets.ingress_bucket_id
}

output "ingress_bucket_arn" {
  description = "ARN of the ingress (upload) S3 bucket."
  value       = module.s3_buckets.ingress_bucket_arn
}

output "egress_bucket_id" {
  description = "Name of the egress (verified) S3 bucket."
  value       = module.s3_buckets.egress_bucket_id
}

output "egress_bucket_arn" {
  description = "ARN of the egress (verified) S3 bucket."
  value       = module.s3_buckets.egress_bucket_arn
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
  description = "Name of the S3 access-log bucket (module-created or external)."
  value       = module.s3_buckets.logs_bucket_id
}

output "log_bucket_arn" {
  description = "ARN of the S3 access-log bucket (null when using an external bucket)."
  value       = module.s3_buckets.logs_bucket_arn
}

################################################################################
# KMS
################################################################################

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption."
  value       = local.kms_key_arn
}

################################################################################
# SFTP / Transfer Family
################################################################################

output "sftp_ingress_server_id" {
  description = "ID of the AWS Transfer Family SFTP server."
  value       = var.enable_sftp_ingress ? module.sftp_ingress[0].server_id : null
}

output "sftp_ingress_server_endpoint" {
  description = "Endpoint hostname of the AWS Transfer Family SFTP server."
  value       = var.enable_sftp_ingress ? module.sftp_ingress[0].server_endpoint : null
}

output "sftp_ingress_user_arns" {
  description = "Map of ingress SFTP username to Transfer user ARN."
  value       = var.enable_sftp_ingress ? module.sftp_ingress[0].user_arns : {}
}

################################################################################
# SFTP Egress / Transfer Family
################################################################################

output "sftp_egress_server_id" {
  description = "ID of the egress AWS Transfer Family SFTP server."
  value       = var.enable_sftp_egress ? module.sftp_egress[0].server_id : null
}

output "sftp_egress_server_endpoint" {
  description = "Endpoint hostname of the egress SFTP server."
  value       = var.enable_sftp_egress ? module.sftp_egress[0].server_endpoint : null
}

output "sftp_egress_user_arns" {
  description = "Map of egress SFTP username to Transfer user ARN."
  value       = var.enable_sftp_egress ? module.sftp_egress[0].user_arns : {}
}

################################################################################
# Notifications
################################################################################

output "sns_topic_arn" {
  description = "ARN of the SNS topic for malware alert notifications."
  value       = module.file_router.sns_topic_arn
}

################################################################################
# GuardDuty
################################################################################

output "guardduty_protection_plan_arn" {
  description = "ARN of the GuardDuty Malware Protection plan for the ingress bucket."
  value       = module.guardduty_protection.protection_plan_arn
}

################################################################################
# Lambda
################################################################################

output "lambda_function_arn" {
  description = "ARN of the file-router Lambda function."
  value       = module.file_router.lambda_function_arn
}

################################################################################
# Dead Letter Queue
################################################################################

output "dlq_arn" {
  description = "ARN of the file-router Lambda dead letter queue."
  value       = module.file_router.dlq_arn
}

################################################################################
# EventBridge
################################################################################

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for GuardDuty scan results."
  value       = module.file_router.eventbridge_rule_arn
}

################################################################################
# Observability
################################################################################

output "cloudwatch_dashboard_arn" {
  description = "ARN of the CloudWatch pipeline dashboard (null when enable_cloudwatch_dashboard is false)."
  value       = module.file_router.cloudwatch_dashboard_arn
}
