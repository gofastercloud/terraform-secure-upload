output "ingress_bucket_id" {
  description = "Name of the ingress bucket."
  value       = module.secure_upload.ingress_bucket_id
}

output "egress_bucket_id" {
  description = "Name of the egress bucket."
  value       = module.secure_upload.egress_bucket_id
}

output "quarantine_bucket_id" {
  description = "Name of the quarantine bucket."
  value       = module.secure_upload.quarantine_bucket_id
}

output "kms_key_arn" {
  description = "KMS key ARN used for encryption."
  value       = module.secure_upload.kms_key_arn
}

output "sftp_ingress_server_id" {
  description = "Ingress Transfer Family server ID."
  value       = module.secure_upload.sftp_ingress_server_id
}

output "sftp_ingress_server_endpoint" {
  description = "Ingress SFTP server endpoint hostname."
  value       = module.secure_upload.sftp_ingress_server_endpoint
}

output "sftp_egress_server_id" {
  description = "Egress Transfer Family server ID."
  value       = module.secure_upload.sftp_egress_server_id
}

output "sftp_egress_server_endpoint" {
  description = "Egress SFTP server endpoint hostname."
  value       = module.secure_upload.sftp_egress_server_endpoint
}

output "sns_topic_arn" {
  description = "ARN of the malware alert SNS topic."
  value       = module.secure_upload.sns_topic_arn
}

output "lambda_function_arn" {
  description = "ARN of the file-router Lambda."
  value       = module.secure_upload.lambda_function_arn
}

output "guardduty_protection_plan_arn" {
  description = "ARN of the GuardDuty protection plan."
  value       = module.secure_upload.guardduty_protection_plan_arn
}
