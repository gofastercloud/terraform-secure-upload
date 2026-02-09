output "staging_bucket_id" {
  description = "Name of the staging bucket."
  value       = module.secure_upload.staging_bucket_id
}

output "clean_bucket_id" {
  description = "Name of the clean bucket."
  value       = module.secure_upload.clean_bucket_id
}

output "quarantine_bucket_id" {
  description = "Name of the quarantine bucket."
  value       = module.secure_upload.quarantine_bucket_id
}

output "sns_topic_arn" {
  description = "ARN of the malware alert SNS topic."
  value       = module.secure_upload.sns_topic_arn
}
