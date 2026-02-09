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

output "sns_topic_arn" {
  description = "ARN of the malware alert SNS topic."
  value       = module.secure_upload.sns_topic_arn
}
