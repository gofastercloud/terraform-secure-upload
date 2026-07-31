output "ingress_bucket_id" {
  description = "ID of the ingress bucket"
  value       = aws_s3_bucket.ingress.id
}

output "ingress_bucket_arn" {
  description = "ARN of the ingress bucket"
  value       = aws_s3_bucket.ingress.arn
}

output "clean_bucket_id" {
  description = "ID of the clean bucket"
  value       = aws_s3_bucket.egress.id
}

output "clean_bucket_arn" {
  description = "ARN of the clean bucket"
  value       = aws_s3_bucket.egress.arn
}

output "quarantine_bucket_id" {
  description = "ID of the quarantine bucket"
  value       = aws_s3_bucket.quarantine.id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine bucket"
  value       = aws_s3_bucket.quarantine.arn
}

output "s3_access_log_group_name" {
  description = "CloudWatch Logs group receiving S3 server access logs."
  value       = aws_cloudwatch_log_group.s3_access.name
}

output "s3_access_log_group_arn" {
  description = "ARN of the CloudWatch Logs group receiving S3 server access logs."
  value       = aws_cloudwatch_log_group.s3_access.arn
}
