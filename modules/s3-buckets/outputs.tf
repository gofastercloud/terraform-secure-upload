################################################################################
# Staging Bucket
################################################################################

output "staging_bucket_id" {
  description = "ID of the staging bucket"
  value       = aws_s3_bucket.staging.id
}

output "staging_bucket_arn" {
  description = "ARN of the staging bucket"
  value       = aws_s3_bucket.staging.arn
}

output "staging_bucket" {
  description = "Domain name of the staging bucket"
  value       = aws_s3_bucket.staging.bucket_domain_name
}

################################################################################
# Clean Bucket
################################################################################

output "clean_bucket_id" {
  description = "ID of the clean bucket"
  value       = aws_s3_bucket.clean.id
}

output "clean_bucket_arn" {
  description = "ARN of the clean bucket"
  value       = aws_s3_bucket.clean.arn
}

output "clean_bucket" {
  description = "Domain name of the clean bucket"
  value       = aws_s3_bucket.clean.bucket_domain_name
}

################################################################################
# Quarantine Bucket
################################################################################

output "quarantine_bucket_id" {
  description = "ID of the quarantine bucket"
  value       = aws_s3_bucket.quarantine.id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine bucket"
  value       = aws_s3_bucket.quarantine.arn
}

output "quarantine_bucket" {
  description = "Domain name of the quarantine bucket"
  value       = aws_s3_bucket.quarantine.bucket_domain_name
}

################################################################################
# Logs Bucket
################################################################################

output "logs_bucket_id" {
  description = "ID of the logs bucket"
  value       = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  description = "ARN of the logs bucket"
  value       = aws_s3_bucket.logs.arn
}

output "logs_bucket" {
  description = "Domain name of the logs bucket"
  value       = aws_s3_bucket.logs.bucket_domain_name
}
