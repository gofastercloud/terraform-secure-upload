################################################################################
# Ingress Bucket
################################################################################

output "ingress_bucket_id" {
  description = "ID of the ingress bucket"
  value       = aws_s3_bucket.ingress.id
}

output "ingress_bucket_arn" {
  description = "ARN of the ingress bucket"
  value       = aws_s3_bucket.ingress.arn
}

output "ingress_bucket" {
  description = "Domain name of the ingress bucket"
  value       = aws_s3_bucket.ingress.bucket_domain_name
}

################################################################################
# Egress Bucket
################################################################################

output "egress_bucket_id" {
  description = "ID of the egress bucket"
  value       = aws_s3_bucket.egress.id
}

output "egress_bucket_arn" {
  description = "ARN of the egress bucket"
  value       = aws_s3_bucket.egress.arn
}

output "egress_bucket" {
  description = "Domain name of the egress bucket"
  value       = aws_s3_bucket.egress.bucket_domain_name
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
  description = "ID of the logs bucket (module-created or external)"
  value       = local.log_bucket_id
}

output "logs_bucket_arn" {
  description = "ARN of the logs bucket (null when using an external bucket)"
  value       = var.create_log_bucket ? aws_s3_bucket.logs[0].arn : null
}

output "logs_bucket" {
  description = "Domain name of the logs bucket (null when using an external bucket)"
  value       = var.create_log_bucket ? aws_s3_bucket.logs[0].bucket_domain_name : null
}
