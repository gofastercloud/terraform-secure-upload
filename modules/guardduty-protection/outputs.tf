output "protection_plan_arn" {
  description = "ARN of the GuardDuty Malware Protection plan"
  value       = aws_guardduty_malware_protection_plan.this.arn
}

output "protection_plan_id" {
  description = "ID of the GuardDuty Malware Protection plan"
  value       = aws_guardduty_malware_protection_plan.this.id
}

output "guardduty_role_arn" {
  description = "ARN of the IAM role used by GuardDuty for malware scanning"
  value       = aws_iam_role.guardduty_malware.arn
}
