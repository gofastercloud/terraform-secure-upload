output "lambda_function_arn" {
  description = "ARN of the file router Lambda function"
  value       = aws_lambda_function.file_router.arn
}

output "lambda_function_name" {
  description = "Name of the file router Lambda function"
  value       = aws_lambda_function.file_router.function_name
}

output "sns_topic_arn" {
  description = "ARN of the malware alert SNS topic"
  value       = aws_sns_topic.malware_alerts.arn
}

output "dlq_arn" {
  description = "ARN of the Lambda dead letter queue"
  value       = aws_sqs_queue.dlq.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for scan results"
  value       = aws_cloudwatch_event_rule.scan_result.arn
}

output "cloudwatch_dashboard_arn" {
  description = "ARN of the CloudWatch dashboard (null when disabled)"
  value       = var.enable_cloudwatch_dashboard ? aws_cloudwatch_dashboard.pipeline[0].dashboard_arn : null
}

output "egress_sns_topic_arn" {
  description = "ARN of the egress notification SNS topic (null when disabled)"
  value       = var.enable_egress_notifications ? aws_sns_topic.egress_notifications[0].arn : null
}

output "audit_trail_table_arn" {
  description = "ARN of the audit trail DynamoDB table (null when disabled)"
  value       = var.enable_audit_trail ? aws_dynamodb_table.audit_trail[0].arn : null
}

output "audit_trail_table_name" {
  description = "Name of the audit trail DynamoDB table (null when disabled)"
  value       = var.enable_audit_trail ? aws_dynamodb_table.audit_trail[0].name : null
}
