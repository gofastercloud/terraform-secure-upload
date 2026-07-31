output "lambda_function_arn" {
  description = "ARN of the scan result router Lambda."
  value       = aws_lambda_function.file_router.arn
}

output "sns_topic_arn" {
  description = "ARN of the scan alert SNS topic."
  value       = aws_sns_topic.notifications.arn
}

output "dlq_arn" {
  description = "ARN of the scan router dead-letter queue."
  value       = aws_sqs_queue.dlq.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the GuardDuty scan result EventBridge rule."
  value       = aws_cloudwatch_event_rule.scan_result.arn
}
