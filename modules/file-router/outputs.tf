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
