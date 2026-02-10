variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "ingress_bucket_name" {
  description = "Name of the ingress S3 bucket"
  type        = string
}

variable "ingress_bucket_arn" {
  description = "ARN of the ingress S3 bucket"
  type        = string
}

variable "egress_bucket_name" {
  description = "Name of the egress S3 bucket"
  type        = string
}

variable "egress_bucket_arn" {
  description = "ARN of the egress S3 bucket"
  type        = string
}

variable "quarantine_bucket_name" {
  description = "Name of the quarantine S3 bucket"
  type        = string
}

variable "quarantine_bucket_arn" {
  description = "ARN of the quarantine S3 bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for encryption"
  type        = string
}

variable "lambda_runtime" {
  description = "Lambda runtime identifier"
  type        = string
  default     = "python3.12"
}

variable "lambda_memory_size" {
  description = "Memory size for the Lambda function in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Timeout for the Lambda function in seconds"
  type        = number
  default     = 60
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrent executions for the Lambda function"
  type        = number
  default     = 10
}

variable "sqs_kms_data_key_reuse_seconds" {
  description = "Duration (seconds) that SQS reuses a data key before calling KMS again."
  type        = number
  default     = 300
}

variable "sns_subscription_emails" {
  description = "Email addresses to subscribe to the SNS topic"
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 90
}

variable "enable_cloudwatch_dashboard" {
  description = "Create a CloudWatch dashboard with metric filters for pipeline observability."
  type        = bool
  default     = false
}

variable "enable_egress_notifications" {
  description = "Enable SNS notifications when clean files are delivered to the egress bucket."
  type        = bool
  default     = false
}

variable "egress_notification_emails" {
  description = "Email addresses subscribed to the egress notification SNS topic."
  type        = list(string)
  default     = []
}

variable "enable_audit_trail" {
  description = "Enable a DynamoDB audit trail that records every file at each pipeline stage."
  type        = bool
  default     = false
}

variable "audit_trail_retention_days" {
  description = "Number of days to retain audit trail records. Set to 0 to retain forever."
  type        = number
  default     = 365
}

variable "virustotal_scanner_function_arn" {
  description = "ARN of the VirusTotal scanner Lambda function. When non-null, the file router invokes it synchronously for files that pass GuardDuty scanning."
  type        = string
  default     = null
}

variable "virustotal_scanner_function_name" {
  description = "Name of the VirusTotal scanner Lambda function (for dashboard metrics). Null when scanning is disabled."
  type        = string
  default     = null
}

variable "virustotal_threshold" {
  description = "Number of VirusTotal positives at or above which a file is quarantined."
  type        = number
  default     = 3
}

variable "prompt_injection_scanner_function_arn" {
  description = "ARN of the prompt injection scanner Lambda function. When non-null, the file router invokes it synchronously for files that pass malware scanning."
  type        = string
  default     = null
}

variable "prompt_injection_scanner_function_name" {
  description = "Name of the prompt injection scanner Lambda function (for dashboard metrics). Null when scanning is disabled."
  type        = string
  default     = null
}

variable "prompt_injection_threshold" {
  description = "Score threshold (0–100) above which a file is quarantined for prompt injection."
  type        = number
  default     = 80
}
