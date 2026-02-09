variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "staging_bucket_name" {
  description = "Name of the staging S3 bucket"
  type        = string
}

variable "staging_bucket_arn" {
  description = "ARN of the staging S3 bucket"
  type        = string
}

variable "clean_bucket_name" {
  description = "Name of the clean S3 bucket"
  type        = string
}

variable "clean_bucket_arn" {
  description = "ARN of the clean S3 bucket"
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
