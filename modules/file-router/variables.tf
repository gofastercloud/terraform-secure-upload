variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}

variable "ingress_bucket_name" {
  description = "Ingress bucket name."
  type        = string
}

variable "ingress_bucket_arn" {
  description = "Ingress bucket ARN."
  type        = string
}

variable "clean_bucket_name" {
  description = "Clean bucket name."
  type        = string
}

variable "clean_bucket_arn" {
  description = "Clean bucket ARN."
  type        = string
}

variable "quarantine_bucket_name" {
  description = "Quarantine bucket name."
  type        = string
}

variable "quarantine_bucket_arn" {
  description = "Quarantine bucket ARN."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN."
  type        = string
}

variable "lambda_runtime" {
  description = "Lambda runtime."
  type        = string
}

variable "lambda_memory_size" {
  description = "Lambda memory in MB."
  type        = number
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds."
  type        = number
}

variable "lambda_reserved_concurrency" {
  description = "Lambda reserved concurrency."
  type        = number
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
}
