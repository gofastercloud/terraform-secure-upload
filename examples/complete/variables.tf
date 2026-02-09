variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "kms_key_arn" {
  description = "ARN of an existing KMS key. Set to null to auto-create."
  type        = string
  default     = null
}

variable "staging_lifecycle_days" {
  description = "Days before staging objects expire."
  type        = number
  default     = 1
}

variable "clean_lifecycle_days" {
  description = "Days before clean objects transition to IA."
  type        = number
  default     = 90
}

variable "quarantine_lifecycle_days" {
  description = "Days before quarantine objects expire."
  type        = number
  default     = 365
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock on the quarantine bucket."
  type        = bool
  default     = true
}

variable "lambda_memory_size" {
  description = "Lambda memory in MB."
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 120
}

variable "lambda_reserved_concurrency" {
  description = "Lambda reserved concurrency."
  type        = number
  default     = 20
}

variable "sns_subscription_emails" {
  description = "Email addresses for malware alerts."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 180
}

variable "vpc_id" {
  description = "VPC ID for the SFTP VPC endpoint."
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the SFTP VPC endpoint."
  type        = list(string)
}

variable "sftp_users" {
  description = "SFTP users to provision."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = optional(string, "/")
  }))
  default = []
}

variable "tags" {
  description = "Tags for all resources."
  type        = map(string)
  default     = {}
}
