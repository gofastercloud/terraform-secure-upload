variable "name_prefix" {
  description = "Prefix for all S3 bucket names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for S3 bucket encryption"
  type        = string
}

variable "staging_lifecycle_days" {
  description = "Number of days before objects in the staging bucket expire"
  type        = number
  default     = 1
}

variable "clean_lifecycle_days" {
  description = "Number of days before objects in the clean bucket transition to STANDARD_IA"
  type        = number
  default     = 30
}

variable "quarantine_lifecycle_days" {
  description = "Number of days before objects in the quarantine bucket expire"
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "Number of days to retain S3 access logs"
  type        = number
  default     = 90
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock on the quarantine bucket"
  type        = bool
  default     = false
}
