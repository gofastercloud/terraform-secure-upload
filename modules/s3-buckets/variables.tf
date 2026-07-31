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
variable "log_retention_days" {
  description = "Number of days to retain S3 access logs in CloudWatch Logs."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "ingress_object_expiration_days" {
  description = "Number of days before an unprocessed current ingress object expires."
  type        = number
  default     = 7

  validation {
    condition     = var.ingress_object_expiration_days > 0
    error_message = "ingress_object_expiration_days must be positive."
  }
}

variable "ingress_noncurrent_version_expiration_days" {
  description = "Number of days before a noncurrent ingress object version expires."
  type        = number
  default     = 7

  validation {
    condition     = var.ingress_noncurrent_version_expiration_days > 0
    error_message = "ingress_noncurrent_version_expiration_days must be positive."
  }
}
