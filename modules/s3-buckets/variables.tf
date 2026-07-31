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
