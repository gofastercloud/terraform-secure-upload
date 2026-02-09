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

variable "ingress_lifecycle_days" {
  description = "Number of days before objects in the ingress bucket expire"
  type        = number
  default     = 1
}

variable "egress_lifecycle_days" {
  description = "Number of days before objects in the egress bucket transition to STANDARD_IA"
  type        = number
  default     = 90
}

variable "quarantine_lifecycle_days" {
  description = "Number of days before objects in the quarantine bucket expire"
  type        = number
  default     = 365
}

variable "log_retention_days" {
  description = "Number of days to retain S3 access logs"
  type        = number
  default     = 90
}

variable "create_log_bucket" {
  description = "Whether to create a managed S3 access-log bucket"
  type        = bool
  default     = true
}

variable "external_log_bucket_id" {
  description = "Name/ID of an existing S3 bucket for access-log shipping. Used when create_log_bucket is false."
  type        = string
  default     = null
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock on the quarantine bucket"
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "Default retention period in days for Object Lock on the quarantine bucket. Only used when enable_object_lock is true."
  type        = number
  default     = 365
}

variable "object_lock_retention_mode" {
  description = "Object Lock retention mode for the quarantine bucket (GOVERNANCE or COMPLIANCE)."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_retention_mode)
    error_message = "object_lock_retention_mode must be GOVERNANCE or COMPLIANCE."
  }
}
