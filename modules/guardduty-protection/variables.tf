variable "staging_bucket_name" {
  description = "Name of the staging bucket to protect with GuardDuty Malware Protection"
  type        = string
}

variable "staging_bucket_arn" {
  description = "ARN of the staging bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for decrypting objects in the staging bucket"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}
