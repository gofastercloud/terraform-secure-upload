variable "ingress_bucket_name" {
  description = "Name of the ingress bucket to protect with GuardDuty Malware Protection"
  type        = string
}

variable "ingress_bucket_arn" {
  description = "ARN of the ingress bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for decrypting objects in the ingress bucket"
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
