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
  description = "ARN of an existing KMS key, or null to create one."
  type        = string
  default     = null
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
  default     = -1
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 180
}

variable "vpc_id" {
  description = "VPC ID for the internet-facing SFTP endpoint."
  type        = string
}

variable "subnet_ids" {
  description = "Public subnet IDs for the SFTP endpoint."
  type        = list(string)
}

variable "address_allocation_ids" {
  description = "Elastic IP allocation IDs, one per SFTP subnet."
  type        = list(string)
}

variable "sftp_allowed_cidrs" {
  description = "Client CIDRs allowed to connect to SFTP."
  type        = list(string)
}

variable "sftp_custom_hostname" {
  description = "Optional custom hostname for the SFTP endpoint."
  type        = string
  default     = null
}

variable "sftp_route53_hosted_zone_id" {
  description = "Optional public Route 53 hosted zone ID for the custom hostname CNAME."
  type        = string
  default     = null
}

variable "sftp_users" {
  description = "SFTP users with distinct logical home prefixes."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = string
  }))
  default = []
}

variable "tags" {
  description = "Tags for all resources."
  type        = map(string)
  default     = {}
}
