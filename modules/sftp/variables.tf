variable "name_prefix" {
  description = "Prefix for SFTP resources."
  type        = string
}

variable "tags" {
  description = "Tags applied to SFTP resources."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC hosting the internet-facing Transfer Family endpoint."
  type        = string
}

variable "subnet_ids" {
  description = "Public subnets hosting the endpoint."
  type        = list(string)
}

variable "address_allocation_ids" {
  description = "Elastic IP allocation IDs, one per subnet."
  type        = list(string)
}

variable "allowed_cidrs" {
  description = "Client source CIDRs allowed to access TCP/22."
  type        = list(string)
}

variable "custom_hostname" {
  description = "Optional custom hostname displayed for the Transfer Family server."
  type        = string
  default     = null

  validation {
    condition     = var.custom_hostname == null || (can(regex("^[A-Za-z0-9.-]+$", var.custom_hostname)) && !can(regex("\\.\\.", var.custom_hostname)))
    error_message = "custom_hostname must be a valid DNS hostname without consecutive dots."
  }
}

variable "route53_hosted_zone_id" {
  description = "Optional public Route 53 hosted zone ID used to create the custom hostname CNAME record."
  type        = string
  default     = null
}

variable "bucket_name" {
  description = "S3 bucket used as the logical SFTP storage target."
  type        = string
}

variable "bucket_arn" {
  description = "S3 bucket ARN used in user IAM policies."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN used for S3 encryption."
  type        = string
}

variable "sftp_users" {
  description = "Service-managed SFTP users and their isolated logical home prefixes."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = string
  }))
  default = []
}
