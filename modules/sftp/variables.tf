variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "create_sftp_server" {
  description = "Whether to create a new Transfer Family server or use an existing one"
  type        = bool
  default     = true
}

variable "existing_server_id" {
  description = "ID of an existing Transfer Family server (used when create_sftp_server is false)"
  type        = string
  default     = null
}

variable "endpoint_type" {
  description = "The type of endpoint for the Transfer Family server"
  type        = string
  default     = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.endpoint_type)
    error_message = "endpoint_type must be \"PUBLIC\" or \"VPC\"."
  }
}

variable "vpc_id" {
  description = "VPC ID for VPC endpoint type"
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Subnet IDs for VPC endpoint type"
  type        = list(string)
  default     = []
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to access the SFTP server (VPC security group)"
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.allowed_cidrs) > 0 || !var.create_sftp_server || var.endpoint_type != "VPC"
    error_message = "allowed_cidrs must not be empty when creating a VPC-type SFTP server."
  }
}

variable "staging_bucket_name" {
  description = "Name of the staging S3 bucket"
  type        = string
}

variable "staging_bucket_arn" {
  description = "ARN of the staging S3 bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used for S3 encryption"
  type        = string
}

variable "sftp_users" {
  description = "List of SFTP users to create"
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = optional(string, "/")
  }))
  default = []
}
