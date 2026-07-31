variable "name_prefix" {
  description = "Lowercase prefix applied to all resource names."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "tags" {
  description = "Tags applied to resources created by this module."
  type        = map(string)
  default     = {}
}

variable "create_kms_key" {
  description = "Create a KMS key when kms_key_arn is not supplied."
  type        = bool
  default     = true
}

variable "kms_key_deletion_window_days" {
  description = "Days before a scheduled KMS key deletion takes effect."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window_days >= 7 && var.kms_key_deletion_window_days <= 30
    error_message = "kms_key_deletion_window_days must be between 7 and 30."
  }
}

variable "kms_key_arn" {
  description = "Existing KMS key ARN. Required when create_kms_key is false."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:[^:]+:kms:", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }

  validation {
    condition     = var.create_kms_key || var.kms_key_arn != null
    error_message = "kms_key_arn is required when create_kms_key is false."
  }
}

variable "enable_sftp" {
  description = "Create a VPC-hosted, internet-facing Transfer Family SFTP server for uploads."
  type        = bool
  default     = false
}

variable "sftp_vpc_id" {
  description = "VPC for the internet-facing Transfer Family endpoint."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_sftp || var.sftp_vpc_id != null
    error_message = "sftp_vpc_id is required when enable_sftp is true."
  }
}

variable "sftp_subnet_ids" {
  description = "Public subnets hosting the Transfer Family endpoint, one per Availability Zone."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_sftp || length(var.sftp_subnet_ids) > 0
    error_message = "sftp_subnet_ids must not be empty when enable_sftp is true."
  }
}

variable "sftp_address_allocation_ids" {
  description = "Elastic IP allocation IDs, one for each SFTP subnet."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_sftp || length(var.sftp_address_allocation_ids) == length(var.sftp_subnet_ids)
    error_message = "sftp_address_allocation_ids must contain exactly one Elastic IP allocation ID per SFTP subnet."
  }
}

variable "sftp_allowed_cidrs" {
  description = "Client source CIDRs allowed to connect to SFTP on TCP/22."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_sftp || length(var.sftp_allowed_cidrs) > 0
    error_message = "sftp_allowed_cidrs must not be empty when enable_sftp is true."
  }

  validation {
    condition     = !contains(var.sftp_allowed_cidrs, "0.0.0.0/0")
    error_message = "sftp_allowed_cidrs must not contain 0.0.0.0/0."
  }
}

variable "sftp_custom_hostname" {
  description = "Optional custom DNS hostname for the SFTP endpoint."
  type        = string
  default     = null

  validation {
    condition     = var.sftp_custom_hostname == null || (can(regex("^[A-Za-z0-9.-]+$", var.sftp_custom_hostname)) && !can(regex("\\.\\.", var.sftp_custom_hostname)))
    error_message = "sftp_custom_hostname must be a valid DNS hostname without consecutive dots."
  }
}

variable "sftp_route53_hosted_zone_id" {
  description = "Optional public Route 53 hosted zone ID. Creates the custom hostname CNAME when supplied with sftp_custom_hostname."
  type        = string
  default     = null
}

variable "sftp_users" {
  description = "Service-managed SFTP users. Each user is restricted to a distinct logical home prefix."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = string
  }))
  default = []

  validation {
    condition = alltrue([
      for user in var.sftp_users : can(regex("^[A-Za-z0-9._-]+$", user.username))
    ])
    error_message = "SFTP usernames may contain only letters, numbers, periods, underscores, and hyphens."
  }

  validation {
    condition = alltrue([
      for user in var.sftp_users : can(regex("^/.+/$", user.home_directory_prefix))
    ])
    error_message = "Each SFTP home_directory_prefix must start and end with / and must not be /."
  }

  validation {
    condition = alltrue([
      for user in var.sftp_users : !can(regex("(^|/)\\.\\.(/|$)", user.home_directory_prefix))
    ])
    error_message = "SFTP home_directory_prefix must not contain path traversal segments."
  }

  validation {
    condition     = length(distinct([for user in var.sftp_users : user.home_directory_prefix])) == length(var.sftp_users)
    error_message = "Each SFTP user must have a distinct home_directory_prefix to avoid overlapping access and hot S3 prefixes."
  }
}

variable "lambda_runtime" {
  description = "Python runtime for the scan result router Lambda."
  type        = string
  default     = "python3.12"

  validation {
    condition     = can(regex("^python3\\.", var.lambda_runtime))
    error_message = "lambda_runtime must be a Python 3.x runtime."
  }
}

variable "lambda_memory_size" {
  description = "Memory allocated to the scan result router Lambda in MB."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "lambda_memory_size must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Timeout for the scan result router Lambda in seconds."
  type        = number
  default     = 60

  validation {
    condition     = var.lambda_timeout > 0 && var.lambda_timeout <= 900
    error_message = "lambda_timeout must be between 1 and 900 seconds."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for the scan result router Lambda."
  type        = number
  default     = -1

  validation {
    condition     = var.lambda_reserved_concurrency == -1 || var.lambda_reserved_concurrency >= 1
    error_message = "lambda_reserved_concurrency must be -1 or at least 1."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period for Lambda logs."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}
