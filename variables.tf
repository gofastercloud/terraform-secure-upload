##############################################################################
# General
##############################################################################

variable "name_prefix" {
  description = "Prefix applied to all resource names for namespacing."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "tags" {
  description = "Tags applied to every resource created by this module."
  type        = map(string)
  default     = {}
}

##############################################################################
# KMS
##############################################################################

variable "kms_key_arn" {
  description = "ARN of an existing KMS key. When null the module creates a new key."
  type        = string
  default     = null
}

##############################################################################
# SFTP / Transfer Family
##############################################################################

variable "enable_sftp" {
  description = "Whether to enable the SFTP upload path via AWS Transfer Family."
  type        = bool
  default     = true
}

variable "create_sftp_server" {
  description = "Create a new Transfer Family server. Set false to attach to an existing server."
  type        = bool
  default     = true
}

variable "sftp_server_id" {
  description = "Existing Transfer Family server ID. Required when create_sftp_server is false."
  type        = string
  default     = null
}

variable "sftp_endpoint_type" {
  description = "Transfer Family endpoint type — PUBLIC or VPC."
  type        = string
  default     = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.sftp_endpoint_type)
    error_message = "sftp_endpoint_type must be PUBLIC or VPC."
  }
}

variable "sftp_vpc_id" {
  description = "VPC ID for a VPC-type Transfer Family endpoint."
  type        = string
  default     = null
}

variable "sftp_subnet_ids" {
  description = "Subnet IDs for a VPC-type Transfer Family endpoint."
  type        = list(string)
  default     = []
}

variable "sftp_allowed_cidrs" {
  description = "CIDR blocks allowed to access the SFTP server (VPC security group). Required for VPC endpoint type."
  type        = list(string)
  default     = []
}

variable "sftp_users" {
  description = "SFTP users to provision on the Transfer Family server."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = optional(string, "/")
  }))
  default = []
}

##############################################################################
# S3 Lifecycle
##############################################################################

variable "staging_lifecycle_days" {
  description = "Number of days before objects in the staging bucket expire."
  type        = number
  default     = 1

  validation {
    condition     = var.staging_lifecycle_days > 0
    error_message = "staging_lifecycle_days must be a positive number."
  }
}

variable "clean_lifecycle_days" {
  description = "Number of days before objects in the clean bucket transition to Infrequent Access."
  type        = number
  default     = 90

  validation {
    condition     = var.clean_lifecycle_days > 0
    error_message = "clean_lifecycle_days must be a positive number."
  }
}

variable "quarantine_lifecycle_days" {
  description = "Number of days before objects in the quarantine bucket expire."
  type        = number
  default     = 365

  validation {
    condition     = var.quarantine_lifecycle_days > 0
    error_message = "quarantine_lifecycle_days must be a positive number."
  }
}

##############################################################################
# Lambda — File Router
##############################################################################

variable "lambda_memory_size" {
  description = "Memory (MB) allocated to the file-router Lambda function."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "lambda_memory_size must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Timeout (seconds) for the file-router Lambda function."
  type        = number
  default     = 60

  validation {
    condition     = var.lambda_timeout > 0 && var.lambda_timeout <= 900
    error_message = "lambda_timeout must be between 1 and 900 seconds."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrent executions for the file-router Lambda function."
  type        = number
  default     = 10

  validation {
    condition     = var.lambda_reserved_concurrency >= 1
    error_message = "lambda_reserved_concurrency must be at least 1."
  }
}

##############################################################################
# Notifications
##############################################################################

variable "sns_subscription_emails" {
  description = "Email addresses subscribed to the malware-alert SNS topic."
  type        = list(string)
  default     = []
}

##############################################################################
# Quarantine — Object Lock
##############################################################################

variable "enable_object_lock" {
  description = "Enable S3 Object Lock on the quarantine bucket for tamper-proof retention."
  type        = bool
  default     = false
}

##############################################################################
# Logging
##############################################################################

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}
