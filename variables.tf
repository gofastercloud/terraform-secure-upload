################################################################################
# General
################################################################################

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

################################################################################
# KMS
################################################################################

variable "create_kms_key" {
  description = "Whether to create a new KMS key. Set to false when providing your own key via kms_key_arn."
  type        = bool
  default     = true
}

variable "kms_key_deletion_window_days" {
  description = "Number of days before a KMS key is permanently deleted after being scheduled for deletion."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window_days >= 7 && var.kms_key_deletion_window_days <= 30
    error_message = "kms_key_deletion_window_days must be between 7 and 30."
  }
}

variable "kms_key_arn" {
  description = "ARN of an existing KMS key. Required when create_kms_key is false. When null and create_kms_key is true, the module creates a new key."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:aws:kms:", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN starting with arn:aws:kms:."
  }

  validation {
    condition     = var.create_kms_key || var.kms_key_arn != null
    error_message = "kms_key_arn is required when create_kms_key is false."
  }
}

################################################################################
# SFTP / Transfer Family
################################################################################

variable "enable_sftp_ingress" {
  description = "Enable the SFTP upload path via AWS Transfer Family. When false (default), no Transfer Family resources are created for ingress."
  type        = bool
  default     = false
}

variable "create_sftp_ingress_server" {
  description = "Create a new Transfer Family server for ingress. Only takes effect when enable_sftp_ingress is true. Set to false to attach users to an existing server via sftp_ingress_server_id."
  type        = bool
  default     = true
}

variable "sftp_ingress_server_id" {
  description = "ID of an existing Transfer Family server to attach ingress users to. Only used when enable_sftp_ingress is true and create_sftp_ingress_server is false."
  type        = string
  default     = null

  validation {
    condition     = var.create_sftp_ingress_server || !var.enable_sftp_ingress || var.sftp_ingress_server_id != null
    error_message = "sftp_ingress_server_id is required when enable_sftp_ingress is true and create_sftp_ingress_server is false."
  }
}

variable "sftp_ingress_endpoint_type" {
  description = "Transfer Family endpoint type for ingress — PUBLIC or VPC. Only used when enable_sftp_ingress and create_sftp_ingress_server are both true."
  type        = string
  default     = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.sftp_ingress_endpoint_type)
    error_message = "sftp_ingress_endpoint_type must be PUBLIC or VPC."
  }
}

variable "sftp_ingress_vpc_id" {
  description = "VPC ID for a VPC-type ingress Transfer Family endpoint. Required when sftp_ingress_endpoint_type is VPC."
  type        = string
  default     = null

  validation {
    condition     = var.sftp_ingress_endpoint_type != "VPC" || !var.enable_sftp_ingress || !var.create_sftp_ingress_server || var.sftp_ingress_vpc_id != null
    error_message = "sftp_ingress_vpc_id is required when sftp_ingress_endpoint_type is VPC, enable_sftp_ingress is true, and create_sftp_ingress_server is true."
  }
}

variable "sftp_ingress_subnet_ids" {
  description = "Subnet IDs for a VPC-type ingress Transfer Family endpoint. Required when sftp_ingress_endpoint_type is VPC."
  type        = list(string)
  default     = []

  validation {
    condition     = var.sftp_ingress_endpoint_type != "VPC" || !var.enable_sftp_ingress || !var.create_sftp_ingress_server || length(var.sftp_ingress_subnet_ids) > 0
    error_message = "sftp_ingress_subnet_ids must not be empty when sftp_ingress_endpoint_type is VPC, enable_sftp_ingress is true, and create_sftp_ingress_server is true."
  }
}

variable "sftp_ingress_allowed_cidrs" {
  description = "CIDR blocks allowed to access the ingress SFTP server security group. Required when sftp_ingress_endpoint_type is VPC."
  type        = list(string)
  default     = []

  validation {
    condition     = var.sftp_ingress_endpoint_type != "VPC" || !var.enable_sftp_ingress || !var.create_sftp_ingress_server || length(var.sftp_ingress_allowed_cidrs) > 0
    error_message = "sftp_ingress_allowed_cidrs must not be empty when sftp_ingress_endpoint_type is VPC, enable_sftp_ingress is true, and create_sftp_ingress_server is true."
  }
}

variable "sftp_ingress_users" {
  description = "Ingress SFTP users to provision. Each home_directory_prefix scopes the user to a subdirectory (must start and end with /, e.g. /uploads/partner-a/). A bare / is not allowed for ingress."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = string
  }))
  default = []

  validation {
    condition = alltrue([
      for user in var.sftp_ingress_users :
      can(regex("^/.+/$", user.home_directory_prefix))
    ])
    error_message = "Each sftp_ingress_users home_directory_prefix must start and end with / and contain at least one path component. A bare / is not allowed — ingress users must be scoped to a subdirectory (e.g. /uploads/partner-a/)."
  }

  validation {
    condition = alltrue([
      for user in var.sftp_ingress_users :
      !can(regex("\\.\\.(/|$)", user.home_directory_prefix))
    ])
    error_message = "sftp_ingress_users home_directory_prefix must not contain '..' path traversal segments."
  }
}

################################################################################
# SFTP Egress / Transfer Family (read-only access to egress bucket)
################################################################################

variable "enable_sftp_egress" {
  description = "Enable an egress SFTP endpoint for read-only access to the egress bucket. When false (default), no Transfer Family resources are created for egress."
  type        = bool
  default     = false
}

variable "create_sftp_egress_server" {
  description = "Create a new Transfer Family server for egress. Only takes effect when enable_sftp_egress is true. Set to false to attach users to an existing server via sftp_egress_server_id."
  type        = bool
  default     = true
}

variable "sftp_egress_server_id" {
  description = "ID of an existing Transfer Family server to attach egress users to. Only used when enable_sftp_egress is true and create_sftp_egress_server is false."
  type        = string
  default     = null

  validation {
    condition     = var.create_sftp_egress_server || !var.enable_sftp_egress || var.sftp_egress_server_id != null
    error_message = "sftp_egress_server_id is required when enable_sftp_egress is true and create_sftp_egress_server is false."
  }
}

variable "sftp_egress_endpoint_type" {
  description = "Transfer Family endpoint type for egress — PUBLIC or VPC. Only used when enable_sftp_egress and create_sftp_egress_server are both true."
  type        = string
  default     = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.sftp_egress_endpoint_type)
    error_message = "sftp_egress_endpoint_type must be PUBLIC or VPC."
  }
}

variable "sftp_egress_vpc_id" {
  description = "VPC ID for a VPC-type egress Transfer Family endpoint. Required when sftp_egress_endpoint_type is VPC."
  type        = string
  default     = null

  validation {
    condition     = var.sftp_egress_endpoint_type != "VPC" || !var.enable_sftp_egress || !var.create_sftp_egress_server || var.sftp_egress_vpc_id != null
    error_message = "sftp_egress_vpc_id is required when sftp_egress_endpoint_type is VPC, enable_sftp_egress is true, and create_sftp_egress_server is true."
  }
}

variable "sftp_egress_subnet_ids" {
  description = "Subnet IDs for a VPC-type egress Transfer Family endpoint. Required when sftp_egress_endpoint_type is VPC."
  type        = list(string)
  default     = []

  validation {
    condition     = var.sftp_egress_endpoint_type != "VPC" || !var.enable_sftp_egress || !var.create_sftp_egress_server || length(var.sftp_egress_subnet_ids) > 0
    error_message = "sftp_egress_subnet_ids must not be empty when sftp_egress_endpoint_type is VPC, enable_sftp_egress is true, and create_sftp_egress_server is true."
  }
}

variable "sftp_egress_allowed_cidrs" {
  description = "CIDR blocks allowed to access the egress SFTP server security group. Required when sftp_egress_endpoint_type is VPC."
  type        = list(string)
  default     = []

  validation {
    condition     = var.sftp_egress_endpoint_type != "VPC" || !var.enable_sftp_egress || !var.create_sftp_egress_server || length(var.sftp_egress_allowed_cidrs) > 0
    error_message = "sftp_egress_allowed_cidrs must not be empty when sftp_egress_endpoint_type is VPC, enable_sftp_egress is true, and create_sftp_egress_server is true."
  }
}

variable "sftp_egress_users" {
  description = "Egress SFTP users with read-only access to the egress bucket. home_directory_prefix must start and end with / (use / for full bucket access, or a subdirectory like /outbound/partner-a/ to scope access)."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = string
  }))
  default = []

  validation {
    condition = alltrue([
      for user in var.sftp_egress_users :
      can(regex("^/", user.home_directory_prefix)) && can(regex("/$", user.home_directory_prefix))
    ])
    error_message = "Each sftp_egress_users home_directory_prefix must start and end with / (e.g. / for full bucket or /outbound/partner-a/ for scoped access)."
  }

  validation {
    condition = alltrue([
      for user in var.sftp_egress_users :
      !can(regex("\\.\\.(/|$)", user.home_directory_prefix))
    ])
    error_message = "sftp_egress_users home_directory_prefix must not contain '..' path traversal segments."
  }
}

################################################################################
# S3 Lifecycle
################################################################################

variable "ingress_lifecycle_days" {
  description = "Number of days before objects in the ingress bucket expire."
  type        = number
  default     = 1

  validation {
    condition     = var.ingress_lifecycle_days > 0
    error_message = "ingress_lifecycle_days must be a positive number."
  }
}

variable "egress_lifecycle_days" {
  description = "Number of days before objects in the egress bucket transition to Infrequent Access."
  type        = number
  default     = 90

  validation {
    condition     = var.egress_lifecycle_days > 0
    error_message = "egress_lifecycle_days must be a positive number."
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

################################################################################
# Lambda — File Router
################################################################################

variable "lambda_runtime" {
  description = "Lambda runtime identifier for the file-router function."
  type        = string
  default     = "python3.12"

  validation {
    condition     = can(regex("^python3\\.", var.lambda_runtime))
    error_message = "lambda_runtime must be a Python 3.x runtime (e.g. python3.12, python3.13)."
  }
}

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
  description = "Reserved concurrent executions for the file-router Lambda function. Set to -1 to use unreserved account concurrency."
  type        = number
  default     = 10

  validation {
    condition     = var.lambda_reserved_concurrency == -1 || var.lambda_reserved_concurrency >= 1
    error_message = "lambda_reserved_concurrency must be -1 (unreserved) or at least 1."
  }
}

################################################################################
# Notifications
################################################################################

variable "sns_subscription_emails" {
  description = "Email addresses subscribed to the malware-alert SNS topic."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for email in var.sns_subscription_emails :
      can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))
    ])
    error_message = "Each sns_subscription_emails entry must be a valid email address (e.g. user@example.com)."
  }
}

################################################################################
# Quarantine — Object Lock
################################################################################

variable "enable_object_lock" {
  description = "Enable S3 Object Lock on the quarantine bucket for tamper-proof retention."
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "Default retention period in days for Object Lock on the quarantine bucket."
  type        = number
  default     = 365

  validation {
    condition     = var.object_lock_retention_days > 0
    error_message = "object_lock_retention_days must be a positive number."
  }
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

################################################################################
# Egress Notifications
################################################################################

variable "enable_egress_notifications" {
  description = "Enable SNS notifications when clean files are delivered to the egress bucket. Creates a separate SNS topic for egress events."
  type        = bool
  default     = false
}

variable "egress_notification_emails" {
  description = "Email addresses subscribed to the egress notification SNS topic. Only used when enable_egress_notifications is true."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for email in var.egress_notification_emails :
      can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))
    ])
    error_message = "Each egress_notification_emails entry must be a valid email address."
  }
}

################################################################################
# VirusTotal Hash Lookup
################################################################################

variable "enable_virustotal_scanning" {
  description = "Enable VirusTotal hash lookup scanning. When true, files that pass GuardDuty scanning are checked against the VirusTotal API before prompt injection scanning."
  type        = bool
  default     = false
}

variable "virustotal_api_key" {
  description = "VirusTotal API key. Required when enable_virustotal_scanning is true. Stored as an SSM SecureString parameter."
  type        = string
  default     = null
  sensitive   = true

  validation {
    condition     = !var.enable_virustotal_scanning || var.virustotal_api_key != null
    error_message = "virustotal_api_key is required when enable_virustotal_scanning is true."
  }
}

variable "virustotal_threshold" {
  description = "Number of VirusTotal positive detections at or above which a file is quarantined."
  type        = number
  default     = 3

  validation {
    condition     = var.virustotal_threshold >= 1
    error_message = "virustotal_threshold must be at least 1."
  }
}

################################################################################
# Audit Trail
################################################################################

variable "enable_audit_trail" {
  description = "Enable a DynamoDB audit trail that records every file at each pipeline stage."
  type        = bool
  default     = false
}

variable "audit_trail_retention_days" {
  description = "Number of days to retain audit trail records. Set to 0 to retain forever."
  type        = number
  default     = 365

  validation {
    condition     = var.audit_trail_retention_days >= 0
    error_message = "audit_trail_retention_days must be 0 (forever) or a positive number."
  }
}

################################################################################
# Observability
################################################################################

variable "enable_cloudwatch_dashboard" {
  description = "Create a CloudWatch dashboard with metric filters for pipeline observability. When false (default), no dashboard or metric filter resources are created."
  type        = bool
  default     = false
}

################################################################################
# Logging
################################################################################

variable "create_log_bucket" {
  description = "Whether to create a managed S3 access-log bucket. Set to false when shipping logs to an existing bucket via log_bucket_name."
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Name of an existing S3 bucket for access-log shipping. Required when create_log_bucket is false. The caller is responsible for the external bucket's policy."
  type        = string
  default     = null

  validation {
    condition     = var.create_log_bucket || var.log_bucket_name != null
    error_message = "log_bucket_name is required when create_log_bucket is false."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "s3_log_retention_days" {
  description = "Number of days to retain S3 access logs in the log bucket."
  type        = number
  default     = 90

  validation {
    condition     = var.s3_log_retention_days > 0
    error_message = "s3_log_retention_days must be a positive number."
  }
}
