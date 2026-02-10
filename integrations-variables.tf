################################################################################
# Slack Integration (AWS Chatbot)
################################################################################

variable "enable_slack_integration" {
  description = "Enable Slack notifications for malware alerts via AWS Chatbot."
  type        = bool
  default     = false
}

variable "slack_workspace_id" {
  description = "Slack workspace (team) ID (e.g. T-xxxxxxx). Required when enable_slack_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_slack_integration || var.slack_workspace_id != null
    error_message = "slack_workspace_id is required when enable_slack_integration is true."
  }
}

variable "slack_channel_id" {
  description = "Slack channel ID to receive alerts (e.g. C-xxxxxxx). Required when enable_slack_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_slack_integration || var.slack_channel_id != null
    error_message = "slack_channel_id is required when enable_slack_integration is true."
  }
}

################################################################################
# Microsoft Teams Integration (AWS Chatbot)
################################################################################

variable "enable_teams_integration" {
  description = "Enable Microsoft Teams notifications for malware alerts via AWS Chatbot."
  type        = bool
  default     = false
}

variable "teams_tenant_id" {
  description = "Microsoft Teams tenant ID. Required when enable_teams_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_teams_integration || var.teams_tenant_id != null
    error_message = "teams_tenant_id is required when enable_teams_integration is true."
  }
}

variable "teams_team_id" {
  description = "Microsoft Teams team ID. Required when enable_teams_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_teams_integration || var.teams_team_id != null
    error_message = "teams_team_id is required when enable_teams_integration is true."
  }
}

variable "teams_channel_id" {
  description = "Microsoft Teams channel ID to receive alerts. Required when enable_teams_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_teams_integration || var.teams_channel_id != null
    error_message = "teams_channel_id is required when enable_teams_integration is true."
  }
}

################################################################################
# PagerDuty
################################################################################

variable "pagerduty_integration_url" {
  description = "PagerDuty Events v2 integration URL for malware alert notifications. When non-null, an SNS HTTPS subscription is created to forward alerts to PagerDuty."
  type        = string
  default     = null

  validation {
    condition     = var.pagerduty_integration_url == null || can(regex("^https://events\\.pagerduty\\.com/", var.pagerduty_integration_url))
    error_message = "pagerduty_integration_url must start with https://events.pagerduty.com/ when provided."
  }
}

################################################################################
# VictorOps / Splunk On-Call
################################################################################

variable "victorops_integration_url" {
  description = "VictorOps (Splunk On-Call) REST endpoint URL for malware alert notifications. When non-null, an SNS HTTPS subscription is created to forward alerts to VictorOps."
  type        = string
  default     = null

  validation {
    condition     = var.victorops_integration_url == null || can(regex("^https://alert\\.victorops\\.com/", var.victorops_integration_url))
    error_message = "victorops_integration_url must start with https://alert.victorops.com/ when provided."
  }
}

################################################################################
# Discord Integration (Webhook)
################################################################################

variable "enable_discord_integration" {
  description = "Enable Discord webhook notifications for malware alerts."
  type        = bool
  default     = false
}

variable "discord_webhook_url" {
  description = "Discord webhook URL for malware alert notifications. Required when enable_discord_integration is true."
  type        = string
  default     = null
  sensitive   = true

  validation {
    condition     = !var.enable_discord_integration || var.discord_webhook_url != null
    error_message = "discord_webhook_url is required when enable_discord_integration is true."
  }
}

################################################################################
# ServiceNow Integration (Incident Creation)
################################################################################

variable "enable_servicenow_integration" {
  description = "Enable ServiceNow incident creation for malware alerts."
  type        = bool
  default     = false
}

variable "servicenow_instance_url" {
  description = "ServiceNow instance URL (e.g. https://mycompany.service-now.com). Required when enable_servicenow_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_servicenow_integration || var.servicenow_instance_url != null
    error_message = "servicenow_instance_url is required when enable_servicenow_integration is true."
  }
}

variable "servicenow_credentials_secret_arn" {
  description = "ARN of an AWS Secrets Manager secret containing ServiceNow credentials (JSON with 'username' and 'password' keys). Required when enable_servicenow_integration is true."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_servicenow_integration || var.servicenow_credentials_secret_arn != null
    error_message = "servicenow_credentials_secret_arn is required when enable_servicenow_integration is true."
  }

  validation {
    condition     = var.servicenow_credentials_secret_arn == null || can(regex("^arn:aws:secretsmanager:", var.servicenow_credentials_secret_arn))
    error_message = "servicenow_credentials_secret_arn must be a valid Secrets Manager ARN."
  }
}
