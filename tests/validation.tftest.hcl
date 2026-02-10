################################################################################
# Variable Validation Rule Tests
################################################################################

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:root"
      user_id    = "AKIAIOSFODNN7EXAMPLE"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

################################################################################
# Test: Invalid sftp_endpoint_type fails
################################################################################

run "invalid_endpoint_type" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = false
    sftp_ingress_endpoint_type = "INVALID"
  }

  expect_failures = [
    var.sftp_ingress_endpoint_type,
  ]
}

################################################################################
# Test: Negative ingress_lifecycle_days fails
################################################################################

run "negative_ingress_lifecycle" {
  command = plan

  variables {
    name_prefix            = "test-val"
    enable_sftp_ingress    = false
    ingress_lifecycle_days = -1
  }

  expect_failures = [
    var.ingress_lifecycle_days,
  ]
}

################################################################################
# Test: Zero ingress_lifecycle_days fails
################################################################################

run "zero_ingress_lifecycle" {
  command = plan

  variables {
    name_prefix            = "test-val"
    enable_sftp_ingress    = false
    ingress_lifecycle_days = 0
  }

  expect_failures = [
    var.ingress_lifecycle_days,
  ]
}

################################################################################
# Test: Negative egress_lifecycle_days fails
################################################################################

run "negative_egress_lifecycle" {
  command = plan

  variables {
    name_prefix           = "test-val"
    enable_sftp_ingress   = false
    egress_lifecycle_days = -5
  }

  expect_failures = [
    var.egress_lifecycle_days,
  ]
}

################################################################################
# Test: Negative quarantine_lifecycle_days fails
################################################################################

run "negative_quarantine_lifecycle" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    quarantine_lifecycle_days = -10
  }

  expect_failures = [
    var.quarantine_lifecycle_days,
  ]
}

################################################################################
# Test: Invalid name_prefix fails (uppercase)
################################################################################

run "invalid_name_prefix_uppercase" {
  command = plan

  variables {
    name_prefix         = "Test-Upload"
    enable_sftp_ingress = false
  }

  expect_failures = [
    var.name_prefix,
  ]
}

################################################################################
# Test: Invalid name_prefix fails (special chars)
################################################################################

run "invalid_name_prefix_special_chars" {
  command = plan

  variables {
    name_prefix         = "test_upload!"
    enable_sftp_ingress = false
  }

  expect_failures = [
    var.name_prefix,
  ]
}

################################################################################
# Test: create_kms_key=false without kms_key_arn should fail
################################################################################

run "kms_key_required_when_not_creating" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    create_kms_key      = false
    kms_key_arn         = null
  }

  expect_failures = [
    var.kms_key_arn,
  ]
}

################################################################################
# Test: create_log_bucket=false without log_bucket_name fails
################################################################################

run "log_bucket_name_required_when_not_creating" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    create_log_bucket   = false
    log_bucket_name     = null
  }

  expect_failures = [
    var.log_bucket_name,
  ]
}

################################################################################
# Test: Invalid lambda_memory_size (too low)
################################################################################

run "lambda_memory_too_low" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    lambda_memory_size  = 64
  }

  expect_failures = [
    var.lambda_memory_size,
  ]
}

################################################################################
# Test: Invalid lambda_memory_size (too high)
################################################################################

run "lambda_memory_too_high" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    lambda_memory_size  = 20480
  }

  expect_failures = [
    var.lambda_memory_size,
  ]
}

################################################################################
# Test: Invalid lambda_timeout (zero)
################################################################################

run "lambda_timeout_zero" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    lambda_timeout      = 0
  }

  expect_failures = [
    var.lambda_timeout,
  ]
}

################################################################################
# Test: Invalid lambda_timeout (exceeds max)
################################################################################

run "lambda_timeout_exceeds_max" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    lambda_timeout      = 901
  }

  expect_failures = [
    var.lambda_timeout,
  ]
}

################################################################################
# Test: Invalid log_retention_days
################################################################################

run "invalid_log_retention" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    log_retention_days  = 42
  }

  expect_failures = [
    var.log_retention_days,
  ]
}

################################################################################
# Test: Invalid lambda_reserved_concurrency (zero)
################################################################################

run "lambda_concurrency_zero" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp_ingress         = false
    lambda_reserved_concurrency = 0
  }

  expect_failures = [
    var.lambda_reserved_concurrency,
  ]
}

################################################################################
# Test: sftp_users bare "/" home_directory_prefix fails
################################################################################

run "sftp_user_bare_slash_prefix" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-rsa AAAAB3example testuser@example.com"
        home_directory_prefix = "/"
      }
    ]
  }

  expect_failures = [
    var.sftp_ingress_users,
  ]
}

################################################################################
# Test: sftp_users path traversal ".." fails
################################################################################

run "sftp_user_path_traversal" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-rsa AAAAB3example testuser@example.com"
        home_directory_prefix = "/uploads/../etc/"
      }
    ]
  }

  expect_failures = [
    var.sftp_ingress_users,
  ]
}

################################################################################
# Test: sftp_users missing trailing slash fails
################################################################################

run "sftp_user_missing_trailing_slash" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-rsa AAAAB3example testuser@example.com"
        home_directory_prefix = "/uploads/testuser"
      }
    ]
  }

  expect_failures = [
    var.sftp_ingress_users,
  ]
}

################################################################################
# Test: sftp_server_id required when using existing server
################################################################################

run "sftp_server_id_required_when_existing" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = false
    sftp_ingress_server_id     = null
    sftp_ingress_users         = []
  }

  expect_failures = [
    var.sftp_ingress_server_id,
  ]
}

################################################################################
# Test: sftp_egress_server_id required when using existing egress server
################################################################################

run "sftp_egress_server_id_required_when_existing" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    enable_sftp_egress        = true
    create_sftp_egress_server = false
    sftp_egress_server_id     = null
  }

  expect_failures = [
    var.sftp_egress_server_id,
  ]
}

################################################################################
# Test: sftp_egress_users missing leading slash fails
################################################################################

run "sftp_egress_user_missing_leading_slash" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    enable_sftp_egress  = true
    sftp_egress_users = [
      {
        username              = "receiver"
        ssh_public_key        = "ssh-rsa AAAAB3example receiver@example.com"
        home_directory_prefix = "outbound/"
      }
    ]
  }

  expect_failures = [
    var.sftp_egress_users,
  ]
}

################################################################################
# Test: sftp_egress_users path traversal fails
################################################################################

run "sftp_egress_user_path_traversal" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    enable_sftp_egress  = true
    sftp_egress_users = [
      {
        username              = "receiver"
        ssh_public_key        = "ssh-rsa AAAAB3example receiver@example.com"
        home_directory_prefix = "/outbound/../secrets/"
      }
    ]
  }

  expect_failures = [
    var.sftp_egress_users,
  ]
}

################################################################################
# Test: VPC endpoint type without vpc_id fails (ingress)
################################################################################

run "ingress_vpc_missing_vpc_id" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_endpoint_type = "VPC"
    sftp_ingress_vpc_id        = null
    sftp_ingress_subnet_ids    = ["subnet-abc123"]
    sftp_ingress_allowed_cidrs = ["10.0.0.0/8"]
    sftp_ingress_users         = []
  }

  expect_failures = [
    var.sftp_ingress_vpc_id,
  ]
}

################################################################################
# Test: VPC endpoint type without subnet_ids fails (ingress)
################################################################################

run "ingress_vpc_missing_subnet_ids" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_endpoint_type = "VPC"
    sftp_ingress_vpc_id        = "vpc-abc123"
    sftp_ingress_subnet_ids    = []
    sftp_ingress_allowed_cidrs = ["10.0.0.0/8"]
    sftp_ingress_users         = []
  }

  expect_failures = [
    var.sftp_ingress_subnet_ids,
  ]
}

################################################################################
# Test: VPC endpoint type without allowed_cidrs fails (ingress)
################################################################################

run "ingress_vpc_missing_allowed_cidrs" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_endpoint_type = "VPC"
    sftp_ingress_vpc_id        = "vpc-abc123"
    sftp_ingress_subnet_ids    = ["subnet-abc123"]
    sftp_ingress_allowed_cidrs = []
    sftp_ingress_users         = []
  }

  expect_failures = [
    var.sftp_ingress_allowed_cidrs,
  ]
}

################################################################################
# Test: VPC endpoint type without vpc_id fails (egress)
################################################################################

run "egress_vpc_missing_vpc_id" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    enable_sftp_egress        = true
    create_sftp_egress_server = true
    sftp_egress_endpoint_type = "VPC"
    sftp_egress_vpc_id        = null
    sftp_egress_subnet_ids    = ["subnet-abc123"]
    sftp_egress_allowed_cidrs = ["10.0.0.0/8"]
  }

  expect_failures = [
    var.sftp_egress_vpc_id,
  ]
}

################################################################################
# Test: VPC endpoint type without subnet_ids fails (egress)
################################################################################

run "egress_vpc_missing_subnet_ids" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    enable_sftp_egress        = true
    create_sftp_egress_server = true
    sftp_egress_endpoint_type = "VPC"
    sftp_egress_vpc_id        = "vpc-abc123"
    sftp_egress_subnet_ids    = []
    sftp_egress_allowed_cidrs = ["10.0.0.0/8"]
  }

  expect_failures = [
    var.sftp_egress_subnet_ids,
  ]
}

################################################################################
# Test: VPC endpoint type without allowed_cidrs fails (egress)
################################################################################

run "egress_vpc_missing_allowed_cidrs" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    enable_sftp_egress        = true
    create_sftp_egress_server = true
    sftp_egress_endpoint_type = "VPC"
    sftp_egress_vpc_id        = "vpc-abc123"
    sftp_egress_subnet_ids    = ["subnet-abc123"]
    sftp_egress_allowed_cidrs = []
  }

  expect_failures = [
    var.sftp_egress_allowed_cidrs,
  ]
}

################################################################################
# Test: Invalid email in sns_subscription_emails fails
################################################################################

run "invalid_sns_email" {
  command = plan

  variables {
    name_prefix             = "test-val"
    enable_sftp_ingress     = false
    sns_subscription_emails = ["not-an-email"]
  }

  expect_failures = [
    var.sns_subscription_emails,
  ]
}

################################################################################
# Test: Valid emails in sns_subscription_emails pass
################################################################################

run "valid_sns_emails" {
  command = plan

  variables {
    name_prefix             = "test-val"
    enable_sftp_ingress     = false
    sns_subscription_emails = ["admin@example.com", "ops@corp.co.uk"]
  }
}

################################################################################
# Test: CloudWatch dashboard disabled by default
################################################################################

run "dashboard_disabled_by_default" {
  command = plan

  variables {
    name_prefix         = "test-val"
    enable_sftp_ingress = false
  }

  assert {
    condition     = output.cloudwatch_dashboard_arn == null
    error_message = "Dashboard ARN should be null when enable_cloudwatch_dashboard is false"
  }
}

################################################################################
# Integration variable validation tests
################################################################################

run "slack_missing_workspace_id" {
  command = plan

  variables {
    name_prefix              = "test-val"
    enable_sftp_ingress      = false
    enable_slack_integration = true
    slack_workspace_id       = null
    slack_channel_id         = "C0XXXXXXXXX"
  }

  expect_failures = [
    var.slack_workspace_id,
  ]
}

run "slack_missing_channel_id" {
  command = plan

  variables {
    name_prefix              = "test-val"
    enable_sftp_ingress      = false
    enable_slack_integration = true
    slack_workspace_id       = "T0XXXXXXXXX"
    slack_channel_id         = null
  }

  expect_failures = [
    var.slack_channel_id,
  ]
}

run "teams_missing_tenant_id" {
  command = plan

  variables {
    name_prefix              = "test-val"
    enable_sftp_ingress      = false
    enable_teams_integration = true
    teams_tenant_id          = null
    teams_team_id            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    teams_channel_id         = "19:xxx@thread.tacv2"
  }

  expect_failures = [
    var.teams_tenant_id,
  ]
}

run "teams_missing_team_id" {
  command = plan

  variables {
    name_prefix              = "test-val"
    enable_sftp_ingress      = false
    enable_teams_integration = true
    teams_tenant_id          = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    teams_team_id            = null
    teams_channel_id         = "19:xxx@thread.tacv2"
  }

  expect_failures = [
    var.teams_team_id,
  ]
}

run "teams_missing_channel_id" {
  command = plan

  variables {
    name_prefix              = "test-val"
    enable_sftp_ingress      = false
    enable_teams_integration = true
    teams_tenant_id          = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    teams_team_id            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    teams_channel_id         = null
  }

  expect_failures = [
    var.teams_channel_id,
  ]
}

run "pagerduty_invalid_url" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    pagerduty_integration_url = "https://example.com/not-pagerduty"
  }

  expect_failures = [
    var.pagerduty_integration_url,
  ]
}

run "victorops_invalid_url" {
  command = plan

  variables {
    name_prefix               = "test-val"
    enable_sftp_ingress       = false
    victorops_integration_url = "https://example.com/not-victorops"
  }

  expect_failures = [
    var.victorops_integration_url,
  ]
}

run "discord_missing_webhook_url" {
  command = plan

  variables {
    name_prefix                = "test-val"
    enable_sftp_ingress        = false
    enable_discord_integration = true
    discord_webhook_url        = null
  }

  expect_failures = [
    var.discord_webhook_url,
  ]
}

run "servicenow_missing_instance_url" {
  command = plan

  variables {
    name_prefix                       = "test-val"
    enable_sftp_ingress               = false
    enable_servicenow_integration     = true
    servicenow_instance_url           = null
    servicenow_credentials_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"
  }

  expect_failures = [
    var.servicenow_instance_url,
  ]
}

run "servicenow_missing_credentials_arn" {
  command = plan

  variables {
    name_prefix                       = "test-val"
    enable_sftp_ingress               = false
    enable_servicenow_integration     = true
    servicenow_instance_url           = "https://mycompany.service-now.com"
    servicenow_credentials_secret_arn = null
  }

  expect_failures = [
    var.servicenow_credentials_secret_arn,
  ]
}

run "servicenow_invalid_credentials_arn" {
  command = plan

  variables {
    name_prefix                       = "test-val"
    enable_sftp_ingress               = false
    enable_servicenow_integration     = true
    servicenow_instance_url           = "https://mycompany.service-now.com"
    servicenow_credentials_secret_arn = "arn:aws:s3:::not-a-secret"
  }

  expect_failures = [
    var.servicenow_credentials_secret_arn,
  ]
}
