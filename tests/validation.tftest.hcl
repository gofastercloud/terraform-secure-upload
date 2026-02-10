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
    name_prefix         = "test-val"
    enable_sftp_ingress = false
    sftp_endpoint_type  = "INVALID"
  }

  expect_failures = [
    var.sftp_endpoint_type,
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
