################################################################################
# Variable Validation Rule Tests
################################################################################

provider "aws" {
  region = "us-east-1"
}

################################################################################
# Test: Invalid sftp_endpoint_type fails
################################################################################

run "invalid_endpoint_type" {
  command = plan

  variables {
    name_prefix        = "test-val"
    enable_sftp        = true
    sftp_endpoint_type = "INVALID"
  }

  expect_failures = [
    var.sftp_endpoint_type,
  ]
}

################################################################################
# Test: Negative staging_lifecycle_days fails
################################################################################

run "negative_staging_lifecycle" {
  command = plan

  variables {
    name_prefix           = "test-val"
    enable_sftp           = false
    staging_lifecycle_days = -1
  }

  expect_failures = [
    var.staging_lifecycle_days,
  ]
}

################################################################################
# Test: Zero staging_lifecycle_days fails
################################################################################

run "zero_staging_lifecycle" {
  command = plan

  variables {
    name_prefix           = "test-val"
    enable_sftp           = false
    staging_lifecycle_days = 0
  }

  expect_failures = [
    var.staging_lifecycle_days,
  ]
}

################################################################################
# Test: Negative clean_lifecycle_days fails
################################################################################

run "negative_clean_lifecycle" {
  command = plan

  variables {
    name_prefix          = "test-val"
    enable_sftp          = false
    clean_lifecycle_days = -5
  }

  expect_failures = [
    var.clean_lifecycle_days,
  ]
}

################################################################################
# Test: Negative quarantine_lifecycle_days fails
################################################################################

run "negative_quarantine_lifecycle" {
  command = plan

  variables {
    name_prefix              = "test-val"
    enable_sftp              = false
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
    name_prefix = "Test-Upload"
    enable_sftp = false
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
    name_prefix = "test_upload!"
    enable_sftp = false
  }

  expect_failures = [
    var.name_prefix,
  ]
}

################################################################################
# Test: Invalid lambda_memory_size (too low)
################################################################################

run "lambda_memory_too_low" {
  command = plan

  variables {
    name_prefix       = "test-val"
    enable_sftp       = false
    lambda_memory_size = 64
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
    name_prefix       = "test-val"
    enable_sftp       = false
    lambda_memory_size = 20480
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
    name_prefix    = "test-val"
    enable_sftp    = false
    lambda_timeout = 0
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
    name_prefix    = "test-val"
    enable_sftp    = false
    lambda_timeout = 901
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
    name_prefix        = "test-val"
    enable_sftp        = false
    log_retention_days = 42
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
    enable_sftp                 = false
    lambda_reserved_concurrency = 0
  }

  expect_failures = [
    var.lambda_reserved_concurrency,
  ]
}
