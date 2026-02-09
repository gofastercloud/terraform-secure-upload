################################################################################
# Basic Module Instantiation Tests
################################################################################

provider "aws" {
  region = "us-east-1"
}

variables {
  name_prefix = "test-upload"
  enable_sftp = false
}

run "basic_plan" {
  command = plan

  assert {
    condition     = output.staging_bucket_arn != ""
    error_message = "Staging bucket ARN should not be empty"
  }

  assert {
    condition     = output.clean_bucket_arn != ""
    error_message = "Clean bucket ARN should not be empty"
  }

  assert {
    condition     = output.quarantine_bucket_arn != ""
    error_message = "Quarantine bucket ARN should not be empty"
  }

  assert {
    condition     = output.sns_topic_arn != ""
    error_message = "SNS topic ARN should not be empty"
  }

  assert {
    condition     = output.kms_key_arn != ""
    error_message = "KMS key ARN should not be empty"
  }

  assert {
    condition     = output.lambda_function_arn != ""
    error_message = "Lambda function ARN should not be empty"
  }

  assert {
    condition     = output.guardduty_protection_plan_arn != ""
    error_message = "GuardDuty protection plan ARN should not be empty"
  }

  assert {
    condition     = output.log_bucket_id != ""
    error_message = "Log bucket ID should not be empty"
  }
}

run "sftp_disabled" {
  command = plan

  assert {
    condition     = output.sftp_server_id == null
    error_message = "SFTP server ID should be null when enable_sftp is false"
  }

  assert {
    condition     = output.sftp_server_endpoint == null
    error_message = "SFTP server endpoint should be null when enable_sftp is false"
  }
}

run "bucket_naming" {
  command = plan

  assert {
    condition     = output.staging_bucket_id == "test-upload-staging"
    error_message = "Staging bucket should follow naming convention: ${output.staging_bucket_id}"
  }

  assert {
    condition     = output.clean_bucket_id == "test-upload-clean"
    error_message = "Clean bucket should follow naming convention: ${output.clean_bucket_id}"
  }

  assert {
    condition     = output.quarantine_bucket_id == "test-upload-quarantine"
    error_message = "Quarantine bucket should follow naming convention: ${output.quarantine_bucket_id}"
  }
}
