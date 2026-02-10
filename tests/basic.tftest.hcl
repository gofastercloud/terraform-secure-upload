################################################################################
# Basic Module Instantiation Tests
################################################################################

provider "aws" {
  region = "us-east-1"
}

variables {
  name_prefix         = "test-upload"
  enable_sftp_ingress = false
}

run "basic_plan" {
  command = plan

  assert {
    condition     = output.ingress_bucket_arn != ""
    error_message = "Ingress bucket ARN should not be empty"
  }

  assert {
    condition     = output.egress_bucket_arn != ""
    error_message = "Egress bucket ARN should not be empty"
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

  assert {
    condition     = output.log_bucket_arn != ""
    error_message = "Log bucket ARN should not be empty"
  }

  assert {
    condition     = output.dlq_arn != ""
    error_message = "DLQ ARN should not be empty"
  }

  assert {
    condition     = output.eventbridge_rule_arn != ""
    error_message = "EventBridge rule ARN should not be empty"
  }
}

run "sftp_disabled" {
  command = plan

  assert {
    condition     = output.sftp_ingress_server_id == null
    error_message = "SFTP server ID should be null when enable_sftp_ingress is false"
  }

  assert {
    condition     = output.sftp_ingress_server_endpoint == null
    error_message = "SFTP server endpoint should be null when enable_sftp_ingress is false"
  }

  assert {
    condition     = output.sftp_egress_server_id == null
    error_message = "Egress SFTP server ID should be null when enable_sftp_egress is false"
  }

  assert {
    condition     = output.sftp_egress_server_endpoint == null
    error_message = "Egress SFTP server endpoint should be null when enable_sftp_egress is false"
  }
}

run "bucket_naming" {
  command = plan

  assert {
    condition     = output.ingress_bucket_id == "test-upload-ingress"
    error_message = "Ingress bucket should follow naming convention: ${output.ingress_bucket_id}"
  }

  assert {
    condition     = output.egress_bucket_id == "test-upload-egress"
    error_message = "Egress bucket should follow naming convention: ${output.egress_bucket_id}"
  }

  assert {
    condition     = output.quarantine_bucket_id == "test-upload-quarantine"
    error_message = "Quarantine bucket should follow naming convention: ${output.quarantine_bucket_id}"
  }
}
