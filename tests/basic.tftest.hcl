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

variables {
  name_prefix = "test-upload"
}

run "sftp_disabled" {
  command = plan

  assert {
    condition     = output.sftp_server_id == null
    error_message = "SFTP server ID should be null when SFTP is disabled"
  }

  assert {
    condition     = output.sftp_server_endpoint == null
    error_message = "SFTP endpoint should be null when SFTP is disabled"
  }

  assert {
    condition     = output.sftp_user_arns == {}
    error_message = "SFTP users should be empty when SFTP is disabled"
  }
}
