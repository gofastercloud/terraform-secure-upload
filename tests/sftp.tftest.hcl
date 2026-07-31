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

run "sftp_vpc_internet_server" {
  command = plan

  module {
    source = "./modules/sftp"
  }

  variables {
    name_prefix            = "test-sftp"
    vpc_id                 = "vpc-12345678"
    subnet_ids             = ["subnet-a", "subnet-b"]
    address_allocation_ids = ["eipalloc-a", "eipalloc-b"]
    allowed_cidrs          = ["203.0.113.10/32"]
    custom_hostname        = "sftp.example.com"
    bucket_name            = "test-ingress"
    bucket_arn             = "arn:aws:s3:::test-ingress"
    kms_key_arn            = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    sftp_users = [
      {
        username              = "partner-a"
        ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample partner-a@example.com"
        home_directory_prefix = "/uploads/partner-a/"
      }
    ]
  }

  assert {
    condition     = aws_transfer_server.this.endpoint_type == "VPC"
    error_message = "SFTP must use a VPC-hosted endpoint"
  }

  assert {
    condition     = aws_transfer_server.this.s3_storage_options[0].directory_listing_optimization == "ENABLED"
    error_message = "Transfer Family S3 directory listing optimization must be enabled"
  }

  assert {
    condition     = aws_transfer_tag.custom_hostname[0].value == "sftp.example.com"
    error_message = "Custom hostname must be applied using the Transfer Family system tag"
  }

  assert {
    condition     = toset(aws_transfer_server.this.endpoint_details[0].address_allocation_ids) == toset(["eipalloc-a", "eipalloc-b"])
    error_message = "Internet-facing SFTP must attach one Elastic IP allocation per subnet"
  }

  assert {
    condition     = aws_transfer_user.this["partner-a"].home_directory_type == "LOGICAL" && aws_transfer_user.this["partner-a"].home_directory_mappings[0].entry == "/" && aws_transfer_user.this["partner-a"].home_directory_mappings[0].target == "/test-ingress/uploads/partner-a"
    error_message = "SFTP users must receive a logical root mapped to their S3 home prefix"
  }

}
