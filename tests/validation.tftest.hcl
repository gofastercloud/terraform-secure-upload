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

run "invalid_name_prefix" {
  command = plan

  variables {
    name_prefix = "Test-Upload"
  }

  expect_failures = [var.name_prefix]
}

run "kms_key_required_when_not_created" {
  command = plan

  variables {
    name_prefix    = "test-val"
    create_kms_key = false
  }

  expect_failures = [var.kms_key_arn]
}

run "sftp_requires_vpc_configuration" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = null
    sftp_subnet_ids             = ["subnet-a"]
    sftp_address_allocation_ids = ["eipalloc-a"]
    sftp_allowed_cidrs          = ["203.0.113.10/32"]
    sftp_users                  = []
  }

  expect_failures = [var.sftp_vpc_id]
}

run "sftp_requires_subnets" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = "vpc-12345678"
    sftp_subnet_ids             = []
    sftp_address_allocation_ids = []
    sftp_allowed_cidrs          = ["203.0.113.10/32"]
  }

  expect_failures = [var.sftp_subnet_ids]
}

run "sftp_requires_matching_elastic_ips" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = "vpc-12345678"
    sftp_subnet_ids             = ["subnet-a", "subnet-b"]
    sftp_address_allocation_ids = ["eipalloc-a"]
    sftp_allowed_cidrs          = ["203.0.113.10/32"]
  }

  expect_failures = [var.sftp_address_allocation_ids]
}

run "sftp_rejects_open_ingress" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = "vpc-12345678"
    sftp_subnet_ids             = ["subnet-a"]
    sftp_address_allocation_ids = ["eipalloc-a"]
    sftp_allowed_cidrs          = ["0.0.0.0/0"]
  }

  expect_failures = [var.sftp_allowed_cidrs]
}

run "sftp_rejects_bare_home" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = "vpc-12345678"
    sftp_subnet_ids             = ["subnet-a"]
    sftp_address_allocation_ids = ["eipalloc-a"]
    sftp_allowed_cidrs          = ["203.0.113.10/32"]
    sftp_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample testuser@example.com"
        home_directory_prefix = "/"
      }
    ]
  }

  expect_failures = [var.sftp_users]
}

run "sftp_rejects_path_traversal" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = "vpc-12345678"
    sftp_subnet_ids             = ["subnet-a"]
    sftp_address_allocation_ids = ["eipalloc-a"]
    sftp_allowed_cidrs          = ["203.0.113.10/32"]
    sftp_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample testuser@example.com"
        home_directory_prefix = "/uploads/../etc/"
      }
    ]
  }

  expect_failures = [var.sftp_users]
}

run "sftp_rejects_overlapping_home_prefixes" {
  command = plan

  variables {
    name_prefix                 = "test-val"
    enable_sftp                 = true
    sftp_vpc_id                 = "vpc-12345678"
    sftp_subnet_ids             = ["subnet-a"]
    sftp_address_allocation_ids = ["eipalloc-a"]
    sftp_allowed_cidrs          = ["203.0.113.10/32"]
    sftp_users = [
      {
        username              = "partner"
        ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample partner@example.com"
        home_directory_prefix = "/uploads/partner/"
      },
      {
        username              = "partner-acme"
        ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample partner-acme@example.com"
        home_directory_prefix = "/uploads/partner/acme/"
      }
    ]
  }

  expect_failures = [var.sftp_users]
}
