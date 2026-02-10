################################################################################
# SFTP Egress Tests
################################################################################

provider "aws" {
  region = "us-east-1"
}

################################################################################
# Test: Egress server with public endpoint and users
################################################################################

run "sftp_egress_public_server" {
  command = plan

  variables {
    name_prefix        = "test-egress-pub"
    enable_sftp_egress = true
    sftp_egress_users = [
      {
        username              = "receiver"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7egress receiver@example.com"
        home_directory_prefix = "/outbound/receiver/"
      }
    ]
  }

  assert {
    condition     = output.sftp_egress_server_id != null
    error_message = "Egress SFTP server ID should be populated"
  }

  assert {
    condition     = output.sftp_egress_server_endpoint != null
    error_message = "Egress SFTP server endpoint should be populated when creating a new server"
  }
}

################################################################################
# Test: Egress with existing server ID
################################################################################

run "sftp_egress_existing_server" {
  command = plan

  variables {
    name_prefix               = "test-egress-exist"
    enable_sftp_egress        = true
    create_sftp_egress_server = false
    sftp_egress_server_id     = "s-1234567890abcdef0"
    sftp_egress_users = [
      {
        username              = "receiver"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7egress receiver@example.com"
        home_directory_prefix = "/outbound/receiver/"
      }
    ]
  }

  assert {
    condition     = output.sftp_egress_server_id != null
    error_message = "Egress SFTP server ID should be populated when using existing server"
  }

  assert {
    condition     = output.sftp_egress_server_endpoint == null
    error_message = "Egress SFTP server endpoint should be null when using existing server"
  }
}

################################################################################
# Test: Multiple egress users with different home prefixes
################################################################################

run "sftp_egress_multiple_users" {
  command = plan

  variables {
    name_prefix        = "test-egress-multi"
    enable_sftp_egress = true
    sftp_egress_users = [
      {
        username              = "partner-a"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7egressA partner-a@example.com"
        home_directory_prefix = "/outbound/partner-a/"
      },
      {
        username              = "partner-b"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7egressB partner-b@example.com"
        home_directory_prefix = "/outbound/partner-b/"
      },
    ]
  }

  assert {
    condition     = output.sftp_egress_server_id != null
    error_message = "Egress SFTP server ID should be populated with multiple users"
  }
}

################################################################################
# Test: Egress user with bare / home directory (allowed for egress)
################################################################################

run "sftp_egress_bare_root_home" {
  command = plan

  variables {
    name_prefix        = "test-egress-root"
    enable_sftp_egress = true
    sftp_egress_users = [
      {
        username              = "full-access"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7egressRoot full-access@example.com"
        home_directory_prefix = "/"
      }
    ]
  }

  assert {
    condition     = output.sftp_egress_server_id != null
    error_message = "Egress SFTP server should accept bare / home directory"
  }
}
