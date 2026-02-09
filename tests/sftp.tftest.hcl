################################################################################
# SFTP Server Tests
################################################################################

provider "aws" {
  region = "us-east-1"
}

################################################################################
# Test: SFTP enabled with new server creation
################################################################################

run "sftp_new_server" {
  command = plan

  variables {
    name_prefix        = "test-sftp"
    enable_sftp        = true
    create_sftp_server = true
    sftp_endpoint_type = "PUBLIC"
    sftp_users = [
      {
        username       = "testuser"
        ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example testuser@example.com"
      }
    ]
  }

  assert {
    condition     = output.sftp_server_id != null
    error_message = "SFTP server ID should be populated when enabled"
  }

  assert {
    condition     = output.sftp_server_endpoint != null
    error_message = "SFTP server endpoint should be populated when creating a new server"
  }
}

################################################################################
# Test: SFTP enabled with existing server
################################################################################

run "sftp_existing_server" {
  command = plan

  variables {
    name_prefix        = "test-sftp-existing"
    enable_sftp        = true
    create_sftp_server = false
    sftp_server_id     = "s-1234567890abcdef0"
    sftp_users = [
      {
        username       = "testuser"
        ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example testuser@example.com"
      }
    ]
  }

  assert {
    condition     = output.sftp_server_id != null
    error_message = "SFTP server ID should be populated when using existing server"
  }

  assert {
    condition     = output.sftp_server_endpoint == null
    error_message = "SFTP server endpoint should be null when using existing server"
  }
}

################################################################################
# Test: SFTP disabled produces no server resources
################################################################################

run "sftp_disabled" {
  command = plan

  variables {
    name_prefix = "test-sftp-off"
    enable_sftp = false
  }

  assert {
    condition     = output.sftp_server_id == null
    error_message = "SFTP server ID should be null when SFTP is disabled"
  }

  assert {
    condition     = output.sftp_server_endpoint == null
    error_message = "SFTP server endpoint should be null when SFTP is disabled"
  }
}

################################################################################
# Test: Multiple SFTP users
################################################################################

run "sftp_multiple_users" {
  command = plan

  variables {
    name_prefix        = "test-sftp-multi"
    enable_sftp        = true
    create_sftp_server = true
    sftp_users = [
      {
        username              = "user-a"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7exampleA user-a@example.com"
        home_directory_prefix = "/uploads/user-a/"
      },
      {
        username              = "user-b"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7exampleB user-b@example.com"
        home_directory_prefix = "/uploads/user-b/"
      },
    ]
  }

  assert {
    condition     = output.sftp_server_id != null
    error_message = "SFTP server ID should be populated with multiple users"
  }
}
