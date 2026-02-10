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
    name_prefix                = "test-sftp"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_endpoint_type = "PUBLIC"
    sftp_ingress_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example testuser@example.com"
        home_directory_prefix = "/uploads/testuser/"
      }
    ]
  }

  assert {
    condition     = output.sftp_ingress_server_id != null
    error_message = "SFTP server ID should be populated when enabled"
  }

  assert {
    condition     = output.sftp_ingress_server_endpoint != null
    error_message = "SFTP server endpoint should be populated when creating a new server"
  }
}

################################################################################
# Test: SFTP enabled with existing server
################################################################################

run "sftp_existing_server" {
  command = plan

  variables {
    name_prefix                = "test-sftp-existing"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = false
    sftp_ingress_server_id     = "s-1234567890abcdef0"
    sftp_ingress_users = [
      {
        username              = "testuser"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example testuser@example.com"
        home_directory_prefix = "/uploads/testuser/"
      }
    ]
  }

  assert {
    condition     = output.sftp_ingress_server_id != null
    error_message = "SFTP server ID should be populated when using existing server"
  }

  assert {
    condition     = output.sftp_ingress_server_endpoint == null
    error_message = "SFTP server endpoint should be null when using existing server"
  }
}

################################################################################
# Test: SFTP disabled produces no server resources
################################################################################

run "sftp_disabled" {
  command = plan

  variables {
    name_prefix         = "test-sftp-off"
    enable_sftp_ingress = false
  }

  assert {
    condition     = output.sftp_ingress_server_id == null
    error_message = "SFTP server ID should be null when SFTP is disabled"
  }

  assert {
    condition     = output.sftp_ingress_server_endpoint == null
    error_message = "SFTP server endpoint should be null when SFTP is disabled"
  }
}

################################################################################
# Test: Egress SFTP enabled
################################################################################

run "sftp_egress_enabled" {
  command = plan

  variables {
    name_prefix         = "test-sftp-egress"
    enable_sftp_ingress = false
    enable_sftp_egress  = true
    sftp_egress_users = [
      {
        username              = "receiver"
        ssh_public_key        = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7egress receiver@example.com"
        home_directory_prefix = "/"
      }
    ]
  }

  assert {
    condition     = output.sftp_egress_server_id != null
    error_message = "Egress SFTP server ID should be populated when enabled"
  }

  assert {
    condition     = output.sftp_egress_server_endpoint != null
    error_message = "Egress SFTP server endpoint should be populated when creating a new server"
  }
}

################################################################################
# Test: Egress SFTP disabled produces no server resources
################################################################################

run "sftp_egress_disabled" {
  command = plan

  variables {
    name_prefix         = "test-sftp-egress-off"
    enable_sftp_ingress = false
    enable_sftp_egress  = false
  }

  assert {
    condition     = output.sftp_egress_server_id == null
    error_message = "Egress SFTP server ID should be null when egress is disabled"
  }

  assert {
    condition     = output.sftp_egress_server_endpoint == null
    error_message = "Egress SFTP server endpoint should be null when egress is disabled"
  }
}

################################################################################
# Test: Multiple SFTP users
################################################################################

run "sftp_multiple_users" {
  command = plan

  variables {
    name_prefix                = "test-sftp-multi"
    enable_sftp_ingress        = true
    create_sftp_ingress_server = true
    sftp_ingress_users = [
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
    condition     = output.sftp_ingress_server_id != null
    error_message = "SFTP server ID should be populated with multiple users"
  }
}
