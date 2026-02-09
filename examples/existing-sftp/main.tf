provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix = var.name_prefix

  # Attach to an existing Transfer Family server
  enable_sftp_ingress = true
  create_sftp_server  = false
  sftp_server_id      = var.sftp_server_id

  sftp_users = var.sftp_users

  tags = {
    Environment = "staging"
    Example     = "existing-sftp"
  }
}
