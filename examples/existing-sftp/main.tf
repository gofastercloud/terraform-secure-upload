provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix = var.name_prefix

  # Attach to an existing Transfer Family server
  enable_sftp_ingress        = true
  create_sftp_ingress_server = false
  sftp_ingress_server_id     = var.sftp_ingress_server_id

  sftp_ingress_users = var.sftp_ingress_users

  tags = {
    Environment = "staging"
    Example     = "existing-sftp"
  }
}
