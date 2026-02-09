provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix         = var.name_prefix
  enable_sftp_ingress = false

  tags = {
    Environment = "dev"
    Example     = "basic"
  }
}
