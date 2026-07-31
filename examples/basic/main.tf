provider "aws" {
  region = var.region
}

module "secure_upload" {
  source = "../../"

  name_prefix = var.name_prefix

  tags = {
    Environment = "dev"
    Example     = "basic"
  }
}
