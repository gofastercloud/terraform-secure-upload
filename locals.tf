data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Resolve the KMS key — prefer the caller-supplied ARN, fall back to the one we create.
  kms_key_arn = coalesce(var.kms_key_arn, try(aws_kms_key.this[0].arn, null))

  # Standard tags merged onto every resource.
  default_tags = merge(var.tags, {
    Module    = "terraform-secure-upload"
    ManagedBy = "terraform"
  })
}
