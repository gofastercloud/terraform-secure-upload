locals {
  account_hash = substr(sha256(data.aws_caller_identity.current.account_id), 0, 8)
  access_log_bucket_arns = {
    ingress    = aws_s3_bucket.ingress.arn
    egress     = aws_s3_bucket.egress.arn
    quarantine = aws_s3_bucket.quarantine.arn
  }
}

resource "aws_cloudwatch_log_group" "s3_access" {
  name              = "/aws/s3/${var.name_prefix}-access"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

################################################################################
# Ingress Bucket
################################################################################

resource "aws_s3_bucket" "ingress" {
  bucket = "${var.name_prefix}-${local.account_hash}-ingress"
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  rule {
    id     = "expire-ingress-objects-and-versions"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = var.ingress_object_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.ingress_noncurrent_version_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    # Object-level S3 encryption context is required for per-user KMS path controls.
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_public_access_block" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "ssl_only_ingress" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.ingress.arn,
      "${aws_s3_bucket.ingress.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyNonKMSEncryption"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.ingress.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyWrongKMSKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.ingress.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "ingress" {
  bucket = aws_s3_bucket.ingress.id
  policy = data.aws_iam_policy_document.ssl_only_ingress.json
}

################################################################################
# S3 EventBridge Notifications (ingress bucket)
################################################################################

resource "aws_s3_bucket_notification" "ingress_eventbridge" {
  bucket      = aws_s3_bucket.ingress.id
  eventbridge = true
}

################################################################################
# Egress Bucket
################################################################################

resource "aws_s3_bucket" "egress" {
  bucket = "${var.name_prefix}-${local.account_hash}-clean"
  tags   = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "egress" {
  bucket = aws_s3_bucket.egress.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "egress" {
  bucket = aws_s3_bucket.egress.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "egress" {
  bucket = aws_s3_bucket.egress.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "ssl_only_egress" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.egress.arn,
      "${aws_s3_bucket.egress.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyNonKMSEncryption"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.egress.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyWrongKMSKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.egress.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "egress" {
  bucket = aws_s3_bucket.egress.id
  policy = data.aws_iam_policy_document.ssl_only_egress.json
}

################################################################################
# Quarantine Bucket
################################################################################

resource "aws_s3_bucket" "quarantine" {
  bucket = "${var.name_prefix}-${local.account_hash}-quarantine"
  tags   = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "ssl_only_quarantine" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.quarantine.arn,
      "${aws_s3_bucket.quarantine.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyNonKMSEncryption"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.quarantine.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyWrongKMSKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.quarantine.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  policy = data.aws_iam_policy_document.ssl_only_quarantine.json
}

################################################################################
# CloudWatch S3 access-log delivery
################################################################################

resource "aws_cloudwatch_log_delivery_source" "s3_access" {
  for_each = local.access_log_bucket_arns

  name         = "${var.name_prefix}-${each.key}-s3-access"
  log_type     = "S3_SERVER_ACCESS_LOGS"
  resource_arn = each.value
  tags         = var.tags
}

resource "aws_cloudwatch_log_delivery_destination" "s3_access" {
  name          = "${var.name_prefix}-s3-access"
  output_format = "json"

  delivery_destination_configuration {
    destination_resource_arn = aws_cloudwatch_log_group.s3_access.arn
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_delivery" "s3_access" {
  for_each = local.access_log_bucket_arns

  delivery_source_name     = aws_cloudwatch_log_delivery_source.s3_access[each.key].name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.s3_access.arn
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
