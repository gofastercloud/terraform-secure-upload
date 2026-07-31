################################################################################
# Logs Bucket (created first - other buckets log to this one)
################################################################################

locals {
  account_hash  = substr(sha256(data.aws_caller_identity.current.account_id), 0, 8)
  log_bucket_id = aws_s3_bucket.logs.id
}

resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-${local.account_hash}-logs"
  tags   = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
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
    sid     = "AllowS3LogDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.logs.arn}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json
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

resource "aws_s3_bucket_logging" "ingress" {
  bucket        = aws_s3_bucket.ingress.id
  target_bucket = local.log_bucket_id
  target_prefix = "ingress/"
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

resource "aws_s3_bucket_logging" "egress" {
  bucket        = aws_s3_bucket.egress.id
  target_bucket = local.log_bucket_id
  target_prefix = "clean/"
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

resource "aws_s3_bucket_logging" "quarantine" {
  bucket        = aws_s3_bucket.quarantine.id
  target_bucket = local.log_bucket_id
  target_prefix = "quarantine/"
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
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
