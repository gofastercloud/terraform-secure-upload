################################################################################
# Logs Bucket (created first - other buckets log to this one)
################################################################################

locals {
  account_hash  = substr(sha256(data.aws_caller_identity.current.account_id), 0, 8)
  log_bucket_id = var.create_log_bucket ? aws_s3_bucket.logs[0].id : var.external_log_bucket_id
}

resource "aws_s3_bucket" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = "${var.name_prefix}-${local.account_hash}-logs"
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "logs" {
  count = var.create_log_bucket ? 1 : 0

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.logs[0].arn,
      "${aws_s3_bucket.logs[0].arn}/*",
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
      "${aws_s3_bucket.logs[0].arn}/*",
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
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.logs[0].json
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.log_retention_days
    }
  }
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

resource "aws_s3_bucket_server_side_encryption_configuration" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
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

resource "aws_s3_bucket_lifecycle_configuration" "ingress" {
  bucket = aws_s3_bucket.ingress.id

  rule {
    id     = "expire-ingress"
    status = "Enabled"
    filter {}

    expiration {
      days = var.ingress_lifecycle_days
    }
  }
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
  bucket = "${var.name_prefix}-${local.account_hash}-egress"
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "egress" {
  bucket = aws_s3_bucket.egress.id

  versioning_configuration {
    status = "Enabled"
  }
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
  target_prefix = "egress/"
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

resource "aws_s3_bucket_lifecycle_configuration" "egress" {
  bucket = aws_s3_bucket.egress.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"
    filter {}

    transition {
      days          = var.egress_lifecycle_days
      storage_class = "STANDARD_IA"
    }
  }
}

################################################################################
# Quarantine Bucket
################################################################################

resource "aws_s3_bucket" "quarantine" {
  bucket              = "${var.name_prefix}-${local.account_hash}-quarantine"
  object_lock_enabled = var.enable_object_lock
  tags                = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  versioning_configuration {
    status = "Enabled"
  }
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

resource "aws_s3_bucket_object_lock_configuration" "quarantine" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.quarantine.id

  rule {
    default_retention {
      mode = var.object_lock_retention_mode
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.quarantine]
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

resource "aws_s3_bucket_lifecycle_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    id     = "expire-quarantine"
    status = "Enabled"
    filter {}

    expiration {
      days = var.quarantine_lifecycle_days
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
