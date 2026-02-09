################################################################################
# IAM Role for GuardDuty Malware Protection
################################################################################

data "aws_iam_policy_document" "guardduty_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["malware-protection-plan.guardduty.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "guardduty_malware" {
  name               = "${var.name_prefix}-guardduty-malware"
  assume_role_policy = data.aws_iam_policy_document.guardduty_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "guardduty_malware" {
  statement {
    sid    = "AllowS3ObjectAccess"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:PutObjectTagging",
    ]

    resources = ["${var.staging_bucket_arn}/*"]
  }

  statement {
    sid    = "AllowS3BucketAccess"
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]

    resources = [var.staging_bucket_arn]
  }

  statement {
    sid    = "AllowKMSAccess"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "guardduty_malware" {
  name   = "${var.name_prefix}-guardduty-malware"
  role   = aws_iam_role.guardduty_malware.id
  policy = data.aws_iam_policy_document.guardduty_malware.json
}

################################################################################
# GuardDuty Malware Protection Plan
################################################################################

resource "aws_guardduty_malware_protection_plan" "this" {
  role = aws_iam_role.guardduty_malware.arn

  protected_resource {
    s3_bucket {
      bucket_name = var.staging_bucket_name
    }
  }

  actions {
    tagging {
      status = "ENABLED"
    }
  }

  tags = var.tags
}
