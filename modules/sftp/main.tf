################################################################################
# Locals
################################################################################

locals {
  server_id  = var.create_sftp_server ? aws_transfer_server.this[0].id : var.existing_server_id
  server_arn = var.create_sftp_server ? aws_transfer_server.this[0].arn : "arn:aws:transfer:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:server/${var.existing_server_id}"
  sftp_users = { for user in var.sftp_users : user.username => user }

  # Normalize home directory prefix for IAM policy patterns.
  # Ensures a trailing / so "uploads/a" doesn't match "uploads/abc".
  # A bare "/" becomes "" so the pattern is just "*" (full bucket — egress only).
  home_prefix = { for k, v in local.sftp_users : k =>
    v.home_directory_prefix == "/" ? "" : "${trimsuffix(trimprefix(v.home_directory_prefix, "/"), "/")}/"
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Transfer Family Server (conditional)
################################################################################

resource "aws_transfer_server" "this" {
  count = var.create_sftp_server ? 1 : 0

  protocols              = ["SFTP"]
  identity_provider_type = "SERVICE_MANAGED"
  endpoint_type          = var.endpoint_type
  security_policy_name   = var.security_policy_name

  dynamic "endpoint_details" {
    for_each = var.endpoint_type == "VPC" ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      vpc_id             = var.vpc_id
      security_group_ids = [aws_security_group.sftp[0].id]
    }
  }

  logging_role = aws_iam_role.transfer_logging.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-sftp-server"
  })
}

################################################################################
# Security Group (VPC endpoint only)
################################################################################

resource "aws_security_group" "sftp" {
  count = var.create_sftp_server && var.endpoint_type == "VPC" ? 1 : 0

  name_prefix = "${var.name_prefix}-sftp-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
    description = "SFTP access from allowed CIDRs"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.egress_cidrs
    description = "HTTPS to AWS APIs"
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Transfer Family Logging Role
################################################################################

data "aws_iam_policy_document" "transfer_logging_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["transfer.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      # Use a wildcard pattern to avoid a dependency cycle: the server
      # references this role, so the assume policy cannot reference the
      # server ARN back. The account/region condition still limits scope.
      values = ["arn:aws:transfer:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:server/*"]
    }
  }
}

resource "aws_iam_role" "transfer_logging" {
  name_prefix        = "${var.name_prefix}-sftp-log-"
  assume_role_policy = data.aws_iam_policy_document.transfer_logging_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "transfer_logging" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/transfer/*",
    ]
  }
}

resource "aws_iam_role_policy" "transfer_logging" {
  name_prefix = "transfer-logging-"
  role        = aws_iam_role.transfer_logging.id
  policy      = data.aws_iam_policy_document.transfer_logging.json
}

################################################################################
# SFTP User IAM Roles
################################################################################

data "aws_iam_policy_document" "sftp_user_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["transfer.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.server_arn]
    }
  }
}

resource "aws_iam_role" "sftp_user" {
  for_each = local.sftp_users

  name_prefix        = "${var.name_prefix}-sftp-${each.key}-"
  assume_role_policy = data.aws_iam_policy_document.sftp_user_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "sftp_user" {
  for_each = local.sftp_users

  statement {
    sid    = "AllowListBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
    ]
    resources = [var.bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        "${local.home_prefix[each.key]}*",
      ]
    }
  }

  statement {
    sid    = "AllowObjectOperations"
    effect = "Allow"
    actions = var.read_only ? [
      "s3:GetObject",
      "s3:GetObjectVersion",
      ] : [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = [
      "${var.bucket_arn}/${local.home_prefix[each.key]}*",
    ]
  }

  statement {
    sid    = "AllowKMSAccess"
    effect = "Allow"
    actions = var.read_only ? [
      "kms:Decrypt",
      ] : [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "sftp_user" {
  for_each = local.sftp_users

  name_prefix = "sftp-s3-access-"
  role        = aws_iam_role.sftp_user[each.key].id
  policy      = data.aws_iam_policy_document.sftp_user[each.key].json
}

################################################################################
# Transfer Users
################################################################################

resource "aws_transfer_user" "this" {
  for_each = local.sftp_users

  server_id = local.server_id
  user_name = each.key
  role      = aws_iam_role.sftp_user[each.key].arn

  home_directory_type = "LOGICAL"

  home_directory_mappings {
    entry  = "/"
    target = "/${var.bucket_name}${each.value.home_directory_prefix}"
  }

  tags = var.tags
}

resource "aws_transfer_ssh_key" "this" {
  for_each = local.sftp_users

  server_id = local.server_id
  user_name = aws_transfer_user.this[each.key].user_name
  body      = each.value.ssh_public_key
}
