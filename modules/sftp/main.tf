locals {
  users = { for user in var.sftp_users : user.username => user }
  home_prefix = {
    for username, user in local.users : username => trimsuffix(trimprefix(user.home_directory_prefix, "/"), "/")
  }
  route53_hosted_zone_id = var.route53_hosted_zone_id == null ? null : trimprefix(var.route53_hosted_zone_id, "/hostedzone/")
  route53_tag_value      = var.route53_hosted_zone_id == null ? null : "/hostedzone/${local.route53_hosted_zone_id}"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_vpc_endpoint" "transfer" {
  count = var.route53_hosted_zone_id == null ? 0 : 1
  id    = aws_transfer_server.this.endpoint_details[0].vpc_endpoint_id

  depends_on = [aws_transfer_server.this]
}

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
      values   = ["arn:aws:transfer:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:server/*"]
    }
  }
}

resource "aws_iam_role" "transfer_logging" {
  name               = "${var.name_prefix}-sftp-logging"
  assume_role_policy = data.aws_iam_policy_document.transfer_logging_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "transfer_logging" {
  name = "${var.name_prefix}-sftp-logging"
  role = aws_iam_role.transfer_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/transfer/*"
    }]
  })
}

resource "aws_security_group" "sftp" {
  name        = "${var.name_prefix}-sftp"
  description = "Allow approved client networks to reach Transfer Family SFTP"
  vpc_id      = var.vpc_id

  ingress {
    description = "SFTP from approved client networks"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    description = "Transfer Family service egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_transfer_server" "this" {
  protocols              = ["SFTP"]
  identity_provider_type = "SERVICE_MANAGED"
  domain                 = "S3"
  endpoint_type          = "VPC"
  security_policy_name   = "TransferSecurityPolicy-2024-01"
  logging_role           = aws_iam_role.transfer_logging.arn

  endpoint_details {
    address_allocation_ids = var.address_allocation_ids
    security_group_ids     = [aws_security_group.sftp.id]
    subnet_ids             = var.subnet_ids
    vpc_id                 = var.vpc_id
  }

  s3_storage_options {
    directory_listing_optimization = "ENABLED"
  }

  lifecycle {
    precondition {
      condition     = var.route53_hosted_zone_id == null || var.custom_hostname != null
      error_message = "route53_hosted_zone_id requires custom_hostname."
    }
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-sftp" })
}

resource "aws_transfer_tag" "custom_hostname" {
  count = var.custom_hostname == null ? 0 : 1

  resource_arn = aws_transfer_server.this.arn
  key          = "transfer:customHostname"
  value        = var.custom_hostname
}

resource "aws_transfer_tag" "route53_hosted_zone" {
  count = var.route53_hosted_zone_id == null ? 0 : 1

  resource_arn = aws_transfer_server.this.arn
  key          = "transfer:route53HostedZoneId"
  value        = local.route53_tag_value
}

resource "aws_route53_record" "custom_hostname" {
  count = var.route53_hosted_zone_id == null ? 0 : 1

  zone_id = local.route53_hosted_zone_id
  name    = var.custom_hostname
  type    = "CNAME"
  ttl     = 300
  records = [data.aws_vpc_endpoint.transfer[0].dns_entry[0].dns_name]
}

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
      values   = ["arn:aws:transfer:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:user/${aws_transfer_server.this.id}/*"]
    }
  }
}

resource "aws_iam_role" "sftp_user" {
  for_each = local.users

  name               = "${var.name_prefix}-sftp-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.sftp_user_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "sftp_user" {
  for_each = local.users

  statement {
    sid       = "ListLogicalHome"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [var.bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        local.home_prefix[each.key],
        "${local.home_prefix[each.key]}/*",
      ]
    }
  }

  statement {
    sid    = "AccessLogicalHomeObjects"
    effect = "Allow"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:GetObjectVersion",
      "s3:GetObjectVersionTagging",
      "s3:PutObject",
    ]
    resources = ["${var.bucket_arn}/${local.home_prefix[each.key]}/*"]
  }

  statement {
    sid       = "DescribeS3KmsKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }

  statement {
    sid    = "UseS3KmsKeyForLogicalHome"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [var.kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${var.bucket_arn}/${local.home_prefix[each.key]}/*"]
    }
  }
}

resource "aws_iam_role_policy" "sftp_user" {
  for_each = local.users

  name   = "${var.name_prefix}-sftp-${each.key}"
  role   = aws_iam_role.sftp_user[each.key].id
  policy = data.aws_iam_policy_document.sftp_user[each.key].json
}

resource "aws_transfer_user" "this" {
  for_each = local.users

  server_id           = aws_transfer_server.this.id
  user_name           = each.key
  role                = aws_iam_role.sftp_user[each.key].arn
  home_directory_type = "LOGICAL"
  home_directory      = "/"

  home_directory_mappings {
    entry  = "/"
    target = "/${var.bucket_name}/${local.home_prefix[each.key]}"
  }

  tags = var.tags
}

resource "aws_transfer_ssh_key" "this" {
  for_each = local.users

  server_id = aws_transfer_server.this.id
  user_name = aws_transfer_user.this[each.key].user_name
  body      = each.value.ssh_public_key
}
