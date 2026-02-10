################################################################################
# Prompt Injection Scanner — Container Image Lambda
#
# All resources gated on var.enable_prompt_injection_scanning.
# The scanner downloads files from ingress, extracts text, and runs an ONNX
# model to detect prompt injection attacks. It returns a score; the file
# router handles all routing decisions.
################################################################################

locals {
  build_scanner_image = var.enable_prompt_injection_scanning && var.prompt_injection_image_uri == null
  scanner_image_uri = var.enable_prompt_injection_scanning ? coalesce(
    var.prompt_injection_image_uri,
    "${aws_ecr_repository.prompt_injection_scanner[0].repository_url}:latest",
  ) : null

  scanner_source_hash = var.enable_prompt_injection_scanning ? sha256(join("", [
    filesha256("${path.module}/functions/prompt_injection_scanner/Dockerfile"),
    filesha256("${path.module}/functions/prompt_injection_scanner/handler.py"),
    filesha256("${path.module}/functions/prompt_injection_scanner/requirements.txt"),
  ])) : null
}

################################################################################
# ECR Repository
################################################################################

resource "aws_ecr_repository" "prompt_injection_scanner" {
  count = var.enable_prompt_injection_scanning ? 1 : 0

  name                 = "${var.name_prefix}-prompt-injection-scanner"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  # Uses the same KMS key as S3 buckets, Lambda, and CloudWatch Logs.
  # For external KMS keys, the Terraform caller needs kms:CreateGrant
  # on the key (ECR creates grants for image-layer encryption).
  # See README.md "External KMS Key" for the required key policy statement.
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = local.kms_key_arn
  }

  tags = local.default_tags
}

resource "aws_ecr_lifecycle_policy" "prompt_injection_scanner" {
  count = var.enable_prompt_injection_scanning ? 1 : 0

  repository = aws_ecr_repository.prompt_injection_scanner[0].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep only the last 3 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 3
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

################################################################################
# Docker Image Build & Push (null_resource)
################################################################################

resource "null_resource" "build_scanner_image" {
  count = local.build_scanner_image ? 1 : 0

  triggers = {
    source_hash    = local.scanner_source_hash
    repository_url = aws_ecr_repository.prompt_injection_scanner[0].repository_url
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/functions/prompt_injection_scanner"
    command     = <<-EOT
      set -e
      aws ecr get-login-password --region ${local.region} | \
        docker login --username AWS --password-stdin ${aws_ecr_repository.prompt_injection_scanner[0].repository_url}
      docker build --platform linux/amd64 -t ${aws_ecr_repository.prompt_injection_scanner[0].repository_url}:latest .
      docker push ${aws_ecr_repository.prompt_injection_scanner[0].repository_url}:latest
    EOT
  }

  depends_on = [aws_ecr_repository.prompt_injection_scanner]
}

################################################################################
# CloudWatch Log Group
################################################################################

resource "aws_cloudwatch_log_group" "prompt_injection_scanner" {
  count = var.enable_prompt_injection_scanning ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-prompt-injection-scanner"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn
  tags              = local.default_tags
}

################################################################################
# IAM Role
################################################################################

resource "aws_iam_role" "prompt_injection_scanner" {
  count = var.enable_prompt_injection_scanning ? 1 : 0

  name = "${var.name_prefix}-prompt-injection-scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = local.default_tags
}

resource "aws_iam_role_policy" "prompt_injection_scanner" {
  count = var.enable_prompt_injection_scanning ? 1 : 0

  name = "${var.name_prefix}-prompt-injection-scanner"
  role = aws_iam_role.prompt_injection_scanner[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IngressBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
        ]
        Resource = "${module.s3_buckets.ingress_bucket_arn}/*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
        ]
        Resource = local.kms_key_arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.prompt_injection_scanner[0].arn}:*"
      },
    ]
  })
}

################################################################################
# Lambda Function
################################################################################

resource "aws_lambda_function" "prompt_injection_scanner" {
  count = var.enable_prompt_injection_scanning ? 1 : 0

  function_name = "${var.name_prefix}-prompt-injection-scanner"
  description   = "Scans uploaded documents for prompt injection attacks using an ONNX model"
  role          = aws_iam_role.prompt_injection_scanner[0].arn
  package_type  = "Image"
  image_uri     = local.scanner_image_uri
  memory_size   = var.prompt_injection_memory_size
  timeout       = var.prompt_injection_timeout

  reserved_concurrent_executions = var.prompt_injection_reserved_concurrency

  kms_key_arn = local.kms_key_arn

  depends_on = [
    aws_iam_role_policy.prompt_injection_scanner,
    aws_cloudwatch_log_group.prompt_injection_scanner,
    null_resource.build_scanner_image,
  ]

  tags = local.default_tags
}
