################################################################################
# S3 Bucket Security Configuration Tests
################################################################################

provider "aws" {
  region = "us-east-1"
}

variables {
  name_prefix = "test-s3sec"
  enable_sftp_ingress = false
}

################################################################################
# Test: All buckets have versioning enabled
################################################################################

run "ingress_bucket_versioning" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix              = "test-s3sec"
    kms_key_arn              = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    ingress_lifecycle_days   = 1
    egress_lifecycle_days     = 90
    quarantine_lifecycle_days = 365
  }

  assert {
    condition     = aws_s3_bucket_versioning.ingress.versioning_configuration[0].status == "Enabled"
    error_message = "Ingress bucket must have versioning enabled"
  }

  assert {
    condition     = aws_s3_bucket_versioning.egress.versioning_configuration[0].status == "Enabled"
    error_message = "Egress bucket must have versioning enabled"
  }

  assert {
    condition     = aws_s3_bucket_versioning.quarantine.versioning_configuration[0].status == "Enabled"
    error_message = "Quarantine bucket must have versioning enabled"
  }

  assert {
    condition     = aws_s3_bucket_versioning.logs.versioning_configuration[0].status == "Enabled"
    error_message = "Logs bucket must have versioning enabled"
  }
}

################################################################################
# Test: All buckets have KMS encryption
################################################################################

run "bucket_encryption" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix              = "test-s3sec"
    kms_key_arn              = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    ingress_lifecycle_days   = 1
    egress_lifecycle_days     = 90
    quarantine_lifecycle_days = 365
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.ingress.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Ingress bucket must use KMS encryption"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.egress.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Egress bucket must use KMS encryption"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.quarantine.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Quarantine bucket must use KMS encryption"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.logs.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Logs bucket must use KMS encryption"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.ingress.rule[0].bucket_key_enabled == true
    error_message = "Ingress bucket must have bucket key enabled"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.egress.rule[0].bucket_key_enabled == true
    error_message = "Egress bucket must have bucket key enabled"
  }

  assert {
    condition     = aws_s3_bucket_server_side_encryption_configuration.quarantine.rule[0].bucket_key_enabled == true
    error_message = "Quarantine bucket must have bucket key enabled"
  }
}

################################################################################
# Test: All buckets block public access
################################################################################

run "block_public_access" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix              = "test-s3sec"
    kms_key_arn              = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    ingress_lifecycle_days   = 1
    egress_lifecycle_days     = 90
    quarantine_lifecycle_days = 365
  }

  # Ingress bucket
  assert {
    condition     = aws_s3_bucket_public_access_block.ingress.block_public_acls == true
    error_message = "Ingress bucket must block public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.ingress.block_public_policy == true
    error_message = "Ingress bucket must block public policy"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.ingress.ignore_public_acls == true
    error_message = "Ingress bucket must ignore public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.ingress.restrict_public_buckets == true
    error_message = "Ingress bucket must restrict public buckets"
  }

  # Egress bucket
  assert {
    condition     = aws_s3_bucket_public_access_block.egress.block_public_acls == true
    error_message = "Egress bucket must block public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.egress.block_public_policy == true
    error_message = "Egress bucket must block public policy"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.egress.ignore_public_acls == true
    error_message = "Egress bucket must ignore public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.egress.restrict_public_buckets == true
    error_message = "Egress bucket must restrict public buckets"
  }

  # Quarantine bucket
  assert {
    condition     = aws_s3_bucket_public_access_block.quarantine.block_public_acls == true
    error_message = "Quarantine bucket must block public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.quarantine.block_public_policy == true
    error_message = "Quarantine bucket must block public policy"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.quarantine.ignore_public_acls == true
    error_message = "Quarantine bucket must ignore public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.quarantine.restrict_public_buckets == true
    error_message = "Quarantine bucket must restrict public buckets"
  }

  # Logs bucket
  assert {
    condition     = aws_s3_bucket_public_access_block.logs.block_public_acls == true
    error_message = "Logs bucket must block public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.block_public_policy == true
    error_message = "Logs bucket must block public policy"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.ignore_public_acls == true
    error_message = "Logs bucket must ignore public ACLs"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.restrict_public_buckets == true
    error_message = "Logs bucket must restrict public buckets"
  }
}

################################################################################
# Test: Bucket ownership controls enforce BucketOwnerEnforced
################################################################################

run "bucket_ownership" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix              = "test-s3sec"
    kms_key_arn              = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    ingress_lifecycle_days   = 1
    egress_lifecycle_days     = 90
    quarantine_lifecycle_days = 365
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.ingress.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "Ingress bucket must enforce BucketOwnerEnforced"
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.egress.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "Egress bucket must enforce BucketOwnerEnforced"
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.quarantine.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "Quarantine bucket must enforce BucketOwnerEnforced"
  }

  assert {
    condition     = aws_s3_bucket_ownership_controls.logs.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "Logs bucket must enforce BucketOwnerEnforced"
  }
}

################################################################################
# Test: Bucket logging targets the logs bucket
################################################################################

run "bucket_logging" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix              = "test-s3sec"
    kms_key_arn              = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    ingress_lifecycle_days   = 1
    egress_lifecycle_days     = 90
    quarantine_lifecycle_days = 365
  }

  assert {
    condition     = aws_s3_bucket_logging.ingress.target_prefix == "ingress/"
    error_message = "Ingress bucket logging should use 'ingress/' prefix"
  }

  assert {
    condition     = aws_s3_bucket_logging.egress.target_prefix == "egress/"
    error_message = "Egress bucket logging should use 'egress/' prefix"
  }

  assert {
    condition     = aws_s3_bucket_logging.quarantine.target_prefix == "quarantine/"
    error_message = "Quarantine bucket logging should use 'quarantine/' prefix"
  }
}

################################################################################
# Test: Lifecycle rules configured correctly
################################################################################

run "lifecycle_rules" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix              = "test-s3sec"
    kms_key_arn              = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
    ingress_lifecycle_days   = 3
    egress_lifecycle_days     = 60
    quarantine_lifecycle_days = 180
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.ingress.rule[0].expiration[0].days == 3
    error_message = "Ingress lifecycle should expire after 3 days"
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.egress.rule[0].transition[0].days == 60
    error_message = "Egress lifecycle should transition after 60 days"
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.egress.rule[0].transition[0].storage_class == "STANDARD_IA"
    error_message = "Egress lifecycle should transition to STANDARD_IA"
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.quarantine.rule[0].expiration[0].days == 180
    error_message = "Quarantine lifecycle should expire after 180 days"
  }
}
