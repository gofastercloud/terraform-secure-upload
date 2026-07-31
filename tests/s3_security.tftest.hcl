mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:root"
      user_id    = "AKIAIOSFODNN7EXAMPLE"
    }
  }
}

run "bucket_security" {
  command = plan

  module {
    source = "./modules/s3-buckets"
  }

  variables {
    name_prefix = "test-s3sec"
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.ingress.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Ingress bucket must use KMS encryption"
  }

  assert {
    condition     = !one(aws_s3_bucket_server_side_encryption_configuration.ingress.rule).bucket_key_enabled
    error_message = "Ingress bucket keys must be disabled for object-level KMS encryption-context isolation"
  }

  assert {
    condition     = aws_s3_bucket_versioning.ingress.versioning_configuration[0].status == "Enabled"
    error_message = "Ingress bucket versioning must be enabled to bind scan results to exact object versions"
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.ingress.rule).expiration[0].days == 7 && one(aws_s3_bucket_lifecycle_configuration.ingress.rule).noncurrent_version_expiration[0].noncurrent_days == 7
    error_message = "Ingress current and noncurrent object versions must have bounded retention"
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.egress.rule).bucket_key_enabled
    error_message = "Clean bucket must have S3 Bucket Keys enabled"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.ingress.block_public_policy && aws_s3_bucket_public_access_block.egress.block_public_policy && aws_s3_bucket_public_access_block.quarantine.block_public_policy && aws_s3_bucket_public_access_block.logs.block_public_policy
    error_message = "All buckets must block public bucket policies"
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.ingress.rule).object_ownership == "BucketOwnerEnforced" && one(aws_s3_bucket_ownership_controls.egress.rule).object_ownership == "BucketOwnerEnforced" && one(aws_s3_bucket_ownership_controls.quarantine.rule).object_ownership == "BucketOwnerEnforced" && one(aws_s3_bucket_ownership_controls.logs.rule).object_ownership == "BucketOwnerEnforced"
    error_message = "All buckets must enforce bucket ownership"
  }

}
