# Changelog

All notable changes to this project will be documented in this file.

## [0.2.2] - 2025-02-10

### Fixed

- **KMS key policy missing CloudWatch Logs service principal** — CloudWatch Logs uses a regional service principal (`logs.<region>.amazonaws.com`) with a `kms:EncryptionContext` condition, which differs from other AWS services. The Lambda log group failed to create with `AccessDeniedException` when KMS encryption was enabled. Added a dedicated `AllowCloudWatchLogs` statement to the KMS key policy.

- **GuardDuty Malware Protection Plan creation failed** — The GuardDuty IAM role was missing `s3:GetBucketNotification`, `s3:PutBucketNotification` (for S3 EventBridge delivery), and `events:PutRule`, `events:PutTargets`, `events:DeleteRule`, `events:RemoveTargets`, `events:DescribeRule` (for EventBridge managed rules). Added both sets of permissions.

- **Transfer Family user creation failed with trailing slash** — Home directory mapping targets included a trailing `/` (e.g. `/bucket/uploads/dave/`), which Transfer Family rejects. Fixed with `trimsuffix()`.

### Changed

- **`lambda_reserved_concurrency` now accepts `-1`** — Setting `-1` uses unreserved account concurrency, which is necessary for accounts with low concurrency limits where reserving even 10 would drop below the 50-unreserved minimum.

## [0.2.1] - 2025-02-10

### Fixed

- **S3 bucket policy blocks AWS service uploads** — Changed `StringNotEquals` to `StringNotEqualsIfExists` in `DenyNonKMSEncryption` and `DenyWrongKMSKey` policy statements across all three buckets (ingress, egress, quarantine). Services that rely on bucket default encryption and omit `x-amz-server-side-encryption` headers (e.g. AWS Transfer Family, GuardDuty, Lambda) were getting `AccessDenied`. The `IfExists` variant only evaluates the condition when the header is present, allowing headless uploads to fall through to bucket default SSE-KMS.

### Changed

- **Bucket names include hashed account ID for global uniqueness** — S3 bucket names changed from `<prefix>-<type>` to `<prefix>-<hash>-<type>` where `<hash>` is the first 8 characters of `sha256(account_id)`. This prevents name collisions across AWS accounts without exposing the raw account ID. **Breaking change**: existing buckets will be recreated.

## [0.2.0] - 2025-02-08

### Added

- SFTP egress endpoint — optional read-only Transfer Family server for pulling verified files from the egress bucket
- CloudWatch dashboard — optional pipeline observability with metric filters for file routing outcomes, Lambda health, DLQ depth, and S3 bucket metrics
- Lambda error alarm — CloudWatch alarm on Lambda invocation errors, firing to the SNS alert topic
- Dead letter queue — SQS DLQ for Lambda invocation failures
- S3 Object Lock — optional tamper-proof retention on the quarantine bucket
- Cross-account log shipping support

## [0.1.0] - 2025-01-15

### Added

- Initial release
- S3 pipeline: ingress, egress, quarantine buckets with KMS encryption
- GuardDuty Malware Protection for S3 scanning
- Lambda file router with EventBridge integration
- SNS alerting for malware detections
- SFTP ingress via AWS Transfer Family
- TLS enforcement and KMS enforcement bucket policies
- Access logging with dedicated log bucket
- Configurable lifecycle rules per bucket
