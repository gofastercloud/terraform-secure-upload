# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-02-10

### Added

- **Prompt injection scanning** — optional second scanning step that runs an ONNX-based prompt injection detection model ([protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)) on uploaded documents before they reach the egress bucket. Files that pass GuardDuty malware scanning are additionally checked for prompt injection attacks when `enable_prompt_injection_scanning = true`.
- **Supported document formats** — scanner extracts text from `.txt`, `.csv`, `.md`, `.json`, `.xml`, `.html`, `.yaml`, `.yml`, `.log`, `.pdf`, `.docx`, and `.pptx` files. Unsupported formats (images, binaries, etc.) pass through with score 0.
- **Configurable threshold** — `prompt_injection_threshold` (default: 80) sets the score above which files are quarantined. Model outputs a 0–100 score based on the maximum injection probability across overlapping 512-token chunks.
- **Container image Lambda** — scanner runs as a Docker-based Lambda with ECR repository, automatic image build via `null_resource`, and BYO image support via `prompt_injection_image_uri`.
- **New variables** — `enable_prompt_injection_scanning`, `prompt_injection_threshold`, `prompt_injection_memory_size`, `prompt_injection_timeout`, `prompt_injection_reserved_concurrency`, `prompt_injection_image_uri`.
- **New outputs** — `prompt_injection_scanner_function_arn`, `prompt_injection_scanner_ecr_repository_url`.
- **Makefile targets** — `make build-scanner` and `make push-scanner` for local Docker image management.
- **Validation tests** — 7 new tests for prompt injection variable validation rules.

## [0.4.0] - 2026-02-10

### Added

- **Slack integration** — optional AWS Chatbot configuration to deliver malware alerts to a Slack channel
- **Microsoft Teams integration** — optional AWS Chatbot configuration to deliver malware alerts to a Teams channel
- **PagerDuty integration** — optional SNS HTTPS subscription to forward alerts to PagerDuty Events API
- **VictorOps / Splunk On-Call integration** — optional SNS HTTPS subscription to forward alerts to VictorOps REST endpoint
- **Discord integration** — optional Lambda webhook forwarder that posts rich embeds to a Discord channel
- **ServiceNow integration** — optional Lambda webhook forwarder that creates incidents in ServiceNow via the REST API, with credentials stored in Secrets Manager
- **Integration documentation** — new [integrations.md](integrations.md) with detailed setup instructions for all six integrations
- **Integration validation tests** — 11 new tests covering all integration variable validation rules (42 total)

## [0.3.0] - 2026-02-10

### Fixed

- **S3 bucket policy `StringNotEqualsIfExists` incorrect for Deny statements** — The v0.2.1 fix was wrong: `StringNotEqualsIfExists` on a Deny evaluates to `true` when the condition key is absent, which still blocks uploads without explicit encryption headers. Replaced with `StringNotEquals` + `Null` condition guard (`"Null": {"s3:x-amz-server-side-encryption": "false"}`) across all three buckets (6 statements). The Deny now only fires when the header is explicitly present with a non-KMS value; absent headers fall through to bucket default SSE-KMS.

- **SFTP user IAM trust policy `aws:SourceArn` used wrong ARN type** — Transfer Family passes a user ARN (`arn:aws:transfer:region:account:user/server-id/username`), not a server ARN, when assuming the data access role. Changed `aws:SourceArn` from `server/*` to `user/server-id/*` to match. The logging role (which correctly uses `server/*`) was unaffected.

- **SFTP `ListBucket` condition too restrictive for directory stat** — The `s3:prefix` condition only allowed `uploads/dave/*` but Transfer Family also needs to stat the home directory prefix itself (`uploads/dave` without trailing slash). Added the bare prefix as a second allowed value.

### Verified

- End-to-end smoke test completed: SFTP upload → GuardDuty scan → Lambda routing → egress/quarantine. Clean files route to egress, EICAR test file routes to quarantine with SNS malware alert email.

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
