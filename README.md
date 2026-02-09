# terraform-secure-upload

A Terraform module that creates a secure file upload pipeline on AWS with automatic malware scanning using Amazon GuardDuty Malware Protection for S3.

## Architecture

```
                          ┌─────────────┐
                          │  S3 Direct  │
                          │   Upload    │
                          └──────┬──────┘
                                 │
          ┌─────────────┐        │
          │    SFTP      │       │
          │ (Transfer    ├───────┤
          │  Family)     │       │
          └─────────────┘        │
                                 ▼
                      ┌─────────────────────┐
                      │   Staging Bucket     │
                      │  (KMS encrypted)     │
                      └──────────┬──────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │  GuardDuty Malware   │
                      │  Protection Scan     │
                      └──────────┬──────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │  EventBridge Rule    │
                      │  (scan result)       │
                      └──────────┬──────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │  Lambda File Router  │──────┐
                      └──────┬──────────────┘      │
                             │                      │
              ┌──────────────┴──────────┐           │
              ▼                         ▼           ▼
   ┌───────────────────┐   ┌───────────────────┐  ┌──────────┐
   │   Clean Bucket    │   │Quarantine Bucket   │  │   SNS    │
   │ (scan passed)     │   │(malware detected)  │  │  Alert   │
   └───────────────────┘   └───────────────────┘  └──────────┘
```

## Features

- **Automatic malware scanning** — GuardDuty Malware Protection scans every object uploaded to the staging bucket
- **Automated file routing** — Lambda moves clean files to the clean bucket and infected files to quarantine
- **SNS alerting** — email notifications when malware is detected
- **SFTP upload support** — optional AWS Transfer Family server with per-user home directories
- **KMS encryption** — all buckets encrypted with a shared KMS key (BYO or auto-created)
- **S3 Object Lock** — optional tamper-proof retention on the quarantine bucket
- **Least-privilege IAM** — scoped IAM roles for GuardDuty, Lambda, Transfer Family, and SFTP users
- **TLS enforcement** — bucket policies deny non-HTTPS requests on all buckets
- **Access logging** — dedicated log bucket for S3 server access logs
- **Lifecycle management** — configurable expiration/transition rules per bucket
- **Dead letter queue** — SQS DLQ for Lambda invocation failures

## Prerequisites

| Requirement | Version |
|---|---|
| Terraform / OpenTofu | `>= 1.5` |
| AWS Provider | `~> 5.0` |
| Archive Provider | `~> 2.0` |
| AWS Account | GuardDuty Malware Protection for S3 must be available in your region |

## Quick Start

```hcl
module "secure_upload" {
  source = "path/to/terraform-secure-upload"

  name_prefix = "myapp"
  enable_sftp = false
}
```

## Full Usage

```hcl
module "secure_upload" {
  source = "path/to/terraform-secure-upload"

  name_prefix = "myapp"

  # KMS — bring your own key or let the module create one
  kms_key_arn = aws_kms_key.custom.arn

  # S3 lifecycle
  staging_lifecycle_days    = 1
  clean_lifecycle_days      = 90
  quarantine_lifecycle_days = 365
  enable_object_lock        = true

  # Lambda tuning
  lambda_memory_size          = 512
  lambda_timeout              = 120
  lambda_reserved_concurrency = 20

  # Notifications
  sns_subscription_emails = ["security@example.com"]

  # Logging
  log_retention_days = 180

  # SFTP
  enable_sftp        = true
  create_sftp_server = true
  sftp_endpoint_type = "VPC"
  sftp_vpc_id        = "vpc-0abc123"
  sftp_subnet_ids    = ["subnet-aaa", "subnet-bbb"]

  sftp_users = [
    {
      username              = "partner-a"
      ssh_public_key        = file("keys/partner-a.pub")
      home_directory_prefix = "/uploads/partner-a/"
    },
    {
      username              = "partner-b"
      ssh_public_key        = file("keys/partner-b.pub")
      home_directory_prefix = "/uploads/partner-b/"
    },
  ]

  tags = {
    Environment = "production"
    Team        = "security"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `name_prefix` | Prefix applied to all resource names for namespacing. Must be lowercase alphanumeric with hyphens. | `string` | — | yes |
| `tags` | Tags applied to every resource created by this module. | `map(string)` | `{}` | no |
| `kms_key_arn` | ARN of an existing KMS key. When `null` the module creates a new key. | `string` | `null` | no |
| `enable_sftp` | Whether to enable the SFTP upload path via AWS Transfer Family. | `bool` | `true` | no |
| `create_sftp_server` | Create a new Transfer Family server. Set `false` to attach to an existing server. | `bool` | `true` | no |
| `sftp_server_id` | Existing Transfer Family server ID. Required when `create_sftp_server` is `false`. | `string` | `null` | no |
| `sftp_endpoint_type` | Transfer Family endpoint type — `PUBLIC` or `VPC`. | `string` | `"PUBLIC"` | no |
| `sftp_vpc_id` | VPC ID for a VPC-type Transfer Family endpoint. | `string` | `null` | no |
| `sftp_subnet_ids` | Subnet IDs for a VPC-type Transfer Family endpoint. | `list(string)` | `[]` | no |
| `sftp_users` | SFTP users to provision. Each object has `username`, `ssh_public_key`, and optional `home_directory_prefix`. | `list(object)` | `[]` | no |
| `staging_lifecycle_days` | Days before objects in the staging bucket expire. | `number` | `1` | no |
| `clean_lifecycle_days` | Days before objects in the clean bucket transition to Infrequent Access. | `number` | `90` | no |
| `quarantine_lifecycle_days` | Days before objects in the quarantine bucket expire. | `number` | `365` | no |
| `lambda_memory_size` | Memory (MB) allocated to the file-router Lambda (128–10240). | `number` | `256` | no |
| `lambda_timeout` | Timeout (seconds) for the file-router Lambda (1–900). | `number` | `60` | no |
| `lambda_reserved_concurrency` | Reserved concurrent executions for the file-router Lambda. | `number` | `10` | no |
| `sns_subscription_emails` | Email addresses subscribed to the malware-alert SNS topic. | `list(string)` | `[]` | no |
| `enable_object_lock` | Enable S3 Object Lock on the quarantine bucket for tamper-proof retention. | `bool` | `false` | no |
| `log_retention_days` | CloudWatch Logs retention period in days. Must be a valid CloudWatch retention value. | `number` | `90` | no |

## Outputs

| Name | Description |
|---|---|
| `staging_bucket_id` | Name of the staging (upload) S3 bucket. |
| `staging_bucket_arn` | ARN of the staging (upload) S3 bucket. |
| `clean_bucket_id` | Name of the clean (scan-passed) S3 bucket. |
| `clean_bucket_arn` | ARN of the clean (scan-passed) S3 bucket. |
| `quarantine_bucket_id` | Name of the quarantine (malware-detected) S3 bucket. |
| `quarantine_bucket_arn` | ARN of the quarantine (malware-detected) S3 bucket. |
| `log_bucket_id` | Name of the S3 access-log bucket. |
| `kms_key_arn` | ARN of the KMS key used for encryption. |
| `sftp_server_id` | ID of the AWS Transfer Family SFTP server (null if SFTP disabled). |
| `sftp_server_endpoint` | Endpoint hostname of the SFTP server (null if SFTP disabled). |
| `sns_topic_arn` | ARN of the SNS topic for malware alert notifications. |
| `guardduty_protection_plan_arn` | ARN of the GuardDuty Malware Protection plan. |
| `lambda_function_arn` | ARN of the file-router Lambda function. |

## Submodules

| Module | Description |
|---|---|
| `modules/s3-buckets` | Creates the staging, clean, quarantine, and access-log S3 buckets with encryption, versioning, public access blocks, TLS-only policies, and lifecycle rules. |
| `modules/guardduty-protection` | Configures a GuardDuty Malware Protection plan on the staging bucket with an IAM role for scanning. |
| `modules/file-router` | Deploys the Lambda function, EventBridge rule, SNS topic, SQS DLQ, and IAM role that route files based on scan results. |
| `modules/sftp` | Optionally provisions an AWS Transfer Family SFTP server (or attaches to an existing one), creates SFTP users with scoped IAM roles and SSH key authentication. |

## How It Works

1. **Upload** — Files are uploaded to the staging bucket, either via direct S3 PutObject or through the optional SFTP endpoint (AWS Transfer Family).

2. **Scan** — GuardDuty Malware Protection for S3 automatically scans every new object in the staging bucket and tags it with the scan result.

3. **Event** — When the scan completes, GuardDuty emits a `GuardDuty Malware Protection Object Scan Result` event to EventBridge.

4. **Route** — An EventBridge rule invokes the file-router Lambda function with the scan result:
   - **NO_THREATS_FOUND** — the file is copied to the clean bucket and deleted from staging.
   - **THREATS_FOUND** — the file is copied to the quarantine bucket, deleted from staging, and an SNS notification is published with threat details.
   - **Other results** (e.g., `UNSUPPORTED`, `ACCESS_DENIED`) — the file is left in staging for manual review.

5. **Alert** — If threats are detected, subscribed email addresses receive a JSON-formatted alert with the file key, threat names, and timestamp.

## Known Limitations

- **GuardDuty region availability** — GuardDuty Malware Protection for S3 is not available in all AWS regions. Check [AWS regional availability](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_regions.html).
- **Scan latency** — GuardDuty scans are asynchronous. Files remain in the staging bucket until the scan completes (typically seconds to minutes).
- **File size limits** — GuardDuty Malware Protection supports objects up to 5 GB. Larger files are not scanned.
- **Object Lock requires bucket recreation** — Enabling `enable_object_lock` after the quarantine bucket already exists requires destroying and recreating the bucket (S3 limitation).
- **SNS email confirmation** — Email subscriptions require manual confirmation by each recipient before alerts are delivered.
- **SFTP users are service-managed** — This module uses Transfer Family's service-managed identity provider. Custom/external identity providers are not supported.
- **Single staging bucket** — All SFTP users share the same staging bucket, isolated by home directory prefix.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
