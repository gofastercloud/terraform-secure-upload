# terraform-secure-upload

[![CI](https://github.com/gofastercloud/terraform-secure-upload/actions/workflows/ci.yml/badge.svg)](https://github.com/gofastercloud/terraform-secure-upload/actions/workflows/ci.yml)
[![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.9-blue?logo=terraform)](https://www.terraform.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Terraform module that creates a secure file upload pipeline on AWS with automatic malware scanning using Amazon GuardDuty Malware Protection for S3.

## Architecture

```
                          ┌─────────────┐
                          │  S3 Direct  │
                          │   Upload    │
                          └──────┬──────┘
                                 │
          ┌─────────────┐        │
          │ SFTP Ingress │       │
          │ (Transfer    ├───────┤
          │  Family)     │       │
          └─────────────┘        │
                                 ▼
                      ┌─────────────────────┐
                      │   Ingress Bucket     │
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
                    (NO_THREATS_FOUND)               │
                             │                      │
                    [scanning enabled?]              │
                     │              │                │
                    YES             NO               │
                     │              │                │
              ┌──────┴──────┐       │               │
              │  Prompt     │       │               │
              │  Injection  │       │               │
              │  Scanner    │       │               │
              └──────┬──────┘       │               │
                     │              │               │
              [score > threshold?]  │               │
               │            │       │               │
              YES           NO      │               │
               │            │       │               │
               │     ┌──────┴───────┘               │
               │     │                              │
               ▼     ▼                              ▼
   ┌───────────────────┐   ┌───────────────────┐  ┌──────────┐
   │  Egress Bucket    │   │Quarantine Bucket   │  │   SNS    │
   │   (verified)      │   │(threats/injection) │  │  Alert   │
   └────────┬──────────┘   └───────────────────┘  └──────────┘
            │
            ▼ (optional)
   ┌─────────────────┐
   │  SFTP Egress    │
   │ (read-only,     │
   │  Transfer Family)│
   └─────────────────┘
```

## Features

- **Prompt injection scanning** — optional AI-powered scanning of uploaded documents for prompt injection attacks using an ONNX model, with configurable score threshold and support for PDF, DOCX, PPTX, and plain text formats
- **Automatic malware scanning** — GuardDuty Malware Protection scans every object uploaded to the ingress bucket
- **Automated file routing** — Lambda moves verified files to the egress bucket and infected files to quarantine
- **SNS alerting** — email notifications when malware is detected
- **SFTP upload support** — optional AWS Transfer Family server with per-user home directories
- **SFTP egress** — optional read-only SFTP endpoint for pulling verified files from the egress bucket
- **KMS encryption** — all buckets encrypted with a shared KMS key (BYO or auto-created)
- **S3 Object Lock** — optional tamper-proof retention on the quarantine bucket
- **Least-privilege IAM** — scoped IAM roles for GuardDuty, Lambda, Transfer Family, and SFTP users
- **TLS enforcement** — bucket policies deny non-HTTPS requests on all buckets
- **KMS enforcement** — bucket policies use `StringNotEquals` with a `Null` condition guard to deny uploads that explicitly specify wrong encryption, while allowing AWS services (e.g. Transfer Family) that rely on bucket default SSE-KMS without sending encryption headers
- **Access logging** — dedicated log bucket for S3 server access logs
- **Lifecycle management** — configurable expiration/transition rules per bucket
- **Dead letter queue** — SQS DLQ for Lambda invocation failures
- **Lambda error alarm** — CloudWatch alarm on Lambda invocation errors (separate from DLQ), firing to the SNS alert topic
- **CloudWatch dashboard** — optional pipeline dashboard with metric filters for file routing outcomes, Lambda health, DLQ depth, and S3 bucket metrics
- **Deletion protection** — `prevent_destroy` lifecycle on the KMS key and quarantine bucket to guard against accidental data loss
- **Chat & incident integrations** — optional integrations for Slack, Microsoft Teams, PagerDuty, VictorOps, Discord, and ServiceNow (see [integrations.md](integrations.md))

## Prerequisites

| Requirement | Version |
|---|---|
| Terraform / OpenTofu | `>= 1.9` |
| AWS Provider | `>= 5.60, < 6.0` |
| Archive Provider | `~> 2.0` |
| AWS Account | GuardDuty Malware Protection for S3 must be available in your region |

## Quick Start

```hcl
module "secure_upload" {
  source = "path/to/terraform-secure-upload"

  name_prefix = "myapp"
  # Creates buckets: myapp-<hash>-ingress, myapp-<hash>-egress, etc.
}
```

This creates the S3 pipeline (ingress, egress, quarantine, logs), GuardDuty scanning, Lambda router, and SNS alerting. Bucket names automatically include an 8-character hash of your AWS account ID for global uniqueness. No SFTP resources are created by default — enable them with `enable_sftp_ingress` or `enable_sftp_egress`.

## Full Usage

```hcl
module "secure_upload" {
  source = "path/to/terraform-secure-upload"

  name_prefix = "myapp"

  # KMS — bring your own key or let the module create one
  create_kms_key = false
  kms_key_arn    = aws_kms_key.custom.arn

  # S3 lifecycle
  ingress_lifecycle_days    = 1
  egress_lifecycle_days      = 90
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
  enable_sftp_ingress        = true
  create_sftp_ingress_server = true
  sftp_ingress_endpoint_type  = "VPC"
  sftp_ingress_vpc_id         = "vpc-0abc123"
  sftp_ingress_subnet_ids     = ["subnet-aaa", "subnet-bbb"]
  sftp_ingress_allowed_cidrs  = ["10.0.0.0/8"]

  sftp_ingress_users = [
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

  # SFTP Egress — read-only pull from egress bucket
  enable_sftp_egress = true
  sftp_egress_users = [
    {
      username              = "receiver-a"
      ssh_public_key        = file("keys/receiver-a.pub")
      home_directory_prefix = "/"
    },
  ]

  tags = {
    Environment = "production"
    Team        = "security"
  }
}
```

## Inputs

### General

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `name_prefix` | Prefix applied to all resource names. Must be lowercase alphanumeric with hyphens. | `string` | — | yes |
| `tags` | Tags applied to every resource created by this module. | `map(string)` | `{}` | no |

### KMS

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `create_kms_key` | Create a new KMS key. Set to `false` when providing your own via `kms_key_arn`. | `bool` | `true` | no |
| `kms_key_deletion_window_days` | Days before a KMS key is permanently deleted after scheduling deletion (7–30). | `number` | `30` | no |
| `kms_key_arn` | ARN of an existing KMS key. Required when `create_kms_key` is `false`. | `string` | `null` | no |

### SFTP Ingress

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `enable_sftp_ingress` | Enable the SFTP upload path via AWS Transfer Family. When `false` (default), no Transfer Family resources are created for ingress. | `bool` | `false` | no |
| `create_sftp_ingress_server` | Create a new Transfer Family server for ingress. Only takes effect when `enable_sftp_ingress` is `true`. Set `false` to attach users to an existing server via `sftp_ingress_server_id`. | `bool` | `true` | no |
| `sftp_ingress_server_id` | ID of an existing Transfer Family server. Only used when `enable_sftp_ingress` is `true` and `create_sftp_ingress_server` is `false`. | `string` | `null` | no |
| `sftp_ingress_endpoint_type` | Transfer Family endpoint type — `PUBLIC` or `VPC`. Only used when both `enable_sftp_ingress` and `create_sftp_ingress_server` are `true`. | `string` | `"PUBLIC"` | no |
| `sftp_ingress_vpc_id` | VPC ID for a VPC-type ingress endpoint. Required when `sftp_ingress_endpoint_type` is `VPC`. | `string` | `null` | no |
| `sftp_ingress_subnet_ids` | Subnet IDs for a VPC-type ingress endpoint. Required when `sftp_ingress_endpoint_type` is `VPC`. | `list(string)` | `[]` | no |
| `sftp_ingress_allowed_cidrs` | CIDR blocks allowed to access the ingress SFTP server security group. Required when `sftp_ingress_endpoint_type` is `VPC`. | `list(string)` | `[]` | no |
| `sftp_ingress_users` | Ingress SFTP users. Each must have `username`, `ssh_public_key`, and `home_directory_prefix` (must start/end with `/`, e.g. `/uploads/partner-a/`). Bare `/` is not allowed. | `list(object)` | `[]` | no |

### SFTP Egress

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `enable_sftp_egress` | Enable an egress SFTP endpoint for read-only access to the egress bucket. When `false` (default), no Transfer Family resources are created for egress. | `bool` | `false` | no |
| `create_sftp_egress_server` | Create a new Transfer Family server for egress. Only takes effect when `enable_sftp_egress` is `true`. Set `false` to attach users to an existing server via `sftp_egress_server_id`. | `bool` | `true` | no |
| `sftp_egress_server_id` | ID of an existing Transfer Family server for egress. Only used when `enable_sftp_egress` is `true` and `create_sftp_egress_server` is `false`. | `string` | `null` | no |
| `sftp_egress_endpoint_type` | Transfer Family endpoint type for egress — `PUBLIC` or `VPC`. Only used when both `enable_sftp_egress` and `create_sftp_egress_server` are `true`. | `string` | `"PUBLIC"` | no |
| `sftp_egress_vpc_id` | VPC ID for a VPC-type egress endpoint. Required when `sftp_egress_endpoint_type` is `VPC`. | `string` | `null` | no |
| `sftp_egress_subnet_ids` | Subnet IDs for a VPC-type egress endpoint. Required when `sftp_egress_endpoint_type` is `VPC`. | `list(string)` | `[]` | no |
| `sftp_egress_allowed_cidrs` | CIDR blocks allowed to access the egress SFTP server security group. Required when `sftp_egress_endpoint_type` is `VPC`. | `list(string)` | `[]` | no |
| `sftp_egress_users` | Egress SFTP users (read-only). `home_directory_prefix` is required and must start/end with `/` (use `/` for full bucket access or a subdirectory to scope). | `list(object)` | `[]` | no |

### S3 Lifecycle

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `ingress_lifecycle_days` | Days before objects in the ingress bucket expire. | `number` | `1` | no |
| `egress_lifecycle_days` | Days before objects in the egress bucket transition to Infrequent Access. | `number` | `90` | no |
| `quarantine_lifecycle_days` | Days before objects in the quarantine bucket expire. | `number` | `365` | no |

### Lambda

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `lambda_runtime` | Lambda runtime identifier for the file-router function. | `string` | `"python3.12"` | no |
| `lambda_memory_size` | Memory (MB) allocated to the file-router Lambda (128–10240). | `number` | `256` | no |
| `lambda_timeout` | Timeout (seconds) for the file-router Lambda (1–900). | `number` | `60` | no |
| `lambda_reserved_concurrency` | Reserved concurrent executions for the file-router Lambda. Set to `-1` to use unreserved account concurrency. | `number` | `10` | no |

### Prompt Injection Scanning

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `enable_prompt_injection_scanning` | Enable prompt injection scanning of uploaded documents. When true, files that pass malware scanning are additionally scanned before reaching egress. | `bool` | `false` | no |
| `prompt_injection_threshold` | Score threshold (0–100) above which a file is quarantined for prompt injection. | `number` | `80` | no |
| `prompt_injection_memory_size` | Memory (MB) for the scanner Lambda (512–10240). Higher memory allocates more CPU, speeding up ONNX model loading. 3008 MB recommended. | `number` | `3008` | no |
| `prompt_injection_timeout` | Timeout (seconds) for the scanner Lambda (1–900). | `number` | `120` | no |
| `prompt_injection_reserved_concurrency` | Reserved concurrent executions for the scanner Lambda. Set to `-1` for unreserved. | `number` | `5` | no |
| `prompt_injection_image_uri` | URI of a pre-built container image for the scanner. When set, skips ECR repo creation and image build. | `string` | `null` | no |

### Notifications

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `sns_subscription_emails` | Email addresses subscribed to the malware-alert SNS topic. Each entry is validated as a well-formed email address. | `list(string)` | `[]` | no |

### Quarantine — Object Lock

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `enable_object_lock` | Enable S3 Object Lock on the quarantine bucket for tamper-proof retention. | `bool` | `false` | no |
| `object_lock_retention_days` | Default retention period in days for Object Lock on the quarantine bucket. | `number` | `365` | no |
| `object_lock_retention_mode` | Object Lock retention mode — `GOVERNANCE` or `COMPLIANCE`. | `string` | `"GOVERNANCE"` | no |

### Observability

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `enable_cloudwatch_dashboard` | Create a CloudWatch dashboard with metric filters for pipeline observability. | `bool` | `false` | no |

### Logging

| Name | Description | Type | Default | Required |
|---|---|---|---|---|
| `create_log_bucket` | Create a managed S3 access-log bucket. Set to `false` when shipping logs to an existing bucket via `log_bucket_name`. | `bool` | `true` | no |
| `log_bucket_name` | Name of an existing S3 bucket for access-log shipping. Required when `create_log_bucket` is `false`. | `string` | `null` | no |
| `log_retention_days` | CloudWatch Logs retention period in days. Must be a valid CloudWatch retention value. | `number` | `90` | no |
| `s3_log_retention_days` | Days to retain S3 access logs in the log bucket. | `number` | `90` | no |

## Outputs

| Name | Description |
|---|---|
| `ingress_bucket_id` | Name of the ingress (upload) S3 bucket. |
| `ingress_bucket_arn` | ARN of the ingress (upload) S3 bucket. |
| `egress_bucket_id` | Name of the egress (verified) S3 bucket. |
| `egress_bucket_arn` | ARN of the egress (verified) S3 bucket. |
| `quarantine_bucket_id` | Name of the quarantine (malware-detected) S3 bucket. |
| `quarantine_bucket_arn` | ARN of the quarantine (malware-detected) S3 bucket. |
| `log_bucket_id` | Name of the S3 access-log bucket. |
| `log_bucket_arn` | ARN of the S3 access-log bucket. |
| `kms_key_arn` | ARN of the KMS key used for encryption. |
| `sftp_ingress_server_id` | ID of the AWS Transfer Family SFTP server (null if SFTP disabled). |
| `sftp_ingress_server_endpoint` | Endpoint hostname of the SFTP server (null if SFTP disabled). |
| `sftp_ingress_user_arns` | Map of ingress SFTP username to Transfer user ARN. |
| `sftp_egress_server_id` | ID of the egress SFTP server (null if egress disabled). |
| `sftp_egress_server_endpoint` | Endpoint hostname of the egress SFTP server (null if egress disabled). |
| `sftp_egress_user_arns` | Map of egress SFTP username to Transfer user ARN. |
| `sns_topic_arn` | ARN of the SNS topic for malware alert notifications. |
| `guardduty_protection_plan_arn` | ARN of the GuardDuty Malware Protection plan. |
| `lambda_function_arn` | ARN of the file-router Lambda function. |
| `dlq_arn` | ARN of the file-router Lambda dead letter queue. |
| `eventbridge_rule_arn` | ARN of the EventBridge rule for GuardDuty scan results. |
| `cloudwatch_dashboard_arn` | ARN of the CloudWatch pipeline dashboard (null when disabled). |
| `prompt_injection_scanner_function_arn` | ARN of the prompt injection scanner Lambda function (null when disabled). |
| `prompt_injection_scanner_ecr_repository_url` | URL of the ECR repository for the scanner image (null when disabled or BYO image). |

## Submodules

| Module | Description |
|---|---|
| `modules/s3-buckets` | Creates the ingress, egress, quarantine, and access-log S3 buckets with encryption, versioning, public access blocks, TLS-only policies, and lifecycle rules. |
| `modules/guardduty-protection` | Configures a GuardDuty Malware Protection plan on the ingress bucket with an IAM role for scanning. |
| `modules/file-router` | Deploys the Lambda function, EventBridge rule, SNS topic, SQS DLQ, and IAM role that route files based on scan results. |
| `modules/sftp` | Optionally provisions an AWS Transfer Family SFTP server (or attaches to an existing one), creates SFTP users with scoped IAM roles and SSH key authentication. |

## How It Works

1. **Upload** — Files are uploaded to the ingress bucket, either via direct S3 PutObject or through the optional SFTP endpoint (AWS Transfer Family).

2. **Scan** — GuardDuty Malware Protection for S3 automatically scans every new object in the ingress bucket and tags it with the scan result.

3. **Event** — When the scan completes, GuardDuty emits a `GuardDuty Malware Protection Object Scan Result` event to EventBridge.

4. **Route** — An EventBridge rule invokes the file-router Lambda function with the scan result:
   - **NO_THREATS_FOUND** — if prompt injection scanning is enabled, the file router invokes the scanner Lambda synchronously. If the score exceeds the threshold, the file is quarantined. Otherwise (or if scanning is disabled), the file is copied to the egress bucket and deleted from ingress.
   - **THREATS_FOUND** — the file is copied to the quarantine bucket, deleted from ingress, and an SNS notification is published with threat details.
   - **Other results** (e.g., `UNSUPPORTED`, `ACCESS_DENIED`) — the file is left in ingress for manual review.

5. **Alert** — If threats are detected, subscribed email addresses receive a JSON-formatted alert with the file key, threat names, and timestamp.

6. **Egress** (optional) — Verified files in the egress bucket can be pulled by downstream receivers via a read-only SFTP endpoint. Egress users have `GetObject` and `ListBucket` permissions only (no `PutObject`).

## External KMS Key

When using an externally managed KMS key (`create_kms_key = false`), your key policy must grant the following permissions to the AWS services used by this module:

```json
[
  {
    "Sid": "AllowSecureUploadServices",
    "Effect": "Allow",
    "Principal": {
      "Service": [
        "guardduty.amazonaws.com",
        "lambda.amazonaws.com",
        "s3.amazonaws.com",
        "transfer.amazonaws.com",
        "sns.amazonaws.com"
      ]
    },
    "Action": [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
      "kms:DescribeKey"
    ],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "aws:SourceAccount": "<YOUR_ACCOUNT_ID>"
      }
    }
  },
  {
    "Sid": "AllowCloudWatchLogs",
    "Effect": "Allow",
    "Principal": {
      "Service": "logs.<YOUR_REGION>.amazonaws.com"
    },
    "Action": [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
      "kms:DescribeKey"
    ],
    "Resource": "*",
    "Condition": {
      "ArnLike": {
        "kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:<YOUR_REGION>:<YOUR_ACCOUNT_ID>:log-group:*"
      }
    }
  }
]
```

The module's IAM roles (Lambda, GuardDuty, Transfer Family users) also need `kms:Decrypt` and `kms:GenerateDataKey` grants on the key. These are handled automatically by the module's IAM policies — you only need to ensure the key policy allows the services listed above.

**Prompt injection scanning**: When `enable_prompt_injection_scanning` is `true` and a BYO image is not provided (`prompt_injection_image_uri` is `null`), the module creates an ECR repository encrypted with the same KMS key. ECR requires `kms:CreateGrant` on the key — the principal running Terraform must have this permission in the key policy. For module-managed keys this is already covered by the `AllowAccountManagement` statement. For external keys, add the following to your key policy:

```json
{
  "Sid": "AllowECRGrants",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<YOUR_ACCOUNT_ID>:root"
  },
  "Action": [
    "kms:CreateGrant",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "Bool": {
      "kms:GrantIsForAWSResource": "true"
    }
  }
}
```

This scoped condition ensures grants can only be created for AWS services (ECR), not arbitrary principals. Alternatively, if you provide a pre-built image via `prompt_injection_image_uri`, no ECR repository is created and this grant is not needed.

## Cross-Account Log Shipping

To ship S3 access logs to a centralized logging bucket (e.g., in a separate AWS account), set `create_log_bucket = false` and provide the bucket name:

```hcl
module "secure_upload" {
  source = "path/to/terraform-secure-upload"

  name_prefix       = "myapp"
  create_log_bucket = false
  log_bucket_name   = "central-logging-bucket"
}
```

The external bucket must have a policy that allows S3 log delivery from the source account. Example bucket policy for the centralized logging bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3LogDelivery",
      "Effect": "Allow",
      "Principal": {
        "Service": "logging.s3.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::central-logging-bucket/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "<SOURCE_ACCOUNT_ID>"
        }
      }
    }
  ]
}
```

When using an external log bucket, the module does not manage the bucket's lifecycle, encryption, or access controls — the caller is responsible for those.

The `log_bucket_arn` output will be `null` when using an external bucket (since the module does not own it).

## External Changes Required

Depending on your configuration, you may need to make changes **outside this module** before deployment:

| Scenario | External Action Required |
|---|---|
| **External KMS key** (`create_kms_key = false`) | Update the KMS key policy to grant service principals access. See [External KMS Key](#external-kms-key) above. |
| **External KMS key + prompt injection scanning** | Additionally grant `kms:CreateGrant` for ECR repository encryption. See the prompt injection note under [External KMS Key](#external-kms-key). Not needed when providing a pre-built image via `prompt_injection_image_uri`. |
| **Cross-account KMS key** | Add cross-account grants for the module's IAM roles (output as `lambda_role_arn`, `guardduty_role_arn`, etc.). |
| **External log bucket** (`create_log_bucket = false`) | Configure the bucket policy, encryption, and lifecycle. See [Cross-Account Log Shipping](#cross-account-log-shipping) above. |
| **Existing SFTP server** (`create_sftp_ingress_server = false`) | Ensure the server uses `SERVICE_MANAGED` identity and the `SFTP` protocol. |
| **SNS email alerts** | Recipients must manually confirm their email subscription before alerts are delivered. |
| **GuardDuty first use** | The calling principal needs `iam:CreateServiceLinkedRole` permission for GuardDuty to create its service-linked role on first use. |

For a comprehensive security checklist for external resources, see [SECURITY.md](SECURITY.md).

## Known Limitations

- **GuardDuty region availability** — GuardDuty Malware Protection for S3 is not available in all AWS regions. Check [AWS regional availability](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_regions.html).
- **Scan latency** — GuardDuty scans are asynchronous. Files remain in the ingress bucket until the scan completes (typically seconds to minutes).
- **File size limits** — GuardDuty Malware Protection supports objects up to 5 GB. Larger files are not scanned.
- **Object Lock requires bucket recreation** — Enabling `enable_object_lock` after the quarantine bucket already exists requires destroying and recreating the bucket (S3 limitation).
- **SNS email confirmation** — Email subscriptions require manual confirmation by each recipient before alerts are delivered.
- **SFTP users are service-managed** — This module uses Transfer Family's service-managed identity provider. Custom/external identity providers are not supported.
- **Single ingress bucket** — All SFTP users share the same ingress bucket, isolated by home directory prefix.

## Upgrading to v0.2.1

v0.2.1 contains two breaking changes:

1. **Bucket names now include a hashed account ID** — Bucket names changed from `<prefix>-ingress` to `<prefix>-<hash>-ingress` (and similarly for egress, quarantine, logs). This ensures global uniqueness. Existing deployments will see Terraform plan to destroy and recreate all four buckets. **Back up your data before upgrading** or use `terraform state mv` to migrate.

2. **S3 bucket policy condition changed** — `DenyNonKMSEncryption` and `DenyWrongKMSKey` statements now use `StringNotEquals` with a `Null` condition guard (see v0.3.0 notes). This correctly allows AWS services that rely on bucket default encryption while denying uploads that explicitly specify wrong encryption. This is a policy-only change and does not affect bucket resources.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and pull request guidelines.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy and an overview of the module's security design.

## License

MIT — see [LICENSE](LICENSE) for details.
