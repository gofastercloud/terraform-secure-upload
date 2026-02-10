# Secure File Upload Module - Architecture

## Overview

This Terraform module provides a secure file upload pipeline with automated malware scanning,
optional VirusTotal hash lookup, and optional prompt injection detection. Files uploaded via
S3 API or SFTP are scanned by GuardDuty Malware Protection. If enabled, VirusTotal scanning
runs in parallel via EventBridge, tagging objects with results. The file router reads all scan
results and routes files to egress or quarantine buckets accordingly.

## Flow

```
                    ┌─────────────┐
                    │  S3 Direct  │
                    │   Upload    │
                    └──────┬──────┘
                           │
                           ▼
┌─────────────┐    ┌──────────────┐
│  SFTP User  │───>│   Ingress    │
│  (Transfer  │    │   Bucket     │
│   Family)   │    └──────┬───────┘
└─────────────┘           │
                 ┌────────┴─────────┐
                 │                  │
                 ▼                  ▼
      ┌────────────────────┐  ┌──────────────┐
      │  GuardDuty Malware │  │  VirusTotal  │
      │  Protection for S3 │  │  Hash Lookup │
      └─────────┬──────────┘  │ (tags object)│
                │             └──────────────┘
                │ EventBridge
                ▼
       ┌────────────────┐
       │  Router Lambda │ (reads VT tags)
       └───┬────────┬───┘
           │        │
  Clean    │        │  Malware / VT positive
           │        ▼
           │   ┌──────────────┐
 [scanning │   │  Quarantine  │
  enabled?]│   │    Bucket    │
    │      │   └──────┬───────┘
   YES     │          │
    │     NO          ▼
    ▼      │   ┌──────────────┐
 ┌──────────┐  │   │  SNS Alert   │
 │  Prompt  │  │   │    Topic     │
 │ Injection│  │   └──────────────┘
 │ Scanner  │  │
 └──┬───┬───┘  │
Safe │   │Risky│
    │   │      │
    │   └──────┤
    ▼          │
 ┌──────────┐  │
 │  Egress  │  │
 │  Bucket  │  │
 └────┬─────┘  │
      │        │
      ▼        ▼
┌─────────────┐  (Quarantine
│ SFTP Egress │   + SNS Alert)
│ (read-only) │
└─────────────┘
```

## Module Structure

```
terraform-secure-upload/
├── main.tf              # Root module — orchestrates submodules
├── variables.tf         # Root module input variables
├── outputs.tf           # Root module outputs
├── versions.tf          # Provider and Terraform version constraints
├── locals.tf            # Common locals (account ID, region, tags, KMS key)
├── Makefile             # Docker-based local dev checks (fmt, validate, test)
├── modules/
│   ├── s3-buckets/      # S3 infrastructure (ingress, egress, quarantine, logs)
│   ├── guardduty-protection/  # GuardDuty Malware Protection plan + IAM
│   ├── file-router/     # Lambda + EventBridge + SNS + SQS DLQ
│   └── sftp/            # Transfer Family server + users (used by both ingress and egress)
├── prompt-injection.tf  # ECR repo, scanner Lambda, IAM (gated on enable flag)
├── prompt-injection-variables.tf  # Scanner configuration variables
├── lambda/
│   ├── file_router.py   # Lambda function — routes files based on scan results
│   └── virustotal_scanner.py  # Lambda function — VT hash lookup + S3 tagging
├── functions/
│   └── prompt_injection_scanner/  # Container-image Lambda
│       ├── Dockerfile             # Python 3.12 + ONNX model + doc parsing libs
│       ├── handler.py             # Download, extract text, run ONNX inference
│       └── requirements.txt       # onnxruntime, transformers, PyPDF2, etc.
├── examples/
│   ├── basic/           # S3-only upload, minimal config
│   ├── complete/        # Full config with SFTP, custom KMS, VPC
│   └── existing-sftp/   # Using existing Transfer Family server
├── test-files/
│   └── generate.py      # uv-runnable script to create test files (clean, EICAR, PI)
├── tests/               # Terraform native tests (.tftest.hcl)
│   ├── validation.tftest.hcl      # Variable validation tests (runs in CI, no AWS creds)
│   ├── basic.tftest.hcl           # Plan-level module instantiation tests
│   ├── sftp.tftest.hcl            # SFTP ingress module plan-level tests
│   ├── sftp-egress.tftest.hcl     # SFTP egress module plan-level tests
│   └── s3_security.tftest.hcl     # S3 bucket security configuration tests
└── test/                # Terratest (Go) — integration tests
```

## Key Design Decisions

1. **Standalone GuardDuty**: Uses `aws_guardduty_malware_protection_plan` which works
   independently of account-wide GuardDuty detector. No detector resource needed.

2. **Submodule approach**: Each concern is isolated in its own submodule for reusability
   and clear separation of concerns.

3. **Lambda router**: Simple Python Lambda triggered by EventBridge when GuardDuty
   completes scanning. Reads the scan result tag, copies to appropriate bucket, deletes
   from ingress.

4. **SFTP is opt-in**: Both `enable_sftp_ingress` and `enable_sftp_egress` default to
   `false`. Each supports three states: disabled (default), create new server, or attach
   to an existing server. The same `modules/sftp` submodule is used for both directions,
   with `read_only = true` for egress.

5. **KMS encryption**: All buckets use KMS encryption. Module can create a KMS key or
   accept an existing key ARN.

6. **External log bucket**: The module can create its own access-log bucket or ship logs
   to an existing bucket (e.g., a centralized logging account). When using an external
   bucket, the caller is responsible for its policy and lifecycle.

7. **SFTP path isolation**: Ingress SFTP users are scoped to a subdirectory via
   `home_directory_prefix` (validated at the root variable level to prevent bare `/` and
   `..` path traversal). IAM policies use the normalized prefix with a trailing `/`
   separator to prevent prefix-overlap attacks (e.g., `/uploads/a` matching `/uploads/abc`).
   Egress users may optionally access the full bucket.

8. **Docker-based local dev**: A `Makefile` wraps all checks (`fmt`, `validate`, `test`)
   in a Docker container pinned to the same Terraform version as CI, avoiding version
   mismatch issues.

9. **Deletion protection**: The KMS key and quarantine bucket have `prevent_destroy`
   lifecycle rules. These are critical resources — deleting the KMS key renders all
   encrypted data unrecoverable, and deleting the quarantine bucket destroys forensic
   evidence. The lifecycle rules must be removed from source before these resources
   can be destroyed.

10. **SFTP namespace isolation**: The ingress SFTP module uses `${name_prefix}-ingress`
    and the egress module uses `${name_prefix}-egress` to prevent Transfer Family
    resource name collisions when both are enabled simultaneously.

11. **Prompt injection scanning**: Optional second scanning step gated behind
    `enable_prompt_injection_scanning`. The file router invokes a container-image
    Lambda synchronously (`InvocationType: RequestResponse`) for files that pass
    GuardDuty. The scanner runs the `protectai/deberta-v3-base-prompt-injection-v2`
    ONNX model (184M params, Apache 2.0) to score text content. Non-text files
    (images, binaries) get score 0 and pass through. The file router timeout
    auto-bumps to `scanner_timeout + 30s` when scanning is enabled. The scanner
    image is ~1.6GB; cold starts benefit from higher memory (more CPU).

12. **Parallel VirusTotal scanning**: When enabled, the VT scanner triggers immediately
    on upload via an EventBridge rule on S3 Object Created events, running in parallel
    with GuardDuty's deeper scan. VT results are written as S3 object tags (`vt-status`,
    `vt-positives`, `vt-total`, `vt-sha256`). The file router reads these tags when making
    its routing decision, falling back to synchronous invocation if tags are absent (race
    condition safety). This architecture eliminates sequential latency without sacrificing
    reliability.

13. **CloudWatch dashboard**: Optional observability layer gated behind
    `enable_cloudwatch_dashboard`. Uses CloudWatch metric filters on the existing
    Lambda log group to derive file routing metrics (egress, quarantine, review,
    skipped) without any Lambda code changes. The dashboard combines custom metrics
    with native AWS/Lambda, AWS/SQS, and AWS/S3 metrics in a single view.

## External Dependencies and Caller Responsibilities

This module is largely self-contained, but several configurations require the caller to manage resources or policies outside the module:

### External KMS Key (`create_kms_key = false`)

When bringing your own KMS key, the caller is responsible for:

- **Key policy grants** — The key policy must allow `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey*`, `kms:ReEncrypt*`, and `kms:DescribeKey` for the AWS service principals used by the module (`guardduty.amazonaws.com`, `lambda.amazonaws.com`, `s3.amazonaws.com`, `transfer.amazonaws.com`, `sns.amazonaws.com`). Scope with `aws:SourceAccount` condition.
- **Cross-account grants** — If the KMS key lives in a different account, you must also create grants or key policy statements allowing the IAM roles created by this module to use the key. The module outputs all role ARNs for this purpose.
- **Key rotation** — The module does not manage rotation for externally provided keys.

### External Log Bucket (`create_log_bucket = false`)

When shipping S3 access logs to an existing bucket:

- **Bucket policy** — The target bucket must allow `s3:PutObject` from the `logging.s3.amazonaws.com` service principal, scoped to the source account.
- **Encryption** — If the log bucket uses KMS-SSE, the key policy must allow the S3 log delivery service to encrypt.
- **Lifecycle and retention** — The module does not manage lifecycle rules on the external bucket.

### Existing Transfer Family Server (`create_sftp_ingress_server = false`)

When attaching to a pre-existing SFTP server:

- **Server configuration** — The existing server must use the `SERVICE_MANAGED` identity provider type and support the `SFTP` protocol.
- **Logging role** — The module creates its own CloudWatch logging role, but the existing server's logging configuration is not modified.
- **Security groups** — For VPC-type servers, the caller manages security groups and network access.

### VPC Endpoint Type (`sftp_ingress_endpoint_type = "VPC"`)

When using VPC-type SFTP endpoints:

- **VPC and subnets** — Must exist before module deployment. The module does not create networking infrastructure.
- **Security groups** — The module creates a security group with ingress from `sftp_ingress_allowed_cidrs`. The caller must ensure the VPC has appropriate routing (NAT gateway, VPC endpoints, or internet gateway as needed).
- **EC2 permissions** — VPC-type endpoints require EC2 permissions for security group and ENI operations (e.g. `ec2:CreateSecurityGroup`, `ec2:CreateNetworkInterface`).

### GuardDuty

- **Regional availability** — GuardDuty Malware Protection for S3 must be available in the deployment region. The module creates a standalone `aws_guardduty_malware_protection_plan` and does not require an account-wide GuardDuty detector.
- **Service-linked role** — GuardDuty may require a service-linked role (`AWSServiceRoleForAmazonGuardDutyMalwareProtection`). AWS creates this automatically on first use, but it requires `iam:CreateServiceLinkedRole` permission.

### SNS Email Subscriptions

- Email subscriptions created by the module require **manual confirmation** by each recipient. Unconfirmed subscriptions will not receive alerts.
