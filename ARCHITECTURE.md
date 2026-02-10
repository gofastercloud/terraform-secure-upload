# Secure File Upload Module - Architecture

## Overview

This Terraform module provides a secure file upload pipeline with automated malware scanning.
Files uploaded via S3 API or SFTP are scanned by GuardDuty Malware Protection, then routed
to egress or quarantine buckets based on scan results.

## Flow

```
                    ┌─────────────┐
                    │  S3 Direct  │
                    │   Upload    │
                    └──────┬──────┘
                           │
                           ▼
┌─────────────┐    ┌──────────────┐    ┌────────────────────┐
│  SFTP User  │───>│   Ingress    │───>│  GuardDuty Malware │
│  (Transfer  │    │   Bucket     │    │  Protection for S3 │
│   Family)   │    └──────────────┘    └─────────┬──────────┘
└─────────────┘                                  │
                                                 │ EventBridge
                                                 ▼
                                        ┌────────────────┐
                                        │  Router Lambda │
                                        └───┬────────┬───┘
                                            │        │
                                   Clean    │        │  Malware
                                            ▼        ▼
                                  ┌──────────┐  ┌──────────────┐
                                  │  Egress  │  │  Quarantine  │
                                  │  Bucket  │  │    Bucket    │
                                  └────┬─────┘  └──────┬───────┘
                                       │               │
                                       ▼               ▼
                              ┌─────────────┐   ┌──────────────┐
                              │ SFTP Egress │   │  SNS Alert   │
                              │ (read-only) │   │    Topic     │
                              └─────────────┘   └──────────────┘
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
├── lambda/
│   └── file_router.py   # Lambda function source code
├── examples/
│   ├── basic/           # S3-only upload, minimal config
│   ├── complete/        # Full config with SFTP, custom KMS, VPC
│   └── existing-sftp/   # Using existing Transfer Family server
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

## External Dependencies and Caller Responsibilities

This module is largely self-contained, but several configurations require the caller to manage resources or policies outside the module:

### SCP / Organization Policy Changes

If your AWS Organization uses a service allowlist SCP (Deny with `NotAction` pattern), you must ensure `"transfer:*"` is in the allowed list before deploying SFTP functionality. The base pipeline (S3, Lambda, GuardDuty, KMS, EventBridge, SQS, SNS, CloudWatch) uses only commonly-allowed services and is unlikely to be blocked.

See `plans/scp-change-request-transfer-family.md` for a detailed change request template.

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
- **EC2 SCP permissions** — VPC-type endpoints require `ec2:*` in service allowlist SCPs (for security group and ENI operations). This is separate from the `transfer:*` requirement.

### GuardDuty

- **Regional availability** — GuardDuty Malware Protection for S3 must be available in the deployment region. The module creates a standalone `aws_guardduty_malware_protection_plan` and does not require an account-wide GuardDuty detector.
- **Service-linked role** — GuardDuty may require a service-linked role (`AWSServiceRoleForAmazonGuardDutyMalwareProtection`). AWS creates this automatically on first use, but it requires `iam:CreateServiceLinkedRole` permission.

### SNS Email Subscriptions

- Email subscriptions created by the module require **manual confirmation** by each recipient. Unconfirmed subscriptions will not receive alerts.
