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
│   ├── validation.tftest.hcl   # Variable validation tests (runs in CI, no AWS creds)
│   ├── basic.tftest.hcl        # Plan-level module instantiation tests
│   ├── sftp.tftest.hcl         # SFTP module plan-level tests
│   └── s3_security.tftest.hcl  # S3 bucket security configuration tests
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
