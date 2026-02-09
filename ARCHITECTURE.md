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
│  SFTP User  │───▶│   Ingress    │───▶│  GuardDuty Malware │
│  (Transfer  │    │   Bucket     │    │  Protection for S3 │
│   Family)   │    └──────────────┘    └─────────┬──────────┘
└─────────────┘                                  │
                                                 │ EventBridge
                                                 ▼
                                        ┌────────────────┐
                                        │  Router Lambda │
                                        └───┬────────┬───┘
                                            │        │
                                   Egress   │        │  Malware
                                            ▼        ▼
                                  ┌──────────┐  ┌──────────────┐
                                  │  Egress  │  │  Quarantine  │
                                  │  Bucket  │  │    Bucket    │
                                  └──────────┘  └──────┬───────┘
                                                       │
                                                       ▼
                                                ┌──────────────┐
                                                │  SNS Alert   │
                                                │    Topic     │
                                                └──────────────┘
```

## Module Structure

```
terraform-secure-upload/
├── main.tf              # Root module - orchestrates submodules
├── variables.tf         # Root module input variables
├── outputs.tf           # Root module outputs
├── versions.tf          # Provider and Terraform version constraints
├── locals.tf            # Common locals (naming, tags)
├── modules/
│   ├── s3-buckets/      # S3 infrastructure (ingress, egress, quarantine, logs)
│   ├── guardduty-protection/  # GuardDuty Malware Protection plan + IAM
│   ├── file-router/     # Lambda + EventBridge + SNS + SQS DLQ
│   └── sftp/            # Transfer Family server + users
├── lambda/
│   └── file_router.py   # Lambda function source code
├── examples/
│   ├── basic/           # S3-only upload, minimal config
│   ├── complete/        # Full config with SFTP, custom KMS, VPC
│   └── existing-sftp/   # Using existing Transfer Family server
├── tests/               # Terraform native tests (.tftest.hcl)
└── test/                # Terratest (Go)
```

## Key Design Decisions

1. **Standalone GuardDuty**: Uses `aws_guardduty_malware_protection_plan` which works
   independently of account-wide GuardDuty detector. No detector resource needed.

2. **Submodule approach**: Each concern is isolated in its own submodule for reusability
   and clear separation of concerns.

3. **Lambda router**: Simple Python Lambda triggered by EventBridge when GuardDuty
   completes scanning. Reads the scan result tag, copies to appropriate bucket, deletes
   from ingress.

4. **SFTP flexibility**: `create_sftp_server` variable controls whether to create a new
   Transfer Family server or use an existing one via `sftp_server_id`.

5. **KMS encryption**: All buckets use KMS encryption. Module can create a KMS key or
   accept an existing key ARN.
