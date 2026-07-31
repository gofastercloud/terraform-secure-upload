# Security notes

This module is an S3 upload quarantine boundary, not a general file-sharing platform.

## Defaults

- S3 buckets use KMS encryption, Block Public Access, bucket-owner-enforced ownership, and TLS-only bucket policies. S3 Bucket Keys remain enabled on clean, quarantine, and log buckets; they are disabled on ingress to preserve object-level KMS encryption context.
- GuardDuty Malware Protection for S3 tags scanned objects and emits scan-result events.
- Only `NO_THREATS_FOUND` is treated as clean. Unsupported, failed, and access-denied scans are quarantined.
- A failed router invocation is retried by EventBridge and sent to an SQS dead-letter queue after retry exhaustion.
- SFTP is disabled by default. When enabled, the server is VPC-hosted and internet-facing, source-CIDR restricted, SFTP-only, and uses `TransferSecurityPolicy-2024-01`.
- Each SFTP user receives a separate role and a logical `/` mapping to a distinct S3 prefix.
- Each SFTP user's KMS encrypt/decrypt/data-key permissions are restricted to S3 requests whose encryption context matches that user's logical home prefix and that arrive through S3. This is crypto-level path isolation using the shared CMK, not per-user key material.

## Caller responsibilities

- Use public subnets with internet-gateway routing and one Elastic IP allocation per VPC-hosted internet-facing Transfer endpoint subnet.
- Keep `sftp_allowed_cidrs` narrow. The module rejects `0.0.0.0/0`, but it cannot determine whether a supplied CIDR is operationally appropriate.
- Store SSH private keys outside Terraform and outside this repository.
- Subscribe consumers to the instance SNS topic output.
- Define retention and archival controls in the consuming stack.
- If using an external KMS key, update its key policy for GuardDuty, Transfer Family, Lambda, S3, SNS, CloudWatch Logs, and the module-created IAM roles.
