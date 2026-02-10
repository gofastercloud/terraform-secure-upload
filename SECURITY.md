# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly. **Do not open a public GitHub issue.**

Instead, please email **security@gofaster.cloud** with:

- A description of the vulnerability
- Steps to reproduce or a proof of concept
- The affected version(s)
- Any suggested remediation, if you have one

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation plan within 7 days for confirmed issues.

## Scope

This policy covers the Terraform module code in this repository. It does **not** cover:

- The AWS services the module provisions (report those to [AWS Security](https://aws.amazon.com/security/vulnerability-reporting/))
- Your own infrastructure configuration or deployment environment
- Third-party dependencies managed by HashiCorp (Terraform providers)

## Security Design

This module follows AWS security best practices by default:

- **Encryption at rest** — All S3 buckets use KMS server-side encryption with bucket keys enabled.
- **Encryption in transit** — Bucket policies deny any request made over plain HTTP (`aws:SecureTransport = false`).
- **KMS enforcement in bucket policies** — Bucket policies on the ingress, egress, and quarantine buckets deny `PutObject` requests that don't use KMS encryption (`s3:x-amz-server-side-encryption != aws:kms`) or that use the wrong KMS key (`s3:x-amz-server-side-encryption-aws-kms-key-id != module key ARN`). This prevents uploads encrypted with SSE-S3 or a different KMS key.
- **Least-privilege IAM** — Each component (Lambda, GuardDuty, Transfer Family, SFTP users) receives a scoped IAM role with only the permissions it needs.
- **Public access blocked** — All buckets have S3 Block Public Access enabled on every setting.
- **Bucket ownership enforced** — ACLs are disabled; the bucket owner controls all objects.
- **Object Lock** — Optional WORM retention on the quarantine bucket for tamper-proof evidence preservation.
- **SFTP path isolation** — Ingress SFTP users are scoped to a subdirectory via validated `home_directory_prefix` (bare `/` and `..` path traversal are rejected). IAM policies enforce a trailing `/` separator to prevent prefix-overlap attacks.
- **Dead letter queue** — Failed Lambda invocations are captured in an SQS DLQ so no scan results are silently lost.
- **Lambda error alarm** — A CloudWatch alarm on the Lambda `Errors` metric fires to the SNS alert topic when invocation errors occur (timeouts, crashes, permission failures), independent of the DLQ depth alarm.
- **CloudWatch dashboard** — Optional metric filters and dashboard for pipeline observability. The metric filters operate on the existing Lambda log group and do not require additional IAM permissions beyond what the Lambda already has for CloudWatch Logs.
- **Deletion protection** — The KMS key and quarantine bucket have `prevent_destroy` lifecycle rules to prevent accidental deletion via `terraform destroy` or refactoring. To remove these resources, the lifecycle block must be explicitly removed from the module source first.

## Caller Security Responsibilities

While this module enforces security best practices for resources it manages, several scenarios require the caller to maintain security properties on external resources:

### External KMS Key

When providing your own KMS key (`create_kms_key = false`):

- Ensure the key policy follows least privilege — grant only the specific service principals needed (`guardduty.amazonaws.com`, `lambda.amazonaws.com`, `s3.amazonaws.com`, `transfer.amazonaws.com`, `sns.amazonaws.com`), scoped by `aws:SourceAccount`.
- If the key is in a different account, create cross-account grants for the module's IAM roles rather than using `"Principal": "*"` with conditions. The module outputs all role ARNs.
- Enable automatic key rotation on your externally managed key.
- Do not use the same key for unrelated workloads — this widens the blast radius if the key is compromised.

### External Log Bucket

When using an existing log bucket (`create_log_bucket = false`):

- Enforce KMS-SSE or SSE-S3 encryption on the log bucket.
- Apply a bucket policy that restricts writes to `logging.s3.amazonaws.com` with `aws:SourceAccount` condition.
- Enable versioning and configure lifecycle rules for log retention per your compliance requirements.
- Block public access on the log bucket.

### Existing Transfer Family Server

When attaching to a pre-existing SFTP server (`create_sftp_ingress_server = false`):

- Ensure the server's CloudWatch logging is configured (the module does not modify existing server settings).
- For VPC-type servers, ensure security groups restrict inbound access to known CIDR ranges.
- Review the server's security policy — the module does not set the TLS policy on existing servers.

### Network Security (VPC Endpoints)

When using VPC-type SFTP endpoints:

- Restrict `sftp_ingress_allowed_cidrs` to the minimum set of source IP ranges that need SFTP access.
- Consider using AWS PrivateLink or VPN for partner connectivity rather than public endpoints.
- Monitor VPC Flow Logs for unexpected traffic to the SFTP endpoint ENIs.

## Supported Versions

We provide security fixes for the latest release only. If you are using an older version, please upgrade before reporting.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No |

## Disclosure Policy

We follow coordinated disclosure. Once a fix is released, we will credit the reporter (unless they prefer to remain anonymous) in the release notes.
