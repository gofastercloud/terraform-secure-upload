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
- **Least-privilege IAM** — Each component (Lambda, GuardDuty, Transfer Family, SFTP users) receives a scoped IAM role with only the permissions it needs.
- **Public access blocked** — All buckets have S3 Block Public Access enabled on every setting.
- **Bucket ownership enforced** — ACLs are disabled; the bucket owner controls all objects.
- **Object Lock** — Optional WORM retention on the quarantine bucket for tamper-proof evidence preservation.
- **Dead letter queue** — Failed Lambda invocations are captured in an SQS DLQ so no scan results are silently lost.

## Supported Versions

We provide security fixes for the latest release only. If you are using an older version, please upgrade before reporting.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No |

## Disclosure Policy

We follow coordinated disclosure. Once a fix is released, we will credit the reporter (unless they prefer to remain anonymous) in the release notes.
