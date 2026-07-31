# Codex instructions

- The supported deployment shapes are S3-only and S3 plus one optional Transfer Family SFTP endpoint.
- Preserve S3 malware scanning, one SNS topic per instance, logical SFTP homes, Transfer S3 directory-listing optimization, and mandatory KMS encryption-context path isolation.
- Retention, archival, and downstream SNS delivery are configured by consuming stacks.
- Keep SFTP access least-privilege: narrow CIDRs, distinct home prefixes, correct bucket/object ARN separation, and no broad user KMS permissions.
- Use `apply_patch` for edits. Never commit secrets. Run `terraform fmt -recursive`, `terraform validate`, and `terraform test` before claiming completion.
- Do not claim an AWS deployment or live integration test without evidence from an actual apply and verification.
