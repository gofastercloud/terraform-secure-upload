# Architecture

```text
S3 API or optional Transfer Family SFTP
                 |
                 v
        encrypted ingress bucket
                 |
       GuardDuty Malware Protection
                 |
        EventBridge scan result
                 |
          scan-router Lambda
          /               \
         v                 v
   clean bucket       quarantine bucket
         \                 /
          ---- SNS topic ----
             every result
```

## Components

- `modules/s3-buckets` creates four encrypted, private buckets: ingress, clean, quarantine, and access logs. Ingress versioning and bounded current/noncurrent lifecycle are managed by the module; clean and quarantine retention and archival remain consumer-configured.
- `modules/guardduty-protection` creates a standalone GuardDuty Malware Protection for S3 plan with post-scan object tagging enabled.
- `modules/file-router` consumes GuardDuty scan-result events, routes the scanned S3 object version, publishes one notification per result, and uses an SQS dead-letter queue for failed processing.
- `modules/sftp` is created only when `enable_sftp = true`. It creates a VPC-hosted, internet-facing SFTP server, a source-CIDR security group, a logging role, and one least-privilege IAM role per service-managed user.

## SFTP access model

Each user has one logical mapping:

```text
logical /  ->  /<ingress-bucket>/<user-prefix-without-leading-slash>
```

The IAM role grants bucket listing only for that prefix and object access only below that prefix. The role trust policy is constrained to Transfer Family users on the module-created server. User prefixes must be disjoint at path-segment boundaries, start and end with `/`, and contain no `..` segments.

The ingress bucket does not use S3 Bucket Keys. This preserves the object ARN encryption context, allowing each user's KMS permissions to require `kms:ViaService = s3.<region>.amazonaws.com` and an encryption context matching that user's S3 prefix. This is a second authorization gate, not separate KMS key material. Clean and quarantine retain S3 Bucket Keys because SFTP users do not access them.

The endpoint uses `endpoint_type = "VPC"` with caller-supplied public subnets and Elastic IP allocation IDs. Custom hostnames use Transfer Family system tags and optional Route 53 CNAME management.

## Failure handling

Only `NO_THREATS_FOUND` is routed to the clean bucket. `THREATS_FOUND`, `UNSUPPORTED`, `ACCESS_DENIED`, and `FAILED` are quarantined and published to the SNS topic. Malformed or unexpected events raise an error so EventBridge retries and eventually uses the dead-letter queue.
