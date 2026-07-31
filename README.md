# Secure S3 upload with optional SFTP

This Terraform module creates a small, fail-closed upload pipeline:

1. Objects land in an encrypted S3 ingress bucket.
2. GuardDuty Malware Protection for S3 scans each uploaded object.
3. `NO_THREATS_FOUND` objects move to a clean bucket.
4. Threats, unsupported objects, access-denied scans, and failed scans move to quarantine.
5. One SNS topic per module instance receives every scan result notification.

The optional Transfer Family path creates one service-managed SFTP server using a VPC-hosted, internet-facing endpoint. The caller supplies public subnets, one Elastic IP allocation per subnet, and source CIDRs for TCP/22. Users are mapped to logical `/` directories backed by distinct S3 prefixes.

Transfer Family S3 directory listing optimization is enabled, so logical home directories do not require zero-byte S3 folder objects at server startup. Optional custom hostnames are applied using the AWS-supported Transfer Family system tags; the module can also create a Route 53 CNAME when a hosted zone ID is supplied.

The ingress bucket deliberately disables S3 Bucket Keys so KMS receives the individual S3 object ARN as its encryption context. Each SFTP user can therefore use the shared CMK only for objects below that user's logical home prefix, in addition to the normal S3 IAM restriction. Clean and quarantine buckets retain S3 Bucket Keys because SFTP users do not access them.

Ingress versioning binds each malware-scan verdict to the exact object version that GuardDuty inspected. The scan router rejects events without a usable version ID and never falls back to the current key. Ingress current objects and noncurrent versions expire using `ingress_object_expiration_days` and `ingress_noncurrent_version_expiration_days`; the defaults are 7 days for each.

S3 server access logs for the ingress, clean, and quarantine buckets are delivered as structured logs to the KMS-encrypted CloudWatch Logs group exported as `s3_access_log_group_name`. The module does not create an S3 access-log bucket.

## Usage

```hcl
module "secure_upload" {
  source = "./"

  name_prefix = "partner-upload"

  enable_sftp                 = true
  sftp_vpc_id                 = "vpc-0123456789abcdef0"
  sftp_subnet_ids             = ["subnet-aaa", "subnet-bbb"]
  sftp_address_allocation_ids = ["eipalloc-aaa", "eipalloc-bbb"]
  sftp_allowed_cidrs          = ["203.0.113.10/32"]
  sftp_custom_hostname        = "sftp.example.com"
  # Optional: also create the CNAME in this public Route 53 hosted zone.
  sftp_route53_hosted_zone_id = null
  sftp_users = [
    {
      username              = "partner-a"
      ssh_public_key        = "ssh-ed25519 AAAA... partner-a@example.com"
      home_directory_prefix = "/uploads/partner-a/"
    }
  ]
}
```

Use disjoint user prefixes such as `/uploads/partner-a/` and `/uploads/partner-b/`; ancestor/descendant pairs such as `/uploads/partner/` and `/uploads/partner/acme/` are rejected. This both isolates IAM access and distributes S3 request load across prefixes. S3 prefixes are virtual, and Transfer Family S3 directory listing optimization allows these logical homes to operate without placeholder objects at startup.

All taggable resources receive the supplied `tags` plus `Module=terraform-secure-upload` and `ManagedBy=terraform`. AWS resources without tag support, such as KMS aliases, IAM inline policies, and Route 53 records, cannot receive tags.

## Important caller responsibilities

- Internet-facing VPC Transfer endpoints require public subnet routing through an internet gateway and an Elastic IP for each selected subnet.
- Restrict `sftp_allowed_cidrs` to partner networks. `0.0.0.0/0` is rejected.
- Supply SSH public keys only. Private keys remain with the client.
- Subscribe downstream consumers to the exported `sns_topic_arn`.
- If using a custom hostname with an external DNS provider, create a CNAME from that hostname to the Transfer Family VPC endpoint DNS name. Supplying `sftp_route53_hosted_zone_id` makes the module create the Route 53 record instead.
- Configure clean and quarantine retention and archival policies in the consuming stack. Ingress current objects and noncurrent versions expire using `ingress_object_expiration_days` and `ingress_noncurrent_version_expiration_days`.
- If supplying `kms_key_arn`, use a full symmetric customer-managed KMS key ARN. For a key in a central security account, its key policy must grant the workload account or module-created roles and required AWS services, and the workload IAM policies must also grant the required KMS actions. The key must be in the same Region as the workload resources.
- Do not grant SFTP user roles broad standalone KMS permissions. Their KMS permissions are intentionally constrained to S3 requests whose encryption context matches their home prefix.

## Outputs

The main outputs are `ingress_bucket_id`, `clean_bucket_id`, `quarantine_bucket_id`, `s3_access_log_group_name`, `s3_access_log_group_arn`, `sns_topic_arn`, `guardduty_protection_plan_arn`, `eventbridge_rule_arn`, `dlq_arn`, and `kms_key_arn`. When SFTP is enabled, `sftp_server_id`, `sftp_server_endpoint`, `sftp_hostname`, and `sftp_user_arns` are populated.

## Verification

```bash
terraform fmt -recursive
terraform init -backend=false
terraform validate
terraform test -filter=tests/validation.tftest.hcl
terraform test -filter=tests/s3_security.tftest.hcl
terraform test -filter=tests/sftp.tftest.hcl
```

Native Terraform tests use a mocked provider and do not create AWS resources. Live integration tests require AWS credentials and a sandbox account.

## Full AWS integration test

The deploy-and-exercise harness creates the S3+SFTP stack, two users, temporary KMS/SQS resources, clean and EICAR-style uploads through S3 and SFTP, logical-home command checks, lateral-movement attempts, SNS assertions, and CloudWatch log checks. It purges test objects, destroys Terraform resources, schedules the temporary KMS key for deletion, and prints a PASS/FAIL/WARN/SKIP report.

Run it from the repository root with AWS credentials for a disposable account:

```bash
export RUN_AWS_INTEGRATION=1
export AWS_REGION=us-east-1
export TEST_SFTP_VPC_ID=vpc-0123456789abcdef
export TEST_SFTP_SUBNET_IDS=subnet-aaa,subnet-bbb
export TEST_SFTP_ALLOWED_CIDRS=203.0.113.10/32
(cd test && go test -v -timeout=30m -run '^TestFullIntegration$')
```

`TEST_SFTP_EIP_ALLOCATION_IDS` is optional; omitted IDs cause the harness to allocate tagged temporary EIPs and release them during cleanup. `TEST_SFTP_CUSTOM_HOSTNAME` and `TEST_SFTP_ROUTE53_HOSTED_ZONE_ID` are optional. The harness is skipped unless `RUN_AWS_INTEGRATION=1` or `true`; it is not a substitute for a controlled AWS staging test.

## AWS references

- [GuardDuty Malware Protection for S3](https://docs.aws.amazon.com/guardduty/latest/ug/how-malware-protection-for-s3-gdu-works.html)
- [GuardDuty S3 scan result events](https://docs.aws.amazon.com/guardduty/latest/ug/monitor-with-eventbridge-s3-malware-protection.html)
- [Transfer Family VPC-hosted endpoints](https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html)
- [Transfer Family logical directories](https://docs.aws.amazon.com/transfer/latest/userguide/logical-dir-mappings.html)
- [Transfer Family custom hostnames](https://docs.aws.amazon.com/transfer/latest/userguide/requirements-dns.html)
- [Transfer Family S3 IAM policies](https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html)
- [S3 performance optimization](https://docs.aws.amazon.com/AmazonS3/latest/userguide/optimizing-performance.html)
- [S3 SSE-KMS encryption context](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
- [AWS KMS encryption-context conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)
- [CloudWatch Logs delivery for S3 server access logs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
