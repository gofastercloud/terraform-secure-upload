# Basic Example

Minimal deployment using direct S3 uploads only. The module creates encrypted ingress, clean, and quarantine buckets, a KMS-encrypted CloudWatch Logs group for S3 access logs, GuardDuty Malware Protection for S3, a scan router, a dead-letter queue, and one SNS topic for all scan results.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

Upload a test file:

```bash
aws s3 cp test-file.txt s3://$(terraform output -raw ingress_bucket_id)/
```
