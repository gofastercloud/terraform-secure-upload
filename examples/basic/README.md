# Basic Example

Minimal deployment of `terraform-secure-upload` using direct S3 uploads only (no SFTP). The module creates a KMS key, four S3 buckets (staging, clean, quarantine, logs), GuardDuty Malware Protection, and the file-router Lambda.

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
aws s3 cp test-file.txt s3://$(terraform output -raw staging_bucket_id)/
```
