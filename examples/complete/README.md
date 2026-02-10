# Complete Example

Full deployment of `terraform-secure-upload` with all features enabled:

- VPC-based SFTP endpoint via AWS Transfer Family
- Custom KMS key (or auto-created)
- Multiple SFTP users with isolated home directories
- Email alerts for malware detections
- S3 Object Lock on the quarantine bucket
- Custom Lambda tuning and log retention

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

## Test SFTP Upload

```bash
sftp -i ~/.ssh/partner-a partner-a@$(terraform output -raw sftp_ingress_server_endpoint)
sftp> put test-file.txt /
```
