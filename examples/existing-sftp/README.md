# Existing SFTP Server Example

Deploys `terraform-secure-upload` and attaches SFTP users to an **existing** AWS Transfer Family server instead of creating a new one. This is useful when you already have a Transfer Family server shared across multiple applications.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set sftp_server_id to your existing server
terraform init
terraform plan
terraform apply
```

## Notes

- The existing server must use `SERVICE_MANAGED` identity provider type
- The module creates new SFTP users and IAM roles scoped to the staging bucket
- The existing server's endpoint type (PUBLIC or VPC) does not need to be specified — it is already configured on the server
