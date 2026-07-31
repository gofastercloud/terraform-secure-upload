# Contributing

Thanks for your interest in contributing to `terraform-secure-upload`. This guide covers the process for submitting changes.

## Getting Started

1. Fork the repository and clone your fork.
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-change
   ```
3. Make your changes and commit using [Conventional Commits](https://www.conventionalcommits.org/) style:
   ```bash
   git commit -m "feat: improve SFTP access controls"
   ```

## Prerequisites

| Tool | Version |
|---|---|
| [Docker](https://docs.docker.com/get-docker/) or [OrbStack](https://orbstack.dev/) | Latest |
| [Make](https://www.gnu.org/software/make/) | Any |

Docker runs Terraform checks at the pinned project version (`1.9.8`). You do **not** need Terraform installed locally.

For running integration tests that create real AWS resources, you also need:

| Tool | Version |
|---|---|
| AWS CLI | v2 |
| AWS credentials | configured for a sandbox account |
| Go | 1.21 or newer |
| OpenSSH client | `ssh-keygen` and `sftp` on `PATH` |
| Terraform | `>= 1.9` on `PATH` for the live harness |

## Development Workflow

### Local Checks (recommended)

Run the full CI-equivalent suite with a single command:

```bash
make test
```

This runs `fmt-check`, `validate`, and `test-validation` inside a Docker container with the correct Terraform version. No local Terraform installation required.

Available Makefile targets:

| Target | What it does |
|---|---|
| `make fmt` | Format all `.tf` and `.tftest.hcl` files in place |
| `make fmt-check` | Check formatting without modifying files (matches CI) |
| `make validate` | Run `terraform init` and `terraform validate` |
| `make test-validation` | Run validation-only tests (no AWS credentials needed) |
| `make test` | Run all three above (full CI equivalent) |
| `make test-all` | Run all native Terraform tests with mocked providers |
| `make test-integration` | Run the opt-in full AWS deploy-and-exercise harness |

Override the Terraform version if needed: `make test TF_VERSION=1.10.0`

### Manual Checks (without Docker)

If you prefer to run checks without Docker, you need Terraform `>= 1.9`:

```bash
terraform fmt -recursive
terraform init -backend=false
terraform validate
terraform test -filter=tests/validation.tftest.hcl
```

### Tests

This project uses Terraform's native test framework. Tests live in the `tests/` directory.

- **`validation.tftest.hcl`** — Variable validation rule tests. Uses `mock_provider` so no AWS credentials are needed. These run in CI on every push/PR.
- **`basic.tftest.hcl`** — S3-only root-module plan test using a mocked provider.
- **`sftp.tftest.hcl`** — SFTP endpoint and logical-directory plan test using a mocked provider.
- **`s3_security.tftest.hcl`** — S3 encryption and bucket-security plan test using a mocked provider.

The native Terraform tests plan resources with a mocked provider and do not create AWS resources. Live integration testing requires a separately configured sandbox account.

### Full AWS integration test

The full harness is opt-in and creates real S3, GuardDuty, Lambda, SNS, SQS, KMS, Transfer Family, VPC security-group, and CloudWatch resources. It exercises S3 and SFTP clean/dirty uploads, logical homes, common SFTP commands, lateral-movement failures, SNS delivery, and CloudWatch logs before cleanup.

```bash
export RUN_AWS_INTEGRATION=1
export AWS_REGION=us-east-1
export TEST_SFTP_VPC_ID=vpc-0123456789abcdef
export TEST_SFTP_SUBNET_IDS=subnet-aaa,subnet-bbb
export TEST_SFTP_ALLOWED_CIDRS=203.0.113.10/32
(cd test && go test -v -timeout=30m -run '^TestFullIntegration$')
```

The harness allocates and releases tagged temporary EIPs when `TEST_SFTP_EIP_ALLOCATION_IDS` is omitted. Set that variable to reuse existing allocations. Set `TEST_SFTP_CUSTOM_HOSTNAME` and `TEST_SFTP_ROUTE53_HOSTED_ZONE_ID` when testing custom DNS. The command prints the test report and must run only against a disposable AWS account.

### Documentation

If you add or change a variable, output, or module behaviour:

1. Update the relevant `variables.tf` description.
2. Update the inputs/outputs tables in `README.md`.
3. Add or update examples in the `examples/` directory if the change affects user-facing configuration.

## Pull Request Process

1. Ensure your branch is up to date with `main`.
2. Verify that `make test` passes locally.
3. Open a pull request against `main` with a clear title and description.
4. Link any related issues (e.g., `Closes #42`).
5. A maintainer will review your PR. Please respond to feedback promptly.

## What We Look For

- **Backward compatibility** — Breaking changes require discussion in an issue first.
- **Minimal scope** — One logical change per PR. Avoid bundling unrelated fixes.
- **Variable validation** — New variables should include `validation` blocks where sensible.
- **Test coverage** — New variables with validation rules should have a corresponding test in `tests/validation.tftest.hcl`. Behavioral changes should have plan-level or apply-level tests as appropriate.
- **Security defaults** — Resources should be secure by default (encryption enabled, public access blocked, TLS enforced). Relaxing security posture requires an explicit opt-in variable.

## Reporting Bugs

Open a [GitHub issue](https://github.com/gofastercloud/terraform-secure-upload/issues) with:

- Terraform/OpenTofu version
- AWS provider version
- Module version or commit SHA
- Minimal reproduction configuration
- Expected vs. actual behaviour

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
