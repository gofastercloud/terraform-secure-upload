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
   git commit -m "feat: add support for custom log bucket"
   ```

## Prerequisites

| Tool | Version |
|---|---|
| [Terraform](https://www.terraform.io/) or [OpenTofu](https://opentofu.org/) | `>= 1.9` |
| [terraform-docs](https://terraform-docs.io/) | Latest |
| AWS CLI | v2 |

## Development Workflow

### Formatting

All Terraform files must pass `terraform fmt`:

```bash
terraform fmt -recursive
```

### Validation

Run `terraform validate` from the project root:

```bash
terraform init -backend=false
terraform validate
```

### Tests

This project uses Terraform's native test framework. Tests live in the `tests/` directory.

```bash
terraform test
```

> **Note:** Some tests (`basic.tftest.hcl`, `sftp.tftest.hcl`, `s3_security.tftest.hcl`) require AWS credentials and will create real resources. Use a sandbox account. Validation tests (`validation.tftest.hcl`) run in plan-only mode and do not require AWS access.

### Documentation

If you add or change a variable, output, or module behaviour:

1. Update the relevant `variables.tf` description.
2. Update the inputs/outputs tables in `README.md`.
3. Add or update examples in the `examples/` directory if the change affects user-facing configuration.

## Pull Request Process

1. Ensure your branch is up to date with `main`.
2. Verify that `terraform fmt`, `terraform validate`, and `terraform test` all pass.
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
