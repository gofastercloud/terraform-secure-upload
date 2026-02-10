TF_VERSION  ?= 1.9.8
TF_IMAGE    := hashicorp/terraform:$(TF_VERSION)
DOCKER_RUN  := docker run --rm -v "$(CURDIR):/workspace" -w /workspace $(TF_IMAGE)

.PHONY: fmt fmt-check init validate test test-validation test-all

## Format all .tf and .tftest.hcl files in place
fmt:
	$(DOCKER_RUN) fmt -recursive

## Check formatting (fails if any file needs changes — matches CI)
fmt-check:
	$(DOCKER_RUN) fmt -check -recursive -diff

## Initialise providers (no backend)
init:
	$(DOCKER_RUN) init -backend=false

## Run terraform validate (requires init first)
validate: init
	$(DOCKER_RUN) validate

## Run validation-only tests (no AWS credentials needed)
test-validation: init
	$(DOCKER_RUN) test -filter=tests/validation.tftest.hcl

## Run all tests (may require AWS credentials)
test-all: init
	$(DOCKER_RUN) test

## Run the same checks CI runs: fmt + validate + validation tests
test: fmt-check validate test-validation
