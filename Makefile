TF_VERSION  ?= 1.9.8
TF_IMAGE    := hashicorp/terraform:$(TF_VERSION)
DOCKER_RUN  := docker run --rm -v "$(CURDIR):/workspace" -w /workspace $(TF_IMAGE)

.PHONY: fmt fmt-check init validate test test-validation test-all build-scanner push-scanner

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

## Build the prompt injection scanner Docker image locally
build-scanner:
	docker build --platform linux/amd64 \
		-t prompt-injection-scanner:latest \
		functions/prompt_injection_scanner/

## Push the scanner image to ECR (requires ECR_REPO_URL env var)
push-scanner:
	@test -n "$(ECR_REPO_URL)" || (echo "ERROR: set ECR_REPO_URL" && exit 1)
	aws ecr get-login-password --region $$(aws configure get region) | \
		docker login --username AWS --password-stdin $(ECR_REPO_URL)
	docker tag prompt-injection-scanner:latest $(ECR_REPO_URL):latest
	docker push $(ECR_REPO_URL):latest

## Run the same checks CI runs: fmt + validate + validation tests
test: fmt-check validate test-validation
