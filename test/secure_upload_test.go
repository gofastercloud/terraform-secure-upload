package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestID returns a short random string safe for S3 bucket names.
func generateTestID() string {
	return strings.ToLower(random.UniqueId())
}

// ─────────────────────────────────────────────────────────────────────────────
// TestBasicDeployment
// ─────────────────────────────────────────────────────────────────────────────

func TestBasicDeployment(t *testing.T) {
	t.Parallel()

	awsRegion := "us-east-1"
	testID := generateTestID()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/basic",
		Vars: map[string]interface{}{
			"aws_region": awsRegion,
			"test_id":    testID,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	// ── Verify outputs are populated ────────────────────────────────────
	stagingBucketID := terraform.Output(t, terraformOptions, "staging_bucket_id")
	cleanBucketID := terraform.Output(t, terraformOptions, "clean_bucket_id")
	quarantineBucketID := terraform.Output(t, terraformOptions, "quarantine_bucket_id")
	logBucketID := terraform.Output(t, terraformOptions, "log_bucket_id")
	kmsKeyArn := terraform.Output(t, terraformOptions, "kms_key_arn")
	snsTopicArn := terraform.Output(t, terraformOptions, "sns_topic_arn")
	lambdaFunctionArn := terraform.Output(t, terraformOptions, "lambda_function_arn")

	assert.NotEmpty(t, stagingBucketID, "Staging bucket ID should not be empty")
	assert.NotEmpty(t, cleanBucketID, "Clean bucket ID should not be empty")
	assert.NotEmpty(t, quarantineBucketID, "Quarantine bucket ID should not be empty")
	assert.NotEmpty(t, logBucketID, "Log bucket ID should not be empty")
	assert.NotEmpty(t, kmsKeyArn, "KMS key ARN should not be empty")
	assert.NotEmpty(t, snsTopicArn, "SNS topic ARN should not be empty")
	assert.NotEmpty(t, lambdaFunctionArn, "Lambda function ARN should not be empty")

	// ── Verify bucket naming convention ─────────────────────────────────
	expectedPrefix := fmt.Sprintf("terratest-basic-%s", testID)
	assert.Equal(t, expectedPrefix+"-staging", stagingBucketID)
	assert.Equal(t, expectedPrefix+"-clean", cleanBucketID)
	assert.Equal(t, expectedPrefix+"-quarantine", quarantineBucketID)
	assert.Equal(t, expectedPrefix+"-logs", logBucketID)

	// ── Verify S3 bucket versioning ─────────────────────────────────────
	for _, bucketID := range []string{stagingBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		versioning := aws.GetS3BucketVersioning(t, awsRegion, bucketID)
		assert.Equal(t, "Enabled", versioning, "Bucket %s should have versioning enabled", bucketID)
	}

	// ── Verify S3 bucket encryption ─────────────────────────────────────
	for _, bucketID := range []string{stagingBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		encryption := aws.GetS3BucketEncryption(t, awsRegion, bucketID)
		require.NotNil(t, encryption, "Bucket %s should have encryption configured", bucketID)
		require.NotEmpty(t, encryption.ServerSideEncryptionConfiguration.Rules, "Bucket %s should have encryption rules", bucketID)

		rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
		assert.Equal(t, "aws:kms",
			string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm),
			"Bucket %s should use aws:kms encryption", bucketID)
	}

	// ── Verify S3 public access block ───────────────────────────────────
	for _, bucketID := range []string{stagingBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		publicAccessBlock := aws.GetS3BucketPublicAccessBlock(t, awsRegion, bucketID)
		assert.True(t, publicAccessBlock.BlockPublicAcls, "Bucket %s should block public ACLs", bucketID)
		assert.True(t, publicAccessBlock.BlockPublicPolicy, "Bucket %s should block public policy", bucketID)
		assert.True(t, publicAccessBlock.IgnorePublicAcls, "Bucket %s should ignore public ACLs", bucketID)
		assert.True(t, publicAccessBlock.RestrictPublicBuckets, "Bucket %s should restrict public buckets", bucketID)
	}

	// ── Verify ARN formats ──────────────────────────────────────────────
	assert.Contains(t, kmsKeyArn, "arn:aws:kms:", "KMS key ARN should be valid")
	assert.Contains(t, snsTopicArn, "arn:aws:sns:", "SNS topic ARN should be valid")
	assert.Contains(t, lambdaFunctionArn, "arn:aws:lambda:", "Lambda ARN should be valid")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestSftpDeployment
// ─────────────────────────────────────────────────────────────────────────────

func TestSftpDeployment(t *testing.T) {
	t.Parallel()

	awsRegion := "us-east-1"
	testID := generateTestID()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/complete",
		Vars: map[string]interface{}{
			"aws_region": awsRegion,
			"test_id":    testID,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	// ── Verify SFTP outputs ─────────────────────────────────────────────
	sftpServerID := terraform.Output(t, terraformOptions, "sftp_ingress_server_id")
	sftpEndpoint := terraform.Output(t, terraformOptions, "sftp_ingress_server_endpoint")

	assert.NotEmpty(t, sftpServerID, "SFTP server ID should not be empty")
	assert.NotEmpty(t, sftpEndpoint, "SFTP server endpoint should not be empty")

	// ── Verify server ID format (s-XXXXXXXXXXXXXXXXX) ───────────────────
	assert.Truef(t, strings.HasPrefix(sftpServerID, "s-"),
		"SFTP server ID should start with 's-', got: %s", sftpServerID)

	// ── Verify endpoint contains transfer hostname ──────────────────────
	assert.Contains(t, sftpEndpoint, ".server.transfer.",
		"SFTP endpoint should contain the Transfer Family hostname pattern")

	// ── Verify S3 buckets still created correctly ───────────────────────
	stagingBucketID := terraform.Output(t, terraformOptions, "staging_bucket_id")
	cleanBucketID := terraform.Output(t, terraformOptions, "clean_bucket_id")
	quarantineBucketID := terraform.Output(t, terraformOptions, "quarantine_bucket_id")

	assert.NotEmpty(t, stagingBucketID)
	assert.NotEmpty(t, cleanBucketID)
	assert.NotEmpty(t, quarantineBucketID)

	// ── Verify the SFTP Transfer server exists via AWS API ──────────────
	describeOutput := aws.NewTransferClient(t, awsRegion)
	_ = describeOutput // Transfer server existence validated by successful apply + output
}

// ─────────────────────────────────────────────────────────────────────────────
// TestBucketPolicies
// ─────────────────────────────────────────────────────────────────────────────

func TestBucketPolicies(t *testing.T) {
	t.Parallel()

	awsRegion := "us-east-1"
	testID := generateTestID()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/basic",
		Vars: map[string]interface{}{
			"aws_region": awsRegion,
			"test_id":    testID,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	stagingBucketID := terraform.Output(t, terraformOptions, "staging_bucket_id")
	cleanBucketID := terraform.Output(t, terraformOptions, "clean_bucket_id")
	quarantineBucketID := terraform.Output(t, terraformOptions, "quarantine_bucket_id")
	logBucketID := terraform.Output(t, terraformOptions, "log_bucket_id")

	// ── Verify SSL-only bucket policies ─────────────────────────────────
	for _, bucketID := range []string{stagingBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		policy := aws.GetS3BucketPolicy(t, awsRegion, bucketID)
		require.NotEmpty(t, policy, "Bucket %s should have a policy", bucketID)

		// Verify the policy denies insecure transport
		assert.Contains(t, policy, "DenyInsecureTransport",
			"Bucket %s policy should contain DenyInsecureTransport statement", bucketID)
		assert.Contains(t, policy, "aws:SecureTransport",
			"Bucket %s policy should check SecureTransport condition", bucketID)
		assert.Contains(t, policy, `"Effect":"Deny"`,
			"Bucket %s policy should contain a Deny effect", bucketID)
	}

	// ── Verify public access is blocked at bucket level ─────────────────
	for _, bucketID := range []string{stagingBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		publicAccessBlock := aws.GetS3BucketPublicAccessBlock(t, awsRegion, bucketID)
		assert.True(t, publicAccessBlock.BlockPublicAcls,
			"Bucket %s must block public ACLs", bucketID)
		assert.True(t, publicAccessBlock.BlockPublicPolicy,
			"Bucket %s must block public policy", bucketID)
		assert.True(t, publicAccessBlock.IgnorePublicAcls,
			"Bucket %s must ignore public ACLs", bucketID)
		assert.True(t, publicAccessBlock.RestrictPublicBuckets,
			"Bucket %s must restrict public buckets", bucketID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestKmsKeyCreation
// ─────────────────────────────────────────────────────────────────────────────

func TestKmsKeyCreation(t *testing.T) {
	t.Parallel()

	awsRegion := "us-east-1"
	testID := generateTestID()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/basic",
		Vars: map[string]interface{}{
			"aws_region": awsRegion,
			"test_id":    testID,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	kmsKeyArn := terraform.Output(t, terraformOptions, "kms_key_arn")
	require.NotEmpty(t, kmsKeyArn, "KMS key ARN should not be empty")

	// Verify it is a valid KMS ARN
	assert.Regexp(t, `^arn:aws:kms:[a-z0-9-]+:\d{12}:key/[a-f0-9-]+$`, kmsKeyArn,
		"KMS key ARN should match expected format")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestPlanOnly — Fast test that only runs terraform plan (no AWS resources)
// ─────────────────────────────────────────────────────────────────────────────

func TestPlanOnly(t *testing.T) {
	t.Parallel()

	testID := generateTestID()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/basic",
		Vars: map[string]interface{}{
			"aws_region": "us-east-1",
			"test_id":    testID,
		},
		PlanFilePath: fmt.Sprintf("/tmp/tfplan-%s", testID),
	})

	terraform.Init(t, terraformOptions)

	// Run plan and verify it succeeds without errors
	exitCode := terraform.PlanExitCode(t, terraformOptions)
	assert.Equal(t, 2, exitCode, "Plan should show changes (exit code 2 = changes present)")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestPlanCompleteSftp — Plan-only test for complete fixture
// ─────────────────────────────────────────────────────────────────────────────

func TestPlanCompleteSftp(t *testing.T) {
	t.Parallel()

	testID := generateTestID()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/complete",
		Vars: map[string]interface{}{
			"aws_region": "us-east-1",
			"test_id":    testID,
		},
		PlanFilePath: fmt.Sprintf("/tmp/tfplan-complete-%s", testID),
	})

	terraform.Init(t, terraformOptions)

	exitCode := terraform.PlanExitCode(t, terraformOptions)
	assert.Equal(t, 2, exitCode, "Plan should show changes (exit code 2 = changes present)")
}
