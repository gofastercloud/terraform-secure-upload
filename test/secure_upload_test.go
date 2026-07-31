package test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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
	ingressBucketID := terraform.Output(t, terraformOptions, "ingress_bucket_id")
	cleanBucketID := terraform.Output(t, terraformOptions, "clean_bucket_id")
	quarantineBucketID := terraform.Output(t, terraformOptions, "quarantine_bucket_id")
	logBucketID := terraform.Output(t, terraformOptions, "log_bucket_id")
	kmsKeyArn := terraform.Output(t, terraformOptions, "kms_key_arn")
	snsTopicArn := terraform.Output(t, terraformOptions, "sns_topic_arn")
	lambdaFunctionArn := terraform.Output(t, terraformOptions, "lambda_function_arn")

	assert.NotEmpty(t, ingressBucketID, "Ingress bucket ID should not be empty")
	assert.NotEmpty(t, cleanBucketID, "Clean bucket ID should not be empty")
	assert.NotEmpty(t, quarantineBucketID, "Quarantine bucket ID should not be empty")
	assert.NotEmpty(t, logBucketID, "Log bucket ID should not be empty")
	assert.NotEmpty(t, kmsKeyArn, "KMS key ARN should not be empty")
	assert.NotEmpty(t, snsTopicArn, "SNS topic ARN should not be empty")
	assert.NotEmpty(t, lambdaFunctionArn, "Lambda function ARN should not be empty")

	// ── Verify bucket naming convention ─────────────────────────────────
	expectedPrefix := fmt.Sprintf("terratest-basic-%s", testID)
	assert.Equal(t, expectedPrefix+"-ingress", ingressBucketID)
	assert.Equal(t, expectedPrefix+"-clean", cleanBucketID)
	assert.Equal(t, expectedPrefix+"-quarantine", quarantineBucketID)
	assert.Equal(t, expectedPrefix+"-logs", logBucketID)

	// ── Verify S3 bucket encryption ─────────────────────────────────────
	for _, bucketID := range []string{ingressBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		encryption := getS3BucketEncryption(t, awsRegion, bucketID)
		require.NotNil(t, encryption, "Bucket %s should have encryption configured", bucketID)
		require.NotEmpty(t, encryption.ServerSideEncryptionConfiguration.Rules, "Bucket %s should have encryption rules", bucketID)

		rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
		assert.Equal(t, "aws:kms",
			sdkaws.StringValue(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm),
			"Bucket %s should use aws:kms encryption", bucketID)
	}

	// ── Verify S3 public access block ───────────────────────────────────
	for _, bucketID := range []string{ingressBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		publicAccessBlock := getS3BucketPublicAccessBlock(t, awsRegion, bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.BlockPublicAcls), "Bucket %s should block public ACLs", bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.BlockPublicPolicy), "Bucket %s should block public policy", bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.IgnorePublicAcls), "Bucket %s should ignore public ACLs", bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.RestrictPublicBuckets), "Bucket %s should restrict public buckets", bucketID)
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
	t.Skip("requires caller-supplied VPC subnets and Elastic IP allocation IDs")

	sftpServerID := terraform.Output(t, terraformOptions, "sftp_server_id")
	sftpEndpoint := terraform.Output(t, terraformOptions, "sftp_server_endpoint")

	assert.NotEmpty(t, sftpServerID, "SFTP server ID should not be empty")
	assert.NotEmpty(t, sftpEndpoint, "SFTP server endpoint should not be empty")

	// ── Verify server ID format (s-XXXXXXXXXXXXXXXXX) ───────────────────
	assert.Truef(t, strings.HasPrefix(sftpServerID, "s-"),
		"SFTP server ID should start with 's-', got: %s", sftpServerID)

	// ── Verify endpoint contains transfer hostname ──────────────────────
	assert.Contains(t, sftpEndpoint, ".server.transfer.",
		"SFTP endpoint should contain the Transfer Family hostname pattern")

	// ── Verify S3 buckets still created correctly ───────────────────────
	ingressBucketID := terraform.Output(t, terraformOptions, "ingress_bucket_id")
	cleanBucketID := terraform.Output(t, terraformOptions, "clean_bucket_id")
	quarantineBucketID := terraform.Output(t, terraformOptions, "quarantine_bucket_id")

	assert.NotEmpty(t, ingressBucketID)
	assert.NotEmpty(t, cleanBucketID)
	assert.NotEmpty(t, quarantineBucketID)

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

	ingressBucketID := terraform.Output(t, terraformOptions, "ingress_bucket_id")
	cleanBucketID := terraform.Output(t, terraformOptions, "clean_bucket_id")
	quarantineBucketID := terraform.Output(t, terraformOptions, "quarantine_bucket_id")
	logBucketID := terraform.Output(t, terraformOptions, "log_bucket_id")

	// ── Verify SSL-only bucket policies ─────────────────────────────────
	for _, bucketID := range []string{ingressBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		policy := getS3BucketPolicy(t, awsRegion, bucketID)
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
	for _, bucketID := range []string{ingressBucketID, cleanBucketID, quarantineBucketID, logBucketID} {
		publicAccessBlock := getS3BucketPublicAccessBlock(t, awsRegion, bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.BlockPublicAcls),
			"Bucket %s must block public ACLs", bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.BlockPublicPolicy),
			"Bucket %s must block public policy", bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.IgnorePublicAcls),
			"Bucket %s must ignore public ACLs", bucketID)
		assert.True(t, sdkaws.BoolValue(publicAccessBlock.RestrictPublicBuckets),
			"Bucket %s must restrict public buckets", bucketID)
	}
}

func testS3Client(t *testing.T, region string) *s3.S3 {
	t.Helper()
	sess, err := session.NewSession(&sdkaws.Config{Region: sdkaws.String(region)})
	require.NoError(t, err)
	return s3.New(sess)
}

func getS3BucketEncryption(t *testing.T, region, bucket string) *s3.GetBucketEncryptionOutput {
	t.Helper()
	output, err := testS3Client(t, region).GetBucketEncryption(&s3.GetBucketEncryptionInput{Bucket: sdkaws.String(bucket)})
	require.NoError(t, err)
	return output
}

func getS3BucketPublicAccessBlock(t *testing.T, region, bucket string) *s3.PublicAccessBlockConfiguration {
	t.Helper()
	output, err := testS3Client(t, region).GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{Bucket: sdkaws.String(bucket)})
	require.NoError(t, err)
	return output.PublicAccessBlockConfiguration
}

func getS3BucketPolicy(t *testing.T, region, bucket string) string {
	t.Helper()
	output, err := testS3Client(t, region).GetBucketPolicy(&s3.GetBucketPolicyInput{Bucket: sdkaws.String(bucket)})
	require.NoError(t, err)
	policy, err := url.QueryUnescape(sdkaws.StringValue(output.Policy))
	require.NoError(t, err)
	return policy
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
