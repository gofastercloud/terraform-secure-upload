package test

import "testing"

func setIntegrationConfigEnvironment(t *testing.T, keyARN string) {
	t.Helper()
	t.Setenv("RUN_AWS_INTEGRATION", "1")
	t.Setenv("AWS_REGION", "ap-southeast-2")
	t.Setenv("TEST_SFTP_VPC_ID", "vpc-0123456789abcdef0")
	t.Setenv("TEST_SFTP_SUBNET_IDS", "subnet-aaaaaaaa,subnet-bbbbbbbb")
	t.Setenv("TEST_SFTP_ALLOWED_CIDRS", "203.0.113.10/32")
	t.Setenv("TEST_KMS_KEY_ARN", keyARN)
}

func TestLoadFullIntegrationConfigAcceptsExistingKMSKey(t *testing.T) {
	keyARN := "arn:aws:kms:ap-southeast-2:819511250403:key/12345678-1234-1234-1234-123456789012"
	setIntegrationConfigEnvironment(t, keyARN)

	config, err := loadFullIntegrationConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.KMSKeyARN != keyARN {
		t.Fatalf("KMS key ARN = %q, want %q", config.KMSKeyARN, keyARN)
	}
}

func TestLoadFullIntegrationConfigRejectsKMSAlias(t *testing.T) {
	setIntegrationConfigEnvironment(t, "arn:aws:kms:ap-southeast-2:819511250403:alias/terratest")

	if _, err := loadFullIntegrationConfig(); err == nil {
		t.Fatal("expected an alias ARN to be rejected")
	}
}
