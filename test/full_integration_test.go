package test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/transfer"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

const eicarTestString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

type fullIntegrationConfig struct {
	Region           string
	TestID           string
	KMSKeyARN        string
	VPCID            string
	SubnetIDs        []string
	EIPAllocationIDs []string
	AllowedCIDRs     []string
	CustomHostname   string
	Route53ZoneID    string
}

type integrationUser struct {
	Name       string
	Prefix     string
	PrivateKey string
	PublicKey  string
}

type integrationReport struct {
	Started time.Time
	Entries []reportEntry
}

type reportEntry struct {
	Name     string
	Status   string
	Detail   string
	Duration time.Duration
}

type notificationMonitor struct {
	snsClient       *sns.SNS
	sqsClient       *sqs.SQS
	queueURL        string
	subscriptionARN string
}

func TestFullIntegration(t *testing.T) {
	report := &integrationReport{Started: time.Now()}
	defer report.print()

	config, err := loadFullIntegrationConfig()
	if errors.Is(err, errIntegrationDisabled) {
		report.add("preflight", "SKIP", "set RUN_AWS_INTEGRATION=1 to run the deploy-and-exercise harness", 0)
		t.Skip(err)
	}
	if err != nil {
		report.add("preflight", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}

	if _, err := exec.LookPath("terraform"); err != nil {
		report.add("preflight", "FAIL", "terraform is required on PATH", 0)
		t.Fatal(err)
	}
	for _, binary := range []string{"ssh-keygen", "sftp"} {
		if _, err := exec.LookPath(binary); err != nil {
			report.add("preflight", "FAIL", binary+" is required on PATH", 0)
			t.Fatal(err)
		}
	}
	report.add("preflight", "PASS", "integration prerequisites are available", 0)

	ctx := context.Background()
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            aws.Config{Region: aws.String(config.Region)},
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		report.add("aws-session", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}

	identity, err := sts.New(sess).GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		report.add("aws-credentials", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}
	report.add("aws-credentials", "PASS", fmt.Sprintf("account %s", aws.StringValue(identity.Account)), 0)

	users, keyDir, err := generateIntegrationUsers()
	if err != nil {
		report.add("ssh-users", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}
	defer os.RemoveAll(keyDir)
	report.add("ssh-users", "PASS", "generated Alice and Bob Ed25519 key pairs", 0)

	resources := integrationResources{}
	monitor := (*notificationMonitor)(nil)
	var terraformOptions *terraform.Options
	var kmsKey, kmsAlias string
	var kmsKeyOwned bool
	var allocatedEIPs []string
	defer func() {
		cleanupIntegration(t, report, terraformOptions, resources, monitor, kmsKey, kmsAlias, kmsKeyOwned, allocatedEIPs, sess)
	}()

	if config.KMSKeyARN != "" {
		kmsKey = config.KMSKeyARN
		if err := validateIntegrationKMSKey(ctx, kms.New(sess), kmsKey, config.Region, aws.StringValue(identity.Account)); err != nil {
			report.add("test-kms-key", "FAIL", err.Error(), 0)
			t.Fatal(err)
		}
		report.add("test-kms-key", "PASS", "reusing existing KMS key "+kmsKey, 0)
	} else {
		kmsKey, kmsAlias, err = createIntegrationKMSKey(ctx, kms.New(sess), config.Region, aws.StringValue(identity.Account), config.TestID)
		if err != nil {
			report.add("test-kms-key", "FAIL", err.Error(), 0)
			t.Fatal(err)
		}
		kmsKeyOwned = true
		report.add("test-kms-key", "PASS", kmsKey, 0)
	}

	config.EIPAllocationIDs, allocatedEIPs, err = ensureIntegrationEIPs(ctx, ec2.New(sess), config)
	if err != nil {
		report.add("test-eips", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}
	if len(allocatedEIPs) > 0 {
		report.add("test-eips", "PASS", fmt.Sprintf("allocated %d tagged temporary Elastic IPs", len(allocatedEIPs)), 0)
	} else {
		report.add("test-eips", "PASS", "using caller-supplied Elastic IP allocations", 0)
	}

	terraformOptions = terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./fixtures/full",
		Vars: map[string]interface{}{
			"aws_region":                  config.Region,
			"test_id":                     config.TestID,
			"kms_key_arn":                 kmsKey,
			"sftp_vpc_id":                 config.VPCID,
			"sftp_subnet_ids":             config.SubnetIDs,
			"sftp_address_allocation_ids": config.EIPAllocationIDs,
			"sftp_allowed_cidrs":          config.AllowedCIDRs,
			"sftp_users_json":             mustJSONUsers(t, users),
		},
	})
	if config.CustomHostname != "" {
		terraformOptions.Vars["sftp_custom_hostname"] = config.CustomHostname
	}
	if config.Route53ZoneID != "" {
		terraformOptions.Vars["sftp_route53_hosted_zone_id"] = config.Route53ZoneID
	}

	applyStart := time.Now()
	if _, err := terraform.InitAndApplyE(t, terraformOptions); err != nil {
		report.add("terraform-apply", "FAIL", err.Error(), time.Since(applyStart))
		t.Fatal(err)
	}
	report.add("terraform-apply", "PASS", "S3 and SFTP resources deployed", time.Since(applyStart))

	resources, err = readIntegrationResources(t, terraformOptions)
	if err != nil {
		report.add("terraform-outputs", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}
	report.add("terraform-outputs", "PASS", fmt.Sprintf("server %s at %s", resources.ServerID, resources.Hostname), 0)

	transferClient := newTransferClient(sess)
	if err := waitForTransferOnline(ctx, transferClient, resources.ServerID, 10*time.Minute); err != nil {
		report.add("transfer-online", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}
	report.add("transfer-online", "PASS", "Transfer Family server is ONLINE", 0)

	monitor, err = newNotificationMonitor(ctx, sess, resources.SNSTopicARN, "terratest-"+config.TestID)
	if err != nil {
		report.add("sns-monitor", "FAIL", err.Error(), 0)
		t.Fatal(err)
	}
	report.add("sns-monitor", "PASS", "temporary SQS subscription attached to the instance SNS topic", 0)

	s3Client := s3.New(sess)
	logsClient := cloudwatchlogs.New(sess)

	if err := runS3CleanAndDirtyChecks(ctx, report, s3Client, monitor, resources, users[0]); err != nil {
		t.Fatal(err)
	}
	if err := runSFTPChecks(ctx, report, s3Client, monitor, resources, users, keyDir); err != nil {
		t.Fatal(err)
	}
	if err := runCloudWatchChecks(ctx, report, logsClient, resources, time.Now().Add(-15*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

type integrationResources struct {
	IngressBucket    string
	CleanBucket      string
	QuarantineBucket string
	SNSTopicARN      string
	LambdaARN        string
	ServerID         string
	ServerEndpoint   string
	Hostname         string
}

func readIntegrationResources(t *testing.T, options *terraform.Options) (integrationResources, error) {
	output := func(name string) (string, error) {
		return terraform.OutputE(t, options, name)
	}
	var result integrationResources
	var err error
	if result.IngressBucket, err = output("ingress_bucket_id"); err != nil {
		return result, err
	}
	if result.CleanBucket, err = output("clean_bucket_id"); err != nil {
		return result, err
	}
	if result.QuarantineBucket, err = output("quarantine_bucket_id"); err != nil {
		return result, err
	}
	if result.SNSTopicARN, err = output("sns_topic_arn"); err != nil {
		return result, err
	}
	if result.LambdaARN, err = output("lambda_function_arn"); err != nil {
		return result, err
	}
	if result.ServerID, err = output("sftp_server_id"); err != nil {
		return result, err
	}
	if result.ServerEndpoint, err = output("sftp_server_endpoint"); err != nil {
		return result, err
	}
	if result.Hostname, err = output("sftp_hostname"); err != nil {
		return result, err
	}
	return result, nil
}

func runS3CleanAndDirtyChecks(ctx context.Context, report *integrationReport, client *s3.S3, monitor *notificationMonitor, resources integrationResources, user integrationUser) error {
	cleanKey := user.Prefix + "direct-clean.txt"
	dirtyKey := user.Prefix + "direct-eicar.txt"

	if err := report.step("s3-clean-upload", func() error {
		return putObject(ctx, client, resources.IngressBucket, cleanKey, "clean integration payload\n")
	}); err != nil {
		return err
	}
	if err := waitForRoute(ctx, client, resources.IngressBucket, resources.CleanBucket, cleanKey, 10*time.Minute); err != nil {
		report.add("s3-clean-routing", "FAIL", err.Error(), 0)
		return err
	}
	report.add("s3-clean-routing", "PASS", "clean object reached the clean bucket", 0)
	if _, err := monitor.waitFor(ctx, func(message map[string]interface{}) bool {
		return messageString(message, "file_key") == cleanKey && messageString(message, "scan_result_status") == "NO_THREATS_FOUND"
	}); err != nil {
		report.add("sns-clean-notification", "FAIL", err.Error(), 0)
		return err
	}
	report.add("sns-clean-notification", "PASS", "clean scan result received", 0)

	if err := report.step("s3-dirty-upload", func() error {
		return putObject(ctx, client, resources.IngressBucket, dirtyKey, eicarTestString)
	}); err != nil {
		return err
	}
	if err := waitForRoute(ctx, client, resources.IngressBucket, resources.QuarantineBucket, dirtyKey, 10*time.Minute); err != nil {
		report.add("s3-dirty-routing", "FAIL", err.Error(), 0)
		return err
	}
	report.add("s3-dirty-routing", "PASS", "EICAR-style object reached quarantine", 0)
	if _, err := monitor.waitFor(ctx, func(message map[string]interface{}) bool {
		return messageString(message, "file_key") == dirtyKey && messageString(message, "scan_result_status") != "NO_THREATS_FOUND"
	}); err != nil {
		report.add("sns-dirty-notification", "FAIL", err.Error(), 0)
		return err
	}
	report.add("sns-dirty-notification", "PASS", "dirty scan result received", 0)
	return nil
}

func runSFTPChecks(ctx context.Context, report *integrationReport, client *s3.S3, monitor *notificationMonitor, resources integrationResources, users []integrationUser, keyDir string) error {
	alice, bob := users[0], users[1]

	if err := report.step("sftp-alice-common-commands", func() error {
		_, err := runSFTPBatch(ctx, resources.Hostname, alice.Name, alice.PrivateKey, []string{
			"pwd",
			"ls -la",
			"mkdir command-smoke",
			"ls -la",
			"rmdir command-smoke",
		})
		return err
	}); err != nil {
		return err
	}

	if err := report.step("sftp-bob-home-isolation", func() error {
		_, err := runSFTPBatch(ctx, resources.Hostname, bob.Name, bob.PrivateKey, []string{"pwd", "ls -la"})
		return err
	}); err != nil {
		return err
	}

	cleanLocal := filepath.Join(keyDir, "sftp-clean.txt")
	if err := os.WriteFile(cleanLocal, []byte("clean SFTP integration payload\n"), 0600); err != nil {
		return err
	}
	cleanKey := alice.Prefix + "sftp-clean.txt"
	if err := report.step("sftp-clean-upload", func() error {
		_, err := runSFTPBatch(ctx, resources.Hostname, alice.Name, alice.PrivateKey, []string{
			fmt.Sprintf("put %s sftp-clean.txt", cleanLocal),
		})
		return err
	}); err != nil {
		return err
	}
	if err := waitForRoute(ctx, client, resources.IngressBucket, resources.CleanBucket, cleanKey, 10*time.Minute); err != nil {
		report.add("sftp-clean-routing", "FAIL", err.Error(), 0)
		return err
	}
	report.add("sftp-clean-routing", "PASS", "SFTP clean object reached the clean bucket", 0)
	if _, err := monitor.waitFor(ctx, func(message map[string]interface{}) bool {
		return messageString(message, "file_key") == cleanKey && messageString(message, "scan_result_status") == "NO_THREATS_FOUND"
	}); err != nil {
		return err
	}
	report.add("sns-sftp-clean-notification", "PASS", "SFTP clean scan result received", 0)

	dirtyLocal := filepath.Join(keyDir, "sftp-eicar.txt")
	if err := os.WriteFile(dirtyLocal, []byte(eicarTestString), 0600); err != nil {
		return err
	}
	dirtyKey := alice.Prefix + "sftp-eicar.txt"
	if err := report.step("sftp-dirty-upload", func() error {
		_, err := runSFTPBatch(ctx, resources.Hostname, alice.Name, alice.PrivateKey, []string{
			fmt.Sprintf("put %s sftp-eicar.txt", dirtyLocal),
		})
		return err
	}); err != nil {
		return err
	}
	if err := waitForRoute(ctx, client, resources.IngressBucket, resources.QuarantineBucket, dirtyKey, 10*time.Minute); err != nil {
		report.add("sftp-dirty-routing", "FAIL", err.Error(), 0)
		return err
	}
	report.add("sftp-dirty-routing", "PASS", "SFTP EICAR-style object reached quarantine", 0)
	if _, err := monitor.waitFor(ctx, func(message map[string]interface{}) bool {
		return messageString(message, "file_key") == dirtyKey && messageString(message, "scan_result_status") != "NO_THREATS_FOUND"
	}); err != nil {
		return err
	}
	report.add("sns-sftp-dirty-notification", "PASS", "SFTP dirty scan result received", 0)

	for _, direction := range []struct {
		source integrationUser
		target integrationUser
	}{
		{source: alice, target: bob},
		{source: bob, target: alice},
	} {
		operations := []struct {
			name string
			cmd  string
		}{
			{"list", fmt.Sprintf("ls ../%s", direction.target.Prefix)},
			{"get", fmt.Sprintf("get ../%ssecret.txt %s", direction.target.Prefix, filepath.Join(keyDir, "forbidden.txt"))},
			{"put", fmt.Sprintf("put %s ../%sforbidden.txt", dirtyLocal, direction.target.Prefix)},
			{"remove", fmt.Sprintf("rm ../%ssecret.txt", direction.target.Prefix)},
		}
		for _, operation := range operations {
			name := fmt.Sprintf("sftp-isolation-%s-to-%s-%s", direction.source.Name, direction.target.Name, operation.name)
			if err := report.step(name, func() error {
				_, err := runSFTPBatch(ctx, resources.Hostname, direction.source.Name, direction.source.PrivateKey, []string{operation.cmd})
				if operation.name == "put" && err == nil {
					foundIn, checkErr := findObjectInBuckets(ctx, client, []string{
						resources.IngressBucket,
						resources.CleanBucket,
						resources.QuarantineBucket,
					}, direction.target.Prefix+"forbidden.txt")
					if checkErr != nil {
						return checkErr
					}
					if foundIn != "" {
						return fmt.Errorf("%s wrote outside its logical home to %s in %s", direction.source.Name, direction.target.Prefix+"forbidden.txt", foundIn)
					}
					return nil
				}
				if err == nil {
					return fmt.Errorf("%s unexpectedly succeeded with %q", direction.source.Name, operation.cmd)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}

	for _, user := range users {
		name := "sftp-empty-home-relogin-" + user.Name
		if err := report.step(name, func() error {
			if err := waitForPrefixEmpty(ctx, client, resources.IngressBucket, user.Prefix, 10*time.Minute); err != nil {
				return err
			}
			_, err := runSFTPBatch(ctx, resources.Hostname, user.Name, user.PrivateKey, []string{"pwd", "ls -la"})
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

func runCloudWatchChecks(ctx context.Context, report *integrationReport, client *cloudwatchlogs.CloudWatchLogs, resources integrationResources, start time.Time) error {
	functionName := resources.LambdaARN[strings.LastIndex(resources.LambdaARN, ":")+1:]
	lambdaGroup := "/aws/lambda/" + functionName
	events, err := waitForLogEvents(ctx, client, lambdaGroup, "Routing scan result", start, 10*time.Minute)
	if err != nil {
		report.add("cloudwatch-lambda", "FAIL", err.Error(), 0)
		return err
	}
	report.add("cloudwatch-lambda", "PASS", fmt.Sprintf("observed %d scan-router log events", len(events)), 0)

	transferGroup, err := findTransferLogGroup(ctx, client, resources.ServerID, 2*time.Minute)
	if err != nil {
		report.add("cloudwatch-transfer", "WARN", err.Error(), 0)
		return nil
	}
	transferEvents, err := waitForLogEvents(ctx, client, transferGroup, "", start, 2*time.Minute)
	if err != nil {
		report.add("cloudwatch-transfer", "WARN", err.Error(), 0)
		return nil
	}
	report.add("cloudwatch-transfer", "PASS", fmt.Sprintf("observed %d Transfer Family log events", len(transferEvents)), 0)
	return nil
}

func (r *integrationReport) step(name string, action func() error) error {
	started := time.Now()
	if err := action(); err != nil {
		r.add(name, "FAIL", err.Error(), time.Since(started))
		return err
	}
	r.add(name, "PASS", "completed", time.Since(started))
	return nil
}

func (r *integrationReport) add(name, status, detail string, duration time.Duration) {
	r.Entries = append(r.Entries, reportEntry{Name: name, Status: status, Detail: detail, Duration: duration})
}

func (r *integrationReport) print() {
	fmt.Println("\n=== Secure upload full integration report ===")
	fmt.Printf("started: %s\n", r.Started.Format(time.RFC3339))
	fmt.Printf("finished: %s\n", time.Now().Format(time.RFC3339))
	fmt.Println("------------------------------------------------------------")
	for _, entry := range r.Entries {
		fmt.Printf("%-34s %-5s %s", entry.Name, entry.Status, entry.Detail)
		if entry.Duration > 0 {
			fmt.Printf(" (%s)", entry.Duration.Round(time.Second))
		}
		fmt.Println()
	}
	fmt.Println("------------------------------------------------------------")
	counts := map[string]int{}
	for _, entry := range r.Entries {
		counts[entry.Status]++
	}
	overall := "PASS"
	if counts["FAIL"] > 0 {
		overall = "FAIL"
	} else if counts["WARN"] > 0 {
		overall = "WARN"
	} else if counts["SKIP"] > 0 {
		overall = "SKIP"
	}
	fmt.Printf("overall: %s (PASS=%d FAIL=%d WARN=%d SKIP=%d)\n", overall, counts["PASS"], counts["FAIL"], counts["WARN"], counts["SKIP"])
}

var errIntegrationDisabled = errors.New("full AWS integration test disabled")

func loadFullIntegrationConfig() (fullIntegrationConfig, error) {
	if value := strings.ToLower(os.Getenv("RUN_AWS_INTEGRATION")); value != "1" && value != "true" {
		return fullIntegrationConfig{}, errIntegrationDisabled
	}
	value := func(name string) (string, error) {
		if result := strings.TrimSpace(os.Getenv(name)); result != "" {
			return result, nil
		}
		return "", fmt.Errorf("%s is required", name)
	}
	csv := func(name string) ([]string, error) {
		value, err := value(name)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(value, ",")
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
			if parts[index] == "" {
				return nil, fmt.Errorf("%s contains an empty value", name)
			}
		}
		return parts, nil
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	kmsKeyARN := strings.TrimSpace(os.Getenv("TEST_KMS_KEY_ARN"))
	if kmsKeyARN != "" {
		parts := strings.Split(kmsKeyARN, ":")
		if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || !strings.HasPrefix(parts[5], "key/") {
			return fullIntegrationConfig{}, fmt.Errorf("TEST_KMS_KEY_ARN must be a full KMS key ARN, not an alias ARN")
		}
	}
	vpcID, err := value("TEST_SFTP_VPC_ID")
	if err != nil {
		return fullIntegrationConfig{}, err
	}
	subnets, err := csv("TEST_SFTP_SUBNET_IDS")
	if err != nil {
		return fullIntegrationConfig{}, err
	}
	var eips []string
	if value := strings.TrimSpace(os.Getenv("TEST_SFTP_EIP_ALLOCATION_IDS")); value != "" {
		eips = strings.Split(value, ",")
		for index := range eips {
			eips[index] = strings.TrimSpace(eips[index])
			if eips[index] == "" {
				return fullIntegrationConfig{}, fmt.Errorf("TEST_SFTP_EIP_ALLOCATION_IDS contains an empty value")
			}
		}
	}
	cidrs, err := csv("TEST_SFTP_ALLOWED_CIDRS")
	if err != nil {
		return fullIntegrationConfig{}, err
	}
	if len(eips) > 0 && len(subnets) != len(eips) {
		return fullIntegrationConfig{}, fmt.Errorf("TEST_SFTP_SUBNET_IDS and TEST_SFTP_EIP_ALLOCATION_IDS must have equal lengths")
	}
	testID := strings.ToLower(generateTestID())
	return fullIntegrationConfig{
		Region:           region,
		TestID:           testID,
		KMSKeyARN:        kmsKeyARN,
		VPCID:            vpcID,
		SubnetIDs:        subnets,
		EIPAllocationIDs: eips,
		AllowedCIDRs:     cidrs,
		CustomHostname:   strings.TrimSpace(os.Getenv("TEST_SFTP_CUSTOM_HOSTNAME")),
		Route53ZoneID:    strings.TrimSpace(os.Getenv("TEST_SFTP_ROUTE53_HOSTED_ZONE_ID")),
	}, nil
}

func generateIntegrationUsers() ([]integrationUser, string, error) {
	directory, err := os.MkdirTemp("", "secure-upload-sftp-")
	if err != nil {
		return nil, "", err
	}
	users := []integrationUser{
		{Name: "alice", Prefix: "uploads/alice/"},
		{Name: "bob", Prefix: "uploads/bob/"},
	}
	for index := range users {
		privateKey := filepath.Join(directory, users[index].Name)
		command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", privateKey)
		if output, err := command.CombinedOutput(); err != nil {
			return nil, directory, fmt.Errorf("generate %s key: %w: %s", users[index].Name, err, output)
		}
		publicKey, err := os.ReadFile(privateKey + ".pub")
		if err != nil {
			return nil, directory, err
		}
		users[index].PrivateKey = privateKey
		users[index].PublicKey = strings.TrimSpace(string(publicKey))
	}
	return users, directory, nil
}

func mustJSONUsers(t *testing.T, users []integrationUser) string {
	t.Helper()
	values := make([]map[string]string, 0, len(users))
	for _, user := range users {
		values = append(values, map[string]string{
			"username":              user.Name,
			"ssh_public_key":        user.PublicKey,
			"home_directory_prefix": "/" + user.Prefix,
		})
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func validateIntegrationKMSKey(ctx context.Context, client *kms.KMS, keyARN, region, account string) error {
	parts := strings.Split(keyARN, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || parts[3] != region || parts[4] != account || !strings.HasPrefix(parts[5], "key/") {
		return fmt.Errorf("TEST_KMS_KEY_ARN must be a full KMS key ARN in account %s and Region %s", account, region)
	}

	described, err := client.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return fmt.Errorf("describe existing KMS key: %w", err)
	}
	if described.KeyMetadata == nil || aws.StringValue(described.KeyMetadata.Arn) != keyARN {
		return fmt.Errorf("existing KMS key ARN did not resolve to %s", keyARN)
	}
	if aws.StringValue(described.KeyMetadata.KeyState) != kms.KeyStateEnabled {
		return fmt.Errorf("existing KMS key %s is not enabled", keyARN)
	}
	return nil
}

func createIntegrationKMSKey(ctx context.Context, client *kms.KMS, region, account, testID string) (string, string, error) {
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{
				"Sid": "AllowAccountManagement", "Effect": "Allow",
				"Principal": map[string]string{"AWS": "arn:aws:iam::" + account + ":root"},
				"Action":    "kms:*", "Resource": "*",
			},
			map[string]interface{}{
				"Sid": "AllowSecureUploadServices", "Effect": "Allow",
				"Principal": map[string]interface{}{"Service": []string{"events.amazonaws.com", "guardduty.amazonaws.com", "lambda.amazonaws.com", "s3.amazonaws.com", "sns.amazonaws.com", "sqs.amazonaws.com", "transfer.amazonaws.com"}},
				"Action":    []string{"kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"}, "Resource": "*",
				"Condition": map[string]interface{}{"StringEquals": map[string]string{"aws:SourceAccount": account}},
			},
			map[string]interface{}{
				"Sid": "AllowCloudWatchLogs", "Effect": "Allow",
				"Principal": map[string]string{"Service": "logs." + region + ".amazonaws.com"},
				"Action":    []string{"kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"}, "Resource": "*",
				"Condition": map[string]interface{}{"ArnLike": map[string]string{"kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:" + region + ":" + account + ":log-group:*"}},
			},
		},
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return "", "", err
	}
	created, err := client.CreateKeyWithContext(ctx, &kms.CreateKeyInput{
		Description: aws.String("Temporary full integration test key " + testID),
		Policy:      aws.String(string(policyJSON)),
		KeyUsage:    aws.String("ENCRYPT_DECRYPT"),
		Tags:        []*kms.Tag{{TagKey: aws.String("ManagedBy"), TagValue: aws.String("terratest")}, {TagKey: aws.String("Module"), TagValue: aws.String("terraform-secure-upload")}, {TagKey: aws.String("TestID"), TagValue: aws.String(testID)}},
	})
	if err != nil {
		return "", "", err
	}
	keyID := aws.StringValue(created.KeyMetadata.KeyId)
	alias := "alias/terratest-full-" + testID
	if _, err := client.CreateAliasWithContext(ctx, &kms.CreateAliasInput{AliasName: aws.String(alias), TargetKeyId: aws.String(keyID)}); err != nil {
		_, _ = client.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(keyID), PendingWindowInDays: aws.Int64(7)})
		return "", "", err
	}
	return aws.StringValue(created.KeyMetadata.Arn), alias, nil
}

func putObject(ctx context.Context, client *s3.S3, bucket, key, body string) error {
	_, err := client.PutObjectWithContext(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader(body), ContentType: aws.String("text/plain")})
	return err
}

func findObjectInBuckets(ctx context.Context, client *s3.S3, buckets []string, key string) (string, error) {
	for _, bucket := range buckets {
		_, err := client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		if err == nil {
			return bucket, nil
		}
		var awsError awserr.Error
		if errors.As(err, &awsError) && (awsError.Code() == "NotFound" || awsError.Code() == "NoSuchKey") {
			continue
		}
		return "", err
	}
	return "", nil
}

func waitForRoute(ctx context.Context, client *s3.S3, sourceBucket, destinationBucket, key string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{Bucket: aws.String(destinationBucket), Key: aws.String(key)}); err == nil {
			_, sourceErr := client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{Bucket: aws.String(sourceBucket), Key: aws.String(key)})
			if sourceErr != nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	return fmt.Errorf("object %s was not routed from %s to %s within %s", key, sourceBucket, destinationBucket, timeout)
}

func waitForPrefixEmpty(ctx context.Context, client *s3.S3, bucket, prefix string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := client.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
			Bucket:  aws.String(bucket),
			Prefix:  aws.String(prefix),
			MaxKeys: aws.Int64(1),
		})
		if err != nil {
			return err
		}
		if len(output.Contents) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	return fmt.Errorf("S3 prefix s3://%s/%s was not empty within %s", bucket, prefix, timeout)
}

func runSFTPBatch(ctx context.Context, host, user, privateKey string, commands []string) (string, error) {
	batchFile, err := os.CreateTemp("", "secure-upload-sftp-batch-")
	if err != nil {
		return "", err
	}
	defer os.Remove(batchFile.Name())
	if _, err := batchFile.WriteString(strings.Join(commands, "\n") + "\n"); err != nil {
		_ = batchFile.Close()
		return "", err
	}
	if err := batchFile.Close(); err != nil {
		return "", err
	}
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=30",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-i", privateKey,
		"-b", batchFile.Name(),
		user + "@" + host,
	}
	command := exec.CommandContext(ctx, "sftp", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("sftp batch failed: %w: %s", err, output)
	}
	return string(output), nil
}

func cleanupIntegration(t *testing.T, report *integrationReport, options *terraform.Options, resources integrationResources, monitor *notificationMonitor, kmsKey, kmsAlias string, kmsKeyOwned bool, allocatedEIPs []string, sess *session.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if monitor != nil {
		if err := monitor.cleanup(ctx); err != nil {
			report.add("cleanup-sns-monitor", "FAIL", err.Error(), 0)
		} else {
			report.add("cleanup-sns-monitor", "PASS", "temporary subscription and queue deleted", 0)
		}
	}

	s3Client := s3.New(sess)
	for name, bucket := range map[string]string{
		"cleanup-ingress":    resources.IngressBucket,
		"cleanup-clean":      resources.CleanBucket,
		"cleanup-quarantine": resources.QuarantineBucket,
	} {
		if bucket == "" {
			continue
		}
		if err := purgeBucket(ctx, s3Client, bucket); err != nil {
			report.add(name, "FAIL", err.Error(), 0)
		} else {
			report.add(name, "PASS", "all objects and delete markers deleted", 0)
		}
	}

	if options != nil {
		if _, err := terraform.DestroyE(t, options); err != nil {
			report.add("terraform-destroy", "FAIL", err.Error(), 0)
		} else {
			report.add("terraform-destroy", "PASS", "Terraform-managed resources destroyed", 0)
		}
	}

	kmsClient := kms.New(sess)
	if kmsKeyOwned && kmsAlias != "" {
		if _, err := kmsClient.DeleteAliasWithContext(ctx, &kms.DeleteAliasInput{AliasName: aws.String(kmsAlias)}); err != nil {
			report.add("cleanup-kms-alias", "FAIL", err.Error(), 0)
		} else {
			report.add("cleanup-kms-alias", "PASS", "temporary KMS alias deleted", 0)
		}
	}
	if kmsKeyOwned && kmsKey != "" {
		keyID := kmsKey[strings.LastIndex(kmsKey, "/")+1:]
		if _, err := kmsClient.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(keyID), PendingWindowInDays: aws.Int64(7)}); err != nil {
			report.add("cleanup-kms-key", "FAIL", err.Error(), 0)
		} else {
			report.add("cleanup-kms-key", "PASS", "temporary KMS key scheduled for deletion", 0)
		}
	}
	if !kmsKeyOwned && kmsKey != "" {
		report.add("cleanup-kms-key", "PASS", "existing KMS key retained", 0)
	}
	if len(allocatedEIPs) > 0 {
		if err := releaseIntegrationEIPs(ctx, ec2.New(sess), allocatedEIPs); err != nil {
			report.add("cleanup-eips", "FAIL", err.Error(), 0)
		} else {
			report.add("cleanup-eips", "PASS", fmt.Sprintf("released %d temporary Elastic IPs", len(allocatedEIPs)), 0)
		}
	}
}

func ensureIntegrationEIPs(ctx context.Context, client *ec2.EC2, config fullIntegrationConfig) ([]string, []string, error) {
	if len(config.EIPAllocationIDs) > 0 {
		return config.EIPAllocationIDs, nil, nil
	}
	if len(config.SubnetIDs) < 2 {
		return nil, nil, fmt.Errorf("at least two TEST_SFTP_SUBNET_IDS are required when EIP allocation IDs are omitted")
	}
	allocated := make([]string, 0, len(config.SubnetIDs))
	for range config.SubnetIDs {
		output, err := client.AllocateAddressWithContext(ctx, &ec2.AllocateAddressInput{
			Domain: aws.String("vpc"),
			TagSpecifications: []*ec2.TagSpecification{{
				ResourceType: aws.String("elastic-ip"),
				Tags: []*ec2.Tag{
					{Key: aws.String("ManagedBy"), Value: aws.String("terratest")},
					{Key: aws.String("Module"), Value: aws.String("terraform-secure-upload")},
					{Key: aws.String("TestID"), Value: aws.String(config.TestID)},
				},
			}},
		})
		if err != nil {
			_ = releaseIntegrationEIPs(ctx, client, allocated)
			return nil, nil, err
		}
		allocated = append(allocated, aws.StringValue(output.AllocationId))
	}
	return allocated, allocated, nil
}

func releaseIntegrationEIPs(ctx context.Context, client *ec2.EC2, allocationIDs []string) error {
	var firstErr error
	for _, allocationID := range allocationIDs {
		if _, err := client.ReleaseAddressWithContext(ctx, &ec2.ReleaseAddressInput{AllocationId: aws.String(allocationID)}); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func purgeBucket(ctx context.Context, client *s3.S3, bucket string) error {
	var deleteErr error
	err := client.ListObjectVersionsPagesWithContext(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)}, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		objects := make([]*s3.ObjectIdentifier, 0, len(page.Versions)+len(page.DeleteMarkers))
		for _, version := range page.Versions {
			objects = append(objects, &s3.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
		}
		for _, marker := range page.DeleteMarkers {
			objects = append(objects, &s3.ObjectIdentifier{Key: marker.Key, VersionId: marker.VersionId})
		}
		if len(objects) > 0 {
			_, deleteErr = client.DeleteObjectsWithContext(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &s3.Delete{Objects: objects, Quiet: aws.Bool(true)}})
			if deleteErr != nil {
				return false
			}
		}
		return !lastPage
	})
	if err != nil {
		return err
	}
	return deleteErr
}

func waitForTransferOnline(ctx context.Context, client *transfer.Transfer, serverID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := client.DescribeServerWithContext(ctx, &transfer.DescribeServerInput{ServerId: aws.String(serverID)})
		if err == nil && output.Server != nil && aws.StringValue(output.Server.State) == "ONLINE" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
	return fmt.Errorf("Transfer Family server %s did not become ONLINE within %s", serverID, timeout)
}

func newTransferClient(sess *session.Session) *transfer.Transfer {
	return transfer.New(sess)
}

func newNotificationMonitor(ctx context.Context, sess *session.Session, topicARN, queueName string) (*notificationMonitor, error) {
	monitor := &notificationMonitor{snsClient: sns.New(sess), sqsClient: sqs.New(sess)}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			_ = monitor.cleanup(ctx)
		}
	}()
	created, err := monitor.sqsClient.CreateQueueWithContext(ctx, &sqs.CreateQueueInput{QueueName: aws.String(queueName), Attributes: map[string]*string{"VisibilityTimeout": aws.String("60"), "ReceiveMessageWaitTimeSeconds": aws.String("10"), "SqsManagedSseEnabled": aws.String("true")}})
	if err != nil {
		return nil, err
	}
	monitor.queueURL = aws.StringValue(created.QueueUrl)
	if _, err := monitor.sqsClient.TagQueueWithContext(ctx, &sqs.TagQueueInput{QueueUrl: created.QueueUrl, Tags: map[string]*string{"ManagedBy": aws.String("terratest"), "Purpose": aws.String("secure-upload-sns-monitor")}}); err != nil {
		return nil, err
	}
	attributes, err := monitor.sqsClient.GetQueueAttributesWithContext(ctx, &sqs.GetQueueAttributesInput{QueueUrl: created.QueueUrl, AttributeNames: []*string{aws.String("QueueArn")}})
	if err != nil {
		return nil, err
	}
	queueARN := aws.StringValue(attributes.Attributes["QueueArn"])
	policy, _ := json.Marshal(map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{map[string]interface{}{
			"Effect": "Allow", "Principal": map[string]string{"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queueARN,
			"Condition": map[string]interface{}{"ArnEquals": map[string]string{"aws:SourceArn": topicARN}},
		}},
	})
	if _, err := monitor.sqsClient.SetQueueAttributesWithContext(ctx, &sqs.SetQueueAttributesInput{QueueUrl: created.QueueUrl, Attributes: map[string]*string{"Policy": aws.String(string(policy))}}); err != nil {
		return nil, err
	}
	subscription, err := monitor.snsClient.SubscribeWithContext(ctx, &sns.SubscribeInput{TopicArn: aws.String(topicARN), Protocol: aws.String("sqs"), Endpoint: aws.String(queueARN), ReturnSubscriptionArn: aws.Bool(true)})
	if err != nil {
		return nil, err
	}
	monitor.subscriptionARN = aws.StringValue(subscription.SubscriptionArn)
	if _, err := monitor.snsClient.SetSubscriptionAttributesWithContext(ctx, &sns.SetSubscriptionAttributesInput{SubscriptionArn: subscription.SubscriptionArn, AttributeName: aws.String("RawMessageDelivery"), AttributeValue: aws.String("true")}); err != nil {
		return nil, err
	}
	cleanupOnError = false
	return monitor, nil
}

func (m *notificationMonitor) waitFor(ctx context.Context, predicate func(map[string]interface{}) bool) (map[string]interface{}, error) {
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		messages, err := m.sqsClient.ReceiveMessageWithContext(ctx, &sqs.ReceiveMessageInput{QueueUrl: aws.String(m.queueURL), MaxNumberOfMessages: aws.Int64(10), WaitTimeSeconds: aws.Int64(10), VisibilityTimeout: aws.Int64(30)})
		if err != nil {
			return nil, err
		}
		for _, message := range messages.Messages {
			payload, err := parseSNSMessage(aws.StringValue(message.Body))
			if err != nil {
				continue
			}
			if _, err := m.sqsClient.DeleteMessageWithContext(ctx, &sqs.DeleteMessageInput{QueueUrl: aws.String(m.queueURL), ReceiptHandle: message.ReceiptHandle}); err != nil {
				return nil, err
			}
			if predicate(payload) {
				return payload, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	return nil, fmt.Errorf("expected SNS notification was not received within 10m")
}

func (m *notificationMonitor) cleanup(ctx context.Context) error {
	var firstErr error
	if m.subscriptionARN != "" {
		if _, err := m.snsClient.UnsubscribeWithContext(ctx, &sns.UnsubscribeInput{SubscriptionArn: aws.String(m.subscriptionARN)}); err != nil {
			firstErr = err
		}
	}
	if m.queueURL != "" {
		if _, err := m.sqsClient.DeleteQueueWithContext(ctx, &sqs.DeleteQueueInput{QueueUrl: aws.String(m.queueURL)}); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func parseSNSMessage(body string) (map[string]interface{}, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, err
	}
	if message, ok := payload["Message"].(string); ok {
		var nested map[string]interface{}
		if err := json.Unmarshal([]byte(message), &nested); err == nil {
			return nested, nil
		}
	}
	return payload, nil
}

func messageString(payload map[string]interface{}, key string) string {
	value, _ := payload[key].(string)
	return value
}

func waitForLogEvents(ctx context.Context, client *cloudwatchlogs.CloudWatchLogs, group, pattern string, start time.Time, timeout time.Duration) ([]*cloudwatchlogs.FilteredLogEvent, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		input := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String(group), StartTime: aws.Int64(start.UnixMilli()), Interleaved: aws.Bool(true), Limit: aws.Int64(100)}
		if pattern != "" {
			input.FilterPattern = aws.String(pattern)
		}
		output, err := client.FilterLogEventsWithContext(ctx, input)
		if err == nil && len(output.Events) > 0 {
			return output.Events, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
	return nil, fmt.Errorf("no CloudWatch events found in %s within %s", group, timeout)
}

func findTransferLogGroup(ctx context.Context, client *cloudwatchlogs.CloudWatchLogs, serverID string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := client.DescribeLogGroupsWithContext(ctx, &cloudwatchlogs.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String("/aws/transfer/")})
		if err == nil {
			for _, group := range output.LogGroups {
				if strings.Contains(aws.StringValue(group.LogGroupName), serverID) {
					return aws.StringValue(group.LogGroupName), nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
	return "", fmt.Errorf("no Transfer Family log group found for %s", serverID)
}
