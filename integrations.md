# Integrations

terraform-secure-upload supports optional integrations that forward malware detection alerts to external chat, incident management, and ticketing platforms. All integrations subscribe to the module's SNS alert topic and are disabled by default.

## Quick Reference

| Integration | Type | Variable to Enable |
|---|---|---|
| Slack | AWS Chatbot | `enable_slack_integration = true` |
| Microsoft Teams | AWS Chatbot | `enable_teams_integration = true` |
| PagerDuty | SNS HTTPS | `pagerduty_integration_url = "https://..."` |
| VictorOps / Splunk On-Call | SNS HTTPS | `victorops_integration_url = "https://..."` |
| Discord | Lambda webhook | `enable_discord_integration = true` |
| ServiceNow | Lambda webhook | `enable_servicenow_integration = true` |

---

## Slack (AWS Chatbot)

Delivers malware alerts to a Slack channel using [AWS Chatbot](https://docs.aws.amazon.com/chatbot/latest/adminguide/what-is.html).

### Prerequisites

1. **Install the AWS Chatbot app in your Slack workspace.** Go to the [AWS Chatbot console](https://console.aws.amazon.com/chatbot/) and click *Configure new client* > *Slack*. Authorize the AWS Chatbot app for your workspace. This is a one-time setup per workspace.
2. **Note your Slack Workspace ID** (starts with `T`) — visible in the Chatbot console after authorization.
3. **Note the Slack Channel ID** (starts with `C`) — right-click the channel in Slack > *View channel details* > scroll to the bottom.

### Configuration

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  enable_slack_integration = true
  slack_workspace_id       = "T0XXXXXXXXX"   # Your Slack workspace ID
  slack_channel_id         = "C0XXXXXXXXX"   # Channel to receive alerts
}
```

### What Gets Created

- An IAM role for AWS Chatbot with read-only CloudWatch and SNS permissions
- An `aws_chatbot_slack_channel_configuration` that subscribes to the malware alert SNS topic

### Alert Format

AWS Chatbot renders the SNS message as a formatted Slack notification. The message includes the file key, scan result, and threat details.

---

## Microsoft Teams (AWS Chatbot)

Delivers malware alerts to a Microsoft Teams channel using [AWS Chatbot](https://docs.aws.amazon.com/chatbot/latest/adminguide/what-is.html).

### Prerequisites

1. **Install the AWS Chatbot app in your Teams tenant.** Go to the [AWS Chatbot console](https://console.aws.amazon.com/chatbot/) and click *Configure new client* > *Microsoft Teams*. Follow the authorization flow for your tenant.
2. **Note your Tenant ID, Team ID, and Channel ID** — visible in the Chatbot console after authorization, or via the Teams admin center.

### Configuration

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  enable_teams_integration = true
  teams_tenant_id          = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  teams_team_id            = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  teams_channel_id         = "19:xxxxxxxxxxxxx@thread.tacv2"
}
```

### What Gets Created

- An IAM role for AWS Chatbot (shared with Slack if both are enabled) with read-only CloudWatch and SNS permissions
- An `aws_chatbot_teams_channel_configuration` that subscribes to the malware alert SNS topic

---

## PagerDuty

Forwards malware alerts to PagerDuty via a direct SNS HTTPS subscription. Each alert creates a PagerDuty incident.

### Prerequisites

1. **Create a PagerDuty service** (or use an existing one) for receiving malware alerts.
2. **Add an Amazon SNS integration** to the service:
   - In PagerDuty, go to *Services* > your service > *Integrations* > *Add an integration*.
   - Select **Amazon CloudWatch** or **AWS CloudWatch** as the integration type.
   - Copy the **Integration URL** (starts with `https://events.pagerduty.com/`).

### Configuration

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  pagerduty_integration_url = "https://events.pagerduty.com/integration/XXXXXXXX/enqueue"
}
```

Setting `pagerduty_integration_url` to a non-null value automatically enables the integration. Set it back to `null` (default) to disable.

### What Gets Created

- An `aws_sns_topic_subscription` with `protocol = "https"` and `endpoint_auto_confirms = true`
- A delivery retry policy (3 retries with 20-second linear backoff)

### URL Validation

The module validates that the URL starts with `https://events.pagerduty.com/`.

---

## VictorOps / Splunk On-Call

Forwards malware alerts to VictorOps (Splunk On-Call) via a direct SNS HTTPS subscription.

### Prerequisites

1. **Create a REST endpoint integration** in VictorOps:
   - Go to *Integrations* > *REST – Generic* > enable the integration.
   - Copy the **REST endpoint URL** (starts with `https://alert.victorops.com/`).
   - Append your routing key to the URL if needed.

### Configuration

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  victorops_integration_url = "https://alert.victorops.com/integrations/generic/XXXXXXXX/alert/ROUTING_KEY"
}
```

Setting `victorops_integration_url` to a non-null value automatically enables the integration. Set it back to `null` (default) to disable.

### What Gets Created

- An `aws_sns_topic_subscription` with `protocol = "https"` and `endpoint_auto_confirms = true`
- A delivery retry policy (3 retries with 20-second linear backoff)

### URL Validation

The module validates that the URL starts with `https://alert.victorops.com/`.

---

## Discord

Delivers rich embed notifications to a Discord channel via a webhook. Because Discord webhooks require payload transformation, this integration deploys a lightweight Lambda function as a forwarder.

### Prerequisites

1. **Create a Discord webhook** for your channel:
   - In Discord, go to *Server Settings* > *Integrations* > *Webhooks* > *New Webhook*.
   - Select the target channel and copy the **Webhook URL**.

### Configuration

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  enable_discord_integration = true
  discord_webhook_url        = "https://discord.com/api/webhooks/XXXXXXXXXX/XXXXXXXXXX"
}
```

> **Note:** The `discord_webhook_url` variable is marked `sensitive` in Terraform. The webhook URL is stored as a SecureString in SSM Parameter Store (encrypted with the module's KMS key) and fetched by the Lambda at runtime — it never appears as a plaintext environment variable.

### What Gets Created

- An SSM Parameter Store SecureString (`/<name_prefix>/discord-webhook-url`) containing the webhook URL, encrypted with the module's KMS key
- A Lambda function (`webhook_forwarder`) subscribed to the SNS alert topic
- An IAM role for the Lambda with permissions for CloudWatch Logs, KMS, and SSM (scoped to the parameter)
- A CloudWatch Log Group for the Lambda
- An SNS topic subscription (`protocol = lambda`)
- An SNS invoke permission for the Lambda

If ServiceNow is also enabled, both integrations share the same Lambda function.

### Alert Format

The Discord notification appears as a red-colored embed with fields for file name, source bucket, quarantine bucket, scan result, threat names, and timestamp.

---

## ServiceNow

Creates incidents in ServiceNow when malware is detected. Uses the ServiceNow REST API via the same webhook forwarder Lambda as Discord.

### Prerequisites

1. **Note your ServiceNow instance URL** (e.g. `https://mycompany.service-now.com`).
2. **Prepare ServiceNow credentials as a JSON string:**

   ```json
   {"username": "api_user", "password": "api_password"}
   ```

   We recommend creating a dedicated ServiceNow service account with permission to create incidents via the REST API (`/api/now/table/incident`).

### Configuration

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  enable_servicenow_integration = true
  servicenow_instance_url       = "https://mycompany.service-now.com"
  servicenow_credentials        = "{\"username\":\"api_user\",\"password\":\"api_password\"}"
}
```

> **Note:** The `servicenow_credentials` variable is marked `sensitive` in Terraform. The credentials are stored as a SecureString in SSM Parameter Store (encrypted with the module's KMS key) and fetched by the Lambda at runtime — they never appear as plaintext environment variables.

### What Gets Created

- An SSM Parameter Store SecureString (`/<name_prefix>/secure-upload/servicenow-credentials`) containing the credentials, encrypted with the module's KMS key
- A Lambda function (`webhook_forwarder`) subscribed to the SNS alert topic (shared with Discord if both are enabled)
- An IAM role for the Lambda with permissions for CloudWatch Logs, KMS, and SSM (scoped to the parameter)
- A CloudWatch Log Group for the Lambda
- An SNS topic subscription and invoke permission

### Credentials Validation

The module validates that `servicenow_credentials` is a valid JSON string when `enable_servicenow_integration` is `true`.

### Incident Fields

| ServiceNow Field | Value |
|---|---|
| `short_description` | `Malware detected: <file_key>` |
| `description` | Full alert details (file, buckets, scan result, threats, timestamp) |
| `urgency` | 1 (High) |
| `impact` | 1 (High) |
| `category` | Security |

---

## Combining Integrations

All integrations can be enabled simultaneously. For example:

```hcl
module "secure_upload" {
  source = "gofastercloud/secure-upload/aws"

  # ... core configuration ...

  # Slack
  enable_slack_integration = true
  slack_workspace_id       = "T0XXXXXXXXX"
  slack_channel_id         = "C0XXXXXXXXX"

  # PagerDuty
  pagerduty_integration_url = "https://events.pagerduty.com/integration/XXXX/enqueue"

  # Discord
  enable_discord_integration = true
  discord_webhook_url        = "https://discord.com/api/webhooks/XXXX/XXXX"

  # ServiceNow
  enable_servicenow_integration = true
  servicenow_instance_url       = "https://mycompany.service-now.com"
  servicenow_credentials        = var.servicenow_credentials  # JSON: {"username":"...","password":"..."}
}
```

### Resource Sharing

- **Slack + Teams**: Share a single IAM role for AWS Chatbot.
- **Discord + ServiceNow**: Share a single Lambda function (`webhook_forwarder`). The Lambda checks which environment variables are present and forwards to each configured destination.
- **PagerDuty, VictorOps**: Each gets its own independent SNS HTTPS subscription — no Lambda required.
