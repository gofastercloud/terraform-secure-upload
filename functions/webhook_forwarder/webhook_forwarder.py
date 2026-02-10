"""
Lambda function that forwards SNS malware-alert notifications to external
webhook integrations (Discord and/or ServiceNow).

Triggered by an SNS subscription; the SNS message body is a JSON string
published by the file-router Lambda when a file is quarantined.
"""

import json
import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration from environment variables
# ---------------------------------------------------------------------------
DISCORD_WEBHOOK_SSM_PARAMETER = os.environ.get("DISCORD_WEBHOOK_SSM_PARAMETER")
SERVICENOW_INSTANCE_URL = os.environ.get("SERVICENOW_INSTANCE_URL")
SERVICENOW_CREDENTIALS_SECRET_ARN = os.environ.get("SERVICENOW_CREDENTIALS_SECRET_ARN")

# ---------------------------------------------------------------------------
# Cached secrets (fetched once at init, reused across warm invocations)
# ---------------------------------------------------------------------------
_discord_webhook_url = None
_servicenow_username = None
_servicenow_password = None


def _get_discord_webhook_url():
    """Retrieve Discord webhook URL from SSM Parameter Store (cached)."""
    global _discord_webhook_url
    if _discord_webhook_url is not None:
        return _discord_webhook_url

    if not DISCORD_WEBHOOK_SSM_PARAMETER:
        raise ValueError("DISCORD_WEBHOOK_SSM_PARAMETER is not set")

    import boto3

    client = boto3.client("ssm")
    resp = client.get_parameter(
        Name=DISCORD_WEBHOOK_SSM_PARAMETER, WithDecryption=True
    )
    _discord_webhook_url = resp["Parameter"]["Value"]
    logger.info("Discord webhook URL retrieved from SSM Parameter Store")
    return _discord_webhook_url


def _get_servicenow_credentials():
    """Retrieve ServiceNow credentials from AWS Secrets Manager (cached)."""
    global _servicenow_username, _servicenow_password
    if _servicenow_username is not None:
        return _servicenow_username, _servicenow_password

    if not SERVICENOW_CREDENTIALS_SECRET_ARN:
        raise ValueError("SERVICENOW_CREDENTIALS_SECRET_ARN is not set")

    import boto3

    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=SERVICENOW_CREDENTIALS_SECRET_ARN)
    secret = json.loads(resp["SecretString"])
    _servicenow_username = secret["username"]
    _servicenow_password = secret["password"]
    logger.info("ServiceNow credentials retrieved from Secrets Manager")
    return _servicenow_username, _servicenow_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_sns_message(record):
    """Extract alert fields from an SNS record's Message body."""
    message_body = record["Sns"]["Message"]
    msg = json.loads(message_body)
    return {
        "file_key": msg.get("file_key", "unknown"),
        "source_bucket": msg.get("source_bucket", "unknown"),
        "quarantine_bucket": msg.get("quarantine_bucket", "unknown"),
        "scan_result_status": msg.get("scan_result_status", "unknown"),
        "threats": msg.get("threats", []),
        "timestamp": msg.get("timestamp", "unknown"),
    }


def _send_discord(alert):
    """Send a rich embed to a Discord webhook."""
    webhook_url = _get_discord_webhook_url()

    threat_names = ", ".join(
        t.get("name", "unknown") for t in alert["threats"]
    ) or "N/A"

    embed = {
        "title": "Malware Detected in Upload",
        "color": 0xD62728,  # red
        "fields": [
            {"name": "File", "value": alert["file_key"], "inline": False},
            {"name": "Source Bucket", "value": alert["source_bucket"], "inline": True},
            {"name": "Quarantine Bucket", "value": alert["quarantine_bucket"], "inline": True},
            {"name": "Scan Result", "value": alert["scan_result_status"], "inline": True},
            {"name": "Threats", "value": threat_names, "inline": False},
            {"name": "Timestamp", "value": alert["timestamp"], "inline": True},
        ],
    }

    payload = json.dumps({"embeds": [embed]}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "TerraformSecureUpload/1.0 (webhook-forwarder)",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Discord webhook returned %s", resp.status)
    except urllib.error.HTTPError as exc:
        logger.error("Discord webhook HTTP error %s: %s", exc.code, exc.read().decode())
        raise
    except urllib.error.URLError as exc:
        logger.error("Discord webhook URL error: %s", exc.reason)
        raise


def _send_servicenow(alert):
    """Create an incident in ServiceNow via the REST API."""
    username, password = _get_servicenow_credentials()

    threat_names = ", ".join(
        t.get("name", "unknown") for t in alert["threats"]
    ) or "N/A"

    description = (
        f"Malware detected in uploaded file.\n\n"
        f"File: {alert['file_key']}\n"
        f"Source Bucket: {alert['source_bucket']}\n"
        f"Quarantine Bucket: {alert['quarantine_bucket']}\n"
        f"Scan Result: {alert['scan_result_status']}\n"
        f"Threats: {threat_names}\n"
        f"Timestamp: {alert['timestamp']}"
    )

    incident = {
        "short_description": f"Malware detected: {alert['file_key']}",
        "description": description,
        "urgency": "1",
        "impact": "1",
        "category": "Security",
    }

    url = f"{SERVICENOW_INSTANCE_URL.rstrip('/')}/api/now/table/incident"
    payload = json.dumps(incident).encode("utf-8")

    # Basic auth header
    import base64

    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {credentials}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            logger.info("ServiceNow incident created, status %s", resp.status)
    except urllib.error.HTTPError as exc:
        logger.error("ServiceNow HTTP error %s: %s", exc.code, exc.read().decode())
        raise
    except urllib.error.URLError as exc:
        logger.error("ServiceNow URL error: %s", exc.reason)
        raise


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event, context):
    """Process SNS event records and forward to configured integrations."""
    records = event.get("Records", [])
    logger.info("Received %d SNS record(s)", len(records))

    for record in records:
        alert = _parse_sns_message(record)
        logger.info(
            "Processing alert: file_key=%s, scan_result_status=%s",
            alert["file_key"],
            alert["scan_result_status"],
        )

        if DISCORD_WEBHOOK_SSM_PARAMETER:
            _send_discord(alert)

        if SERVICENOW_INSTANCE_URL:
            _send_servicenow(alert)

    return {"statusCode": 200, "body": f"Processed {len(records)} record(s)."}
