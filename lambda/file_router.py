"""
Lambda function triggered by EventBridge when GuardDuty Malware Protection
completes a scan. Routes files to egress or quarantine buckets based on results.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
sns = boto3.client("sns")

INGRESS_BUCKET = os.environ["INGRESS_BUCKET"]
EGRESS_BUCKET = os.environ["EGRESS_BUCKET"]
QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
KMS_KEY_ARN = os.environ["KMS_KEY_ARN"]


def handler(event, context):
    logger.info(
        "Received event: source=%s, detail-type=%s",
        event.get("source", "unknown"),
        event.get("detail-type", "unknown"),
    )

    detail = event.get("detail", {})
    scan_status = detail.get("scanStatus")

    if scan_status not in ("COMPLETED", "SKIPPED", "FAILED"):
        logger.warning("Unexpected scanStatus '%s'. Skipping.", scan_status)
        return {"statusCode": 200, "body": "Unexpected scan status, skipping."}

    # Extract S3 object details from the event
    s3_object_details = detail.get("s3ObjectDetails", {})
    source_bucket = s3_object_details.get("bucketName")
    object_key = s3_object_details.get("objectKey")

    if not source_bucket or not object_key:
        logger.error("Missing bucket name or object key in event detail.")
        raise ValueError("Missing bucket name or object key in event detail.")

    # Validate source bucket matches expected ingress bucket
    if source_bucket != INGRESS_BUCKET:
        logger.error(
            "Source bucket '%s' does not match expected ingress bucket '%s'. Rejecting event.",
            source_bucket,
            INGRESS_BUCKET,
        )
        raise ValueError(
            f"Source bucket '{source_bucket}' does not match expected ingress bucket '{INGRESS_BUCKET}'."
        )

    # Extract scan result
    scan_result_details = detail.get("scanResultDetails", {})
    scan_result_status = scan_result_details.get("scanResultStatus")

    logger.info(
        "Processing: scanStatus=%s, scanResultStatus=%s, s3://%s/%s",
        scan_status,
        scan_result_status,
        source_bucket,
        object_key,
    )

    if scan_result_status == "NO_THREATS_FOUND":
        return _route_egress(source_bucket, object_key)
    elif scan_result_status == "THREATS_FOUND":
        threats = scan_result_details.get("threats") or []
        return _route_quarantine(source_bucket, object_key, scan_result_status, threats)
    else:
        # UNSUPPORTED, ACCESS_DENIED, FAILED — leave for manual review
        logger.warning(
            "Scan result '%s' for s3://%s/%s — leaving for manual review.",
            scan_result_status,
            source_bucket,
            object_key,
        )
        return {
            "statusCode": 200,
            "body": f"Scan result '{scan_result_status}', file left for manual review.",
        }


def _object_exists(bucket, key):
    """Check if an object exists in a bucket (idempotency guard)."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise


def _copy_object(source_bucket, object_key, dest_bucket):
    copy_source = {"Bucket": source_bucket, "Key": object_key}
    s3.copy_object(
        CopySource=copy_source,
        Bucket=dest_bucket,
        Key=object_key,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=KMS_KEY_ARN,
    )
    logger.info("Copied s3://%s/%s to s3://%s/%s", source_bucket, object_key, dest_bucket, object_key)


def _delete_object(bucket, key):
    s3.delete_object(Bucket=bucket, Key=key)
    logger.info("Deleted s3://%s/%s", bucket, key)


def _route_egress(source_bucket, object_key):
    try:
        # Idempotency: if source object is already gone, skip
        if not _object_exists(source_bucket, object_key):
            logger.info("Source object s3://%s/%s no longer exists (duplicate event). Skipping.", source_bucket, object_key)
            return {"statusCode": 200, "body": "Duplicate event, source object already processed."}

        _copy_object(source_bucket, object_key, EGRESS_BUCKET)
        _delete_object(source_bucket, object_key)
        logger.info("File routed to egress bucket: %s", object_key)
        return {"statusCode": 200, "body": "File routed to egress bucket."}
    except ClientError:
        logger.exception("Failed to route egress file s3://%s/%s", source_bucket, object_key)
        raise


def _route_quarantine(source_bucket, object_key, scan_result_status, threats):
    try:
        # Idempotency: if source object is already gone, skip
        if not _object_exists(source_bucket, object_key):
            logger.info("Source object s3://%s/%s no longer exists (duplicate event). Skipping.", source_bucket, object_key)
            return {"statusCode": 200, "body": "Duplicate event, source object already processed."}

        _copy_object(source_bucket, object_key, QUARANTINE_BUCKET)
        _delete_object(source_bucket, object_key)
        logger.info("File routed to quarantine bucket: %s", object_key)

        message = {
            "alert": "Malware detected in uploaded file",
            "file_key": object_key,
            "source_bucket": source_bucket,
            "quarantine_bucket": QUARANTINE_BUCKET,
            "scan_result_status": scan_result_status,
            "threats": threats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="ALERT: Malware Detected in Upload",
            Message=json.dumps(message, indent=2),
        )
        logger.info("SNS notification sent for quarantined file: %s", object_key)

        return {"statusCode": 200, "body": "File quarantined and notification sent."}
    except ClientError:
        logger.exception("Failed to route quarantined file s3://%s/%s", source_bucket, object_key)
        raise
