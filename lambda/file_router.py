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
lambda_client = boto3.client("lambda")

INGRESS_BUCKET = os.environ["INGRESS_BUCKET"]
EGRESS_BUCKET = os.environ["EGRESS_BUCKET"]
QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
KMS_KEY_ARN = os.environ["KMS_KEY_ARN"]
SCANNER_FUNCTION_NAME = os.environ.get("SCANNER_FUNCTION_NAME")
PROMPT_INJECTION_THRESHOLD = int(os.environ.get("PROMPT_INJECTION_THRESHOLD", "0"))
VIRUSTOTAL_FUNCTION_NAME = os.environ.get("VIRUSTOTAL_FUNCTION_NAME")
VIRUSTOTAL_THRESHOLD = int(os.environ.get("VIRUSTOTAL_THRESHOLD", "3"))
EGRESS_SNS_TOPIC_ARN = os.environ.get("EGRESS_SNS_TOPIC_ARN")
AUDIT_TABLE_NAME = os.environ.get("AUDIT_TABLE_NAME")
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "365"))

# Lazy-init DynamoDB resource (only when audit trail is enabled)
_dynamodb_table = None


def _get_audit_table():
    """Return a boto3 DynamoDB Table resource (lazy-initialized)."""
    global _dynamodb_table
    if _dynamodb_table is None:
        dynamodb = boto3.resource("dynamodb")
        _dynamodb_table = dynamodb.Table(AUDIT_TABLE_NAME)
    return _dynamodb_table


def _write_audit(bucket, key, event_type, outcome, detail=None, file_size=0):
    """Write an audit trail record to DynamoDB."""
    if not AUDIT_TABLE_NAME:
        return

    now = datetime.now(timezone.utc)
    item = {
        "PK": f"FILE#{bucket}#{key}",
        "SK": f"EVENT#{now.isoformat()}#{event_type}",
        "file_key": key,
        "file_size": file_size,
        "event_type": event_type,
        "outcome": outcome,
        "timestamp": now.isoformat(),
    }
    if detail:
        item["detail"] = detail
    if AUDIT_RETENTION_DAYS > 0:
        import calendar
        from datetime import timedelta
        expires = now + timedelta(days=AUDIT_RETENTION_DAYS)
        item["expires_at"] = int(calendar.timegm(expires.timetuple()))

    try:
        _get_audit_table().put_item(Item=item)
    except Exception:
        logger.exception("Failed to write audit record for %s/%s event=%s", bucket, key, event_type)


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

    # Get file size for audit records
    file_size = 0
    try:
        head = s3.head_object(Bucket=source_bucket, Key=object_key)
        file_size = head.get("ContentLength", 0)
    except ClientError:
        pass

    _write_audit(source_bucket, object_key, "received", scan_result_status, file_size=file_size)
    _write_audit(source_bucket, object_key, "guardduty_result", scan_result_status,
                 detail={"scan_status": scan_status, "scan_result_status": scan_result_status},
                 file_size=file_size)

    # Collect VT result early (used for routing, notifications, and audit)
    vt_result = None
    if scan_result_status == "NO_THREATS_FOUND" and VIRUSTOTAL_FUNCTION_NAME:
        vt_result = _get_virustotal_result(source_bucket, object_key)
        _write_audit(source_bucket, object_key, "virustotal_result",
                     "malicious" if vt_result.get("positives", 0) >= VIRUSTOTAL_THRESHOLD else "clean",
                     detail=vt_result, file_size=file_size)

    if scan_result_status == "NO_THREATS_FOUND":
        # VirusTotal check (if enabled)
        if vt_result is not None and vt_result.get("positives", 0) >= VIRUSTOTAL_THRESHOLD:
            logger.info(
                "VirusTotal malicious: positives=%s, threshold=%s, s3://%s/%s",
                vt_result["positives"],
                VIRUSTOTAL_THRESHOLD,
                source_bucket,
                object_key,
            )
            return _route_quarantine(
                source_bucket,
                object_key,
                "VIRUSTOTAL_MALICIOUS",
                [{"name": "VirusTotal", "positives": vt_result["positives"],
                  "total": vt_result.get("total", 0), "sha256": vt_result.get("sha256", "")}],
                file_size=file_size,
                vt_result=vt_result,
            )

        # Prompt injection check (if enabled)
        if SCANNER_FUNCTION_NAME:
            score, scannable = _check_prompt_injection(source_bucket, object_key)
            _write_audit(source_bucket, object_key, "prompt_injection_result",
                         "detected" if scannable and score > PROMPT_INJECTION_THRESHOLD else "clean",
                         detail={"score": score, "scannable": scannable, "threshold": PROMPT_INJECTION_THRESHOLD},
                         file_size=file_size)
            if scannable and score > PROMPT_INJECTION_THRESHOLD:
                logger.info(
                    "Prompt injection detected: score=%s, threshold=%s, s3://%s/%s",
                    score,
                    PROMPT_INJECTION_THRESHOLD,
                    source_bucket,
                    object_key,
                )
                return _route_quarantine(
                    source_bucket,
                    object_key,
                    "PROMPT_INJECTION_DETECTED",
                    [{"name": "PromptInjection", "score": score}],
                    file_size=file_size,
                    vt_result=vt_result,
                    pi_score=score,
                )
        return _route_egress(source_bucket, object_key, file_size=file_size, vt_result=vt_result)
    elif scan_result_status == "THREATS_FOUND":
        threats = scan_result_details.get("threats") or []
        return _route_quarantine(source_bucket, object_key, scan_result_status, threats, file_size=file_size, vt_result=vt_result)
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


def _check_prompt_injection(bucket, key):
    """Invoke the prompt injection scanner Lambda synchronously and return (score, scannable)."""
    response = lambda_client.invoke(
        FunctionName=SCANNER_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps({"bucket": bucket, "key": key}),
    )
    payload = json.loads(response["Payload"].read())

    # Handle Lambda errors (function error vs execution error)
    if "FunctionError" in response:
        logger.error("Scanner Lambda returned error: %s", payload)
        raise RuntimeError(f"Prompt injection scanner failed: {payload}")

    score = payload.get("score", 0)
    scannable = payload.get("scannable", False)
    logger.info(
        "Prompt injection scan result for s3://%s/%s: score=%s, scannable=%s",
        bucket,
        key,
        score,
        scannable,
    )
    return score, scannable


def _get_virustotal_result(bucket, key):
    """Read VT results from S3 object tags, fallback to synchronous invoke."""
    try:
        resp = s3.get_object_tagging(Bucket=bucket, Key=key)
        tags = {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        if "vt-status" in tags:
            result = {
                "positives": int(tags.get("vt-positives", "0")),
                "total": int(tags.get("vt-total", "0")),
                "sha256": tags.get("vt-sha256", ""),
                "found": tags.get("vt-status") != "not-found",
                "source": "tags",
            }
            logger.info(
                "VT result from tags for s3://%s/%s: status=%s, positives=%s, total=%s",
                bucket, key, tags["vt-status"], result["positives"], result["total"],
            )
            return result
    except Exception:
        logger.warning("Failed to read VT tags for s3://%s/%s, falling back to sync invoke", bucket, key)

    # Fallback: synchronous invoke (race condition — VT hasn't finished yet)
    return _check_virustotal(bucket, key)


def _check_virustotal(bucket, key):
    """Invoke the VirusTotal scanner Lambda synchronously and return the result."""
    response = lambda_client.invoke(
        FunctionName=VIRUSTOTAL_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps({"bucket": bucket, "key": key}),
    )
    payload = json.loads(response["Payload"].read())

    if "FunctionError" in response:
        logger.error("VirusTotal scanner Lambda returned error: %s", payload)
        raise RuntimeError(f"VirusTotal scanner failed: {payload}")

    logger.info(
        "VirusTotal scan result for s3://%s/%s: positives=%s, total=%s, found=%s",
        bucket,
        key,
        payload.get("positives", 0),
        payload.get("total", 0),
        payload.get("found", False),
    )
    payload["source"] = "invoke"
    return payload


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


def _route_egress(source_bucket, object_key, file_size=0, vt_result=None):
    try:
        # Idempotency: if source object is already gone, skip
        if not _object_exists(source_bucket, object_key):
            logger.info("Source object s3://%s/%s no longer exists (duplicate event). Skipping.", source_bucket, object_key)
            return {"statusCode": 200, "body": "Duplicate event, source object already processed."}

        _copy_object(source_bucket, object_key, EGRESS_BUCKET)
        _delete_object(source_bucket, object_key)
        logger.info("File routed to egress bucket: %s", object_key)

        _write_audit(source_bucket, object_key, "routed", "egress",
                     detail={"destination": EGRESS_BUCKET}, file_size=file_size)

        # Publish egress notification if enabled
        if EGRESS_SNS_TOPIC_ARN:
            egress_message = {
                "event": "file_delivered",
                "bucket": EGRESS_BUCKET,
                "key": object_key,
                "size_bytes": file_size,
                "scans": _build_scan_summary(scan_result_status="NO_THREATS_FOUND", vt_result=vt_result),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            sns.publish(
                TopicArn=EGRESS_SNS_TOPIC_ARN,
                Subject=f"File Delivered: {object_key}",
                Message=json.dumps(egress_message, indent=2),
            )
            logger.info("Egress notification sent for: %s", object_key)

        return {"statusCode": 200, "body": "File routed to egress bucket."}
    except ClientError:
        logger.exception("Failed to route egress file s3://%s/%s", source_bucket, object_key)
        raise


def _build_scan_summary(scan_result_status="NO_THREATS_FOUND", vt_result=None, pi_score=None):
    """Build a summary of scan results for notifications."""
    summary = {"guardduty": scan_result_status}
    if VIRUSTOTAL_FUNCTION_NAME:
        if vt_result:
            summary["virustotal"] = {
                "status": "clean" if vt_result.get("positives", 0) < VIRUSTOTAL_THRESHOLD else "malicious",
                "positives": vt_result.get("positives", 0),
                "total": vt_result.get("total", 0),
                "sha256": vt_result.get("sha256", ""),
                "found": vt_result.get("found", False),
                "source": vt_result.get("source", "unknown"),
            }
        else:
            summary["virustotal"] = "not_checked" if scan_result_status == "THREATS_FOUND" else "clean"
    if SCANNER_FUNCTION_NAME:
        if pi_score is not None:
            summary["prompt_injection"] = {"score": pi_score, "threshold": PROMPT_INJECTION_THRESHOLD}
        else:
            summary["prompt_injection"] = "not_checked" if scan_result_status == "THREATS_FOUND" else "clean"
    return summary


def _route_quarantine(source_bucket, object_key, scan_result_status, threats, file_size=0, vt_result=None, pi_score=None):
    try:
        # Idempotency: if source object is already gone, skip
        if not _object_exists(source_bucket, object_key):
            logger.info("Source object s3://%s/%s no longer exists (duplicate event). Skipping.", source_bucket, object_key)
            return {"statusCode": 200, "body": "Duplicate event, source object already processed."}

        _copy_object(source_bucket, object_key, QUARANTINE_BUCKET)
        _delete_object(source_bucket, object_key)
        logger.info("File routed to quarantine bucket: %s", object_key)

        _write_audit(source_bucket, object_key, "routed", "quarantine",
                     detail={"destination": QUARANTINE_BUCKET, "reason": scan_result_status, "threats": threats},
                     file_size=file_size)

        # Derive GuardDuty status: only THREATS_FOUND means GD caught it;
        # VT/PI quarantines happen after GD passed the file.
        gd_status = scan_result_status if scan_result_status == "THREATS_FOUND" else "NO_THREATS_FOUND"

        message = {
            "alert": "Malware detected in uploaded file",
            "file_key": object_key,
            "source_bucket": source_bucket,
            "quarantine_bucket": QUARANTINE_BUCKET,
            "scan_result_status": scan_result_status,
            "threats": threats,
            "scans": _build_scan_summary(scan_result_status=gd_status, vt_result=vt_result, pi_score=pi_score),
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
