"""Route GuardDuty Malware Protection for S3 scan results."""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
sns = boto3.client("sns")

INGRESS_BUCKET = os.environ["INGRESS_BUCKET"]
CLEAN_BUCKET = os.environ["CLEAN_BUCKET"]
QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
KMS_KEY_ARN = os.environ["KMS_KEY_ARN"]


def handler(event, context):
    detail = event.get("detail", {})
    scan_status = detail.get("scanStatus")
    scan_result_details = detail.get("scanResultDetails", {})
    scan_result_status = scan_result_details.get("scanResultStatus")
    object_details = detail.get("s3ObjectDetails", {})
    source_bucket = object_details.get("bucketName")
    object_key = object_details.get("objectKey")
    version_id = object_details.get("versionId")

    if scan_status not in ("COMPLETED", "SKIPPED", "FAILED"):
        raise ValueError(f"Unsupported GuardDuty scan status: {scan_status!r}")
    if not source_bucket or not object_key or not scan_result_status:
        raise ValueError("GuardDuty scan result did not contain a bucket, key, and result status")
    if source_bucket != INGRESS_BUCKET:
        raise ValueError(f"Unexpected scan bucket: {source_bucket}")

    file_size = _get_file_size(source_bucket, object_key, version_id)
    logger.info(
        "Routing scan result: status=%s result=%s s3://%s/%s version=%s",
        scan_status,
        scan_result_status,
        source_bucket,
        object_key,
        version_id,
    )

    if scan_result_status == "NO_THREATS_FOUND":
        destination_bucket = CLEAN_BUCKET
    else:
        destination_bucket = QUARANTINE_BUCKET

    _copy_object(source_bucket, object_key, version_id, destination_bucket)

    notification = {
        "event": "s3_object_scan_result",
        "scan_status": scan_status,
        "scan_result_status": scan_result_status,
        "status_reasons": scan_result_details.get("statusReasons") or [],
        "threats": scan_result_details.get("threats") or [],
        "file_key": object_key,
        "source_bucket": source_bucket,
        "destination_bucket": destination_bucket,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"S3 object scan: {scan_result_status}",
        Message=json.dumps(notification),
    )
    _delete_object(source_bucket, object_key, version_id)

    return {
        "statusCode": 200,
        "body": f"Object routed to {destination_bucket}",
        "file_size": file_size,
    }


def _get_file_size(bucket, key, version_id):
    arguments = {"Bucket": bucket, "Key": key}
    if version_id:
        arguments["VersionId"] = version_id
    return s3.head_object(**arguments).get("ContentLength", 0)


def _copy_object(source_bucket, key, version_id, destination_bucket):
    copy_source = {"Bucket": source_bucket, "Key": key}
    if version_id:
        copy_source["VersionId"] = version_id

    s3.copy_object(
        CopySource=copy_source,
        Bucket=destination_bucket,
        Key=key,
        MetadataDirective="COPY",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=KMS_KEY_ARN,
        BucketKeyEnabled=True,
    )
    logger.info("Copied s3://%s/%s to s3://%s/%s", source_bucket, key, destination_bucket, key)


def _delete_object(bucket, key, version_id):
    arguments = {"Bucket": bucket, "Key": key}
    if version_id:
        arguments["VersionId"] = version_id
    s3.delete_object(**arguments)
    logger.info("Deleted source version s3://%s/%s version=%s", bucket, key, version_id)
