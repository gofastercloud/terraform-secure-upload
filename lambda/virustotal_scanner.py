"""
Lambda function that computes SHA-256 of uploaded files and checks them against
the VirusTotal API. Returns a verdict indicating whether the file is malicious.

Supports two invocation modes:
  1. Direct invoke (from file router fallback): {"bucket":"...","key":"..."}
  2. EventBridge S3 Object Created: {"source":"aws.s3","detail":{"bucket":{"name":"..."},"object":{"key":"..."}}}

After scanning, tags the S3 object with VT results so the file router can read
them without a synchronous invoke.
"""

import hashlib
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

VIRUSTOTAL_API_KEY_SSM_PARAMETER = os.environ.get("VIRUSTOTAL_API_KEY_SSM_PARAMETER")
VIRUSTOTAL_THRESHOLD = int(os.environ.get("VIRUSTOTAL_THRESHOLD", "3"))

# Cached API key (fetched once at init, reused across warm invocations)
_api_key = None


def _get_api_key():
    """Retrieve VirusTotal API key from SSM Parameter Store (cached)."""
    global _api_key
    if _api_key is not None:
        return _api_key

    if not VIRUSTOTAL_API_KEY_SSM_PARAMETER:
        raise ValueError("VIRUSTOTAL_API_KEY_SSM_PARAMETER is not set")

    ssm = boto3.client("ssm")
    resp = ssm.get_parameter(
        Name=VIRUSTOTAL_API_KEY_SSM_PARAMETER, WithDecryption=True
    )
    _api_key = resp["Parameter"]["Value"]
    logger.info("VirusTotal API key retrieved from SSM Parameter Store")
    return _api_key


def _parse_event(event):
    """Extract bucket and key from either direct invoke or EventBridge S3 event."""
    if event.get("source") == "aws.s3":
        detail = event["detail"]
        bucket = detail["bucket"]["name"]
        key = urllib.parse.unquote_plus(detail["object"]["key"])
    else:
        bucket = event["bucket"]
        key = event["key"]
    return bucket, key


def _tag_object(bucket, key, result):
    """Tag the S3 object with VirusTotal scan results."""
    positives = result["positives"]
    if not result["found"]:
        status = "not-found"
    elif positives >= VIRUSTOTAL_THRESHOLD:
        status = "malicious"
    else:
        status = "clean"

    tags = [
        {"Key": "vt-status", "Value": status},
        {"Key": "vt-positives", "Value": str(positives)},
        {"Key": "vt-total", "Value": str(result["total"])},
        {"Key": "vt-sha256", "Value": result["sha256"]},
    ]

    try:
        s3.put_object_tagging(
            Bucket=bucket, Key=key, Tagging={"TagSet": tags}
        )
        logger.info("Tagged s3://%s/%s with VT results: status=%s", bucket, key, status)
    except Exception:
        logger.exception("Failed to tag s3://%s/%s with VT results", bucket, key)


def handler(event, context):
    """Download file from S3, compute SHA-256, query VirusTotal."""
    bucket, key = _parse_event(event)

    logger.info("Processing s3://%s/%s", bucket, key)

    # Download and hash the file
    response = s3.get_object(Bucket=bucket, Key=key)
    sha256_hash = hashlib.sha256()
    for chunk in iter(lambda: response["Body"].read(8192), b""):
        sha256_hash.update(chunk)
    file_hash = sha256_hash.hexdigest()
    file_size = response["ContentLength"]

    logger.info("SHA-256: %s, size: %d bytes", file_hash, file_size)

    # Query VirusTotal
    api_key = _get_api_key()
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "User-Agent": "TerraformSecureUpload/1.0 (virustotal-scanner)",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            permalink = data.get("data", {}).get("links", {}).get("self", "")

            logger.info(
                "VirusTotal result for %s: positives=%d, total=%d",
                file_hash,
                positives,
                total,
            )

            result = {
                "malicious": positives >= VIRUSTOTAL_THRESHOLD,
                "positives": positives,
                "total": total,
                "sha256": file_hash,
                "permalink": permalink,
                "found": True,
            }
            _tag_object(bucket, key, result)
            return result
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            logger.info("Hash %s not found in VirusTotal (treating as clean)", file_hash)
            result = {
                "malicious": False,
                "positives": 0,
                "total": 0,
                "sha256": file_hash,
                "permalink": "",
                "found": False,
            }
            _tag_object(bucket, key, result)
            return result
        logger.error("VirusTotal API error %s: %s", exc.code, exc.read().decode())
        raise
    except urllib.error.URLError as exc:
        logger.error("VirusTotal URL error: %s", exc.reason)
        raise
