import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock


class FileRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(
            {
                "INGRESS_BUCKET": "ingress-bucket",
                "CLEAN_BUCKET": "clean-bucket",
                "QUARANTINE_BUCKET": "quarantine-bucket",
                "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:topic",
                "KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/test",
            }
        )
        boto3_stub = types.SimpleNamespace(client=Mock())
        sys.modules["boto3"] = boto3_stub
        module_path = Path(__file__).with_name("file_router.py")
        spec = importlib.util.spec_from_file_location("file_router", module_path)
        cls.router = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.router)

    def setUp(self):
        self.router.s3 = Mock()
        self.router.sns = Mock()

    def test_routes_the_scanned_version_only(self):
        self.router.s3.head_object.return_value = {"ContentLength": 12}
        event = {
            "detail": {
                "scanStatus": "COMPLETED",
                "scanResultDetails": {"scanResultStatus": "NO_THREATS_FOUND"},
                "s3ObjectDetails": {
                    "bucketName": "ingress-bucket",
                    "objectKey": "uploads/file.bin",
                    "versionId": "version-a",
                },
            }
        }

        result = self.router.handler(event, None)

        self.router.s3.head_object.assert_called_once_with(
            Bucket="ingress-bucket", Key="uploads/file.bin", VersionId="version-a"
        )
        self.router.s3.copy_object.assert_called_once()
        copy_call = self.router.s3.copy_object.call_args.kwargs
        self.assertEqual(copy_call["CopySource"]["VersionId"], "version-a")
        self.router.s3.delete_object.assert_called_once_with(
            Bucket="ingress-bucket", Key="uploads/file.bin", VersionId="version-a"
        )
        self.assertEqual(result["statusCode"], 200)

    def test_rejects_scan_result_without_a_usable_version(self):
        event = {
            "detail": {
                "scanStatus": "COMPLETED",
                "scanResultDetails": {"scanResultStatus": "NO_THREATS_FOUND"},
                "s3ObjectDetails": {
                    "bucketName": "ingress-bucket",
                    "objectKey": "uploads/file.bin",
                },
            }
        }

        with self.assertRaisesRegex(ValueError, "usable object version ID"):
            self.router.handler(event, None)

        self.router.s3.head_object.assert_not_called()
        self.router.s3.copy_object.assert_not_called()
        self.router.s3.delete_object.assert_not_called()


if __name__ == "__main__":
    unittest.main()
