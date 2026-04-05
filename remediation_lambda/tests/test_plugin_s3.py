"""
Tests for s3.py remediation plugin.
Uses moto + patch.object to inject the fake client into the plugin.
"""
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch


def _make_bucket(client, name="test-bucket"):
    client.create_bucket(Bucket=name)
    return name


# ══════════════════════════════════════════════════════════════════════════════
# S3_NO_ENCRYPTION
# ══════════════════════════════════════════════════════════════════════════════

class TestS3NoEncryption:

    @mock_aws
    def test_remediate_enables_aes256(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            plugin.remediate("S3_NO_ENCRYPTION", "test-bucket", {})
        enc = client.get_bucket_encryption(Bucket="test-bucket")
        algo = enc["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        assert algo == "AES256"

    @mock_aws
    def test_remediate_returns_correct_action(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            result = plugin.remediate("S3_NO_ENCRYPTION", "test-bucket", {})
        assert "AES256" in result["action"]
        assert result["bucket"] == "test-bucket"

    @mock_aws
    def test_rollback_removes_encryption_when_none_before(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            rc = plugin.remediate("S3_NO_ENCRYPTION", "test-bucket", {})
            assert rc["old_encryption"] is None
            plugin.rollback("S3_NO_ENCRYPTION", "test-bucket", rc)
        with pytest.raises(Exception):
            client.get_bucket_encryption(Bucket="test-bucket")

    @mock_aws
    def test_rollback_restores_existing_encryption(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        client.put_bucket_encryption(
            Bucket="test-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        )
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            rc = plugin.remediate("S3_NO_ENCRYPTION", "test-bucket", {})
            plugin.rollback("S3_NO_ENCRYPTION", "test-bucket", rc)
        enc = client.get_bucket_encryption(Bucket="test-bucket")
        assert enc["ServerSideEncryptionConfiguration"] is not None


# ══════════════════════════════════════════════════════════════════════════════
# S3_NO_VERSIONING
# ══════════════════════════════════════════════════════════════════════════════

class TestS3NoVersioning:

    @mock_aws
    def test_remediate_enables_versioning(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            plugin.remediate("S3_NO_VERSIONING", "test-bucket", {})
        assert client.get_bucket_versioning(Bucket="test-bucket").get("Status") == "Enabled"

    @mock_aws
    def test_rollback_suspends_versioning(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            rc = plugin.remediate("S3_NO_VERSIONING", "test-bucket", {})
            assert rc["old_status"] == "Never enabled"
            plugin.rollback("S3_NO_VERSIONING", "test-bucket", rc)
        status = client.get_bucket_versioning(Bucket="test-bucket").get("Status")
        assert status in ("Suspended", None, "")


# ══════════════════════════════════════════════════════════════════════════════
# S3_BLOCK_PUBLIC_DISABLED
# ══════════════════════════════════════════════════════════════════════════════

class TestS3BlockPublic:

    @mock_aws
    def test_remediate_enables_all_four_flags(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            plugin.remediate("S3_BLOCK_PUBLIC_DISABLED", "test-bucket", {})
        # moto uses get_public_access_block (not get_bucket_public_access_block)
        cfg = client.get_public_access_block(Bucket="test-bucket")["PublicAccessBlockConfiguration"]
        assert cfg["BlockPublicAcls"]       is True
        assert cfg["IgnorePublicAcls"]      is True
        assert cfg["BlockPublicPolicy"]     is True
        assert cfg["RestrictPublicBuckets"] is True

    @mock_aws
    def test_rollback_restores_previous_config(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        client.put_public_access_block(
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False, "IgnorePublicAcls": False,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
            }
        )
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            rc = plugin.remediate("S3_BLOCK_PUBLIC_DISABLED", "test-bucket", {})
            plugin.rollback("S3_BLOCK_PUBLIC_DISABLED", "test-bucket", rc)
        cfg = client.get_public_access_block(Bucket="test-bucket")["PublicAccessBlockConfiguration"]
        assert cfg["BlockPublicAcls"]   is False
        assert cfg["BlockPublicPolicy"] is False


# ══════════════════════════════════════════════════════════════════════════════
# S3_PUBLIC_ACL
# ══════════════════════════════════════════════════════════════════════════════

class TestS3PublicAcl:

    @mock_aws
    def test_remediate_sets_acl_private(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            result = plugin.remediate("S3_PUBLIC_ACL", "test-bucket", {})
        assert "private" in result["action"]
        assert result["bucket"] == "test-bucket"

    @mock_aws
    def test_remediate_saves_old_grants(self):
        client = boto3.client("s3", region_name="us-east-1")
        _make_bucket(client)
        import s3 as plugin
        with patch.object(plugin, "s3", client):
            rc = plugin.remediate("S3_PUBLIC_ACL", "test-bucket", {})
        assert "old_grants" in rc
        assert isinstance(rc["old_grants"], list)
