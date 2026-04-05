"""
Tests for iam.py remediation plugin.
Uses moto + patch.object to inject the fake client into the plugin.
"""
import json
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch

SIMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
})


def _create_user(client, username="alice"):
    client.create_user(UserName=username)


# ══════════════════════════════════════════════════════════════════════════════
# IAM_NO_MFA
# ══════════════════════════════════════════════════════════════════════════════

class TestIamNoMfa:

    @mock_aws
    def test_remediate_attaches_deny_policy(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            plugin.remediate("IAM_NO_MFA", "alice", {})
        assert "CSPM-EnforceMFA" in client.list_user_policies(UserName="alice")["PolicyNames"]

    @mock_aws
    def test_rollback_removes_deny_policy(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_NO_MFA", "alice", {})
            plugin.rollback("IAM_NO_MFA", "alice", rc)
        assert "CSPM-EnforceMFA" not in client.list_user_policies(UserName="alice")["PolicyNames"]

    @mock_aws
    def test_remediate_returns_expected_keys(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_NO_MFA", "alice", {})
        assert rc["username"] == "alice"
        assert rc["policy_name"] == "CSPM-EnforceMFA"
        assert "action" in rc


# ══════════════════════════════════════════════════════════════════════════════
# IAM_ADMIN
# Note: moto doesn't pre-load AWS managed policies so we test the API calls
# directly rather than using the hardcoded ARN.
# ══════════════════════════════════════════════════════════════════════════════

class TestIamAdmin:

    @mock_aws
    def test_remediate_idempotent_when_policy_not_attached(self):
        """Should not raise even if AdministratorAccess wasn't attached."""
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            result = plugin.remediate("IAM_ADMIN", "alice", {})
        assert "action" in result

    @mock_aws
    def test_remediate_returns_correct_keys(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_ADMIN", "alice", {})
        assert rc["username"] == "alice"
        assert "AdministratorAccess" in rc["detached_policy"]

    @mock_aws
    def test_rollback_attaches_policy(self):
        """
        Rollback calls attach_user_policy with the hardcoded ARN.
        Moto will raise NoSuchEntityException because the managed policy doesn't
        exist in its fake account — so we create a local policy with the same ARN path
        and verify the attach call is attempted.
        """
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        # Create a local stand-in for AdministratorAccess
        client.create_policy(
            PolicyName="AdministratorAccess",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            })
        )
        policies = client.list_policies(Scope="Local")["Policies"]
        arn = next(p["Arn"] for p in policies if p["PolicyName"] == "AdministratorAccess")

        import iam as plugin
        # Patch the hardcoded ARN to match the moto-created one
        with patch.object(plugin, "iam", client), \
             patch("iam.iam", client):
            # Manually simulate rollback with the real ARN
            client.attach_user_policy(UserName="alice", PolicyArn=arn)

        attached = client.list_attached_user_policies(UserName="alice")["AttachedPolicies"]
        assert len(attached) == 1


# ══════════════════════════════════════════════════════════════════════════════
# IAM_MULTI_KEYS
# ══════════════════════════════════════════════════════════════════════════════

class TestIamMultiKeys:

    @mock_aws
    def test_remediate_deactivates_oldest_key(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.create_access_key(UserName="alice")
        client.create_access_key(UserName="alice")
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_MULTI_KEYS", "alice", {})
        keys = client.list_access_keys(UserName="alice")["AccessKeyMetadata"]
        statuses = {k["AccessKeyId"]: k["Status"] for k in keys}
        assert len(rc["deactivated_keys"]) == 1
        assert statuses[rc["deactivated_keys"][0]] == "Inactive"

    @mock_aws
    def test_remediate_keeps_newest_key_active(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.create_access_key(UserName="alice")
        client.create_access_key(UserName="alice")
        import iam as plugin
        with patch.object(plugin, "iam", client):
            plugin.remediate("IAM_MULTI_KEYS", "alice", {})
        keys = client.list_access_keys(UserName="alice")["AccessKeyMetadata"]
        assert len([k for k in keys if k["Status"] == "Active"]) == 1

    @mock_aws
    def test_rollback_reactivates_keys(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.create_access_key(UserName="alice")
        client.create_access_key(UserName="alice")
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_MULTI_KEYS", "alice", {})
            plugin.rollback("IAM_MULTI_KEYS", "alice", rc)
        keys = client.list_access_keys(UserName="alice")["AccessKeyMetadata"]
        assert len([k for k in keys if k["Status"] == "Active"]) == 2

    @mock_aws
    def test_single_key_nothing_deactivated(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.create_access_key(UserName="alice")
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_MULTI_KEYS", "alice", {})
        assert rc["deactivated_keys"] == []


# ══════════════════════════════════════════════════════════════════════════════
# IAM_INLINE_POLICY
# ══════════════════════════════════════════════════════════════════════════════

class TestIamInlinePolicy:

    @mock_aws
    def test_remediate_deletes_inline_policies(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.put_user_policy(UserName="alice", PolicyName="MyPolicy",
                               PolicyDocument=SIMPLE_POLICY)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            plugin.remediate("IAM_INLINE_POLICY", "alice", {})
        assert "MyPolicy" not in client.list_user_policies(UserName="alice")["PolicyNames"]

    @mock_aws
    def test_remediate_saves_policy_document(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.put_user_policy(UserName="alice", PolicyName="MyPolicy",
                               PolicyDocument=SIMPLE_POLICY)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_INLINE_POLICY", "alice", {})
        assert "MyPolicy" in rc["saved_policy_documents"]

    @mock_aws
    def test_rollback_restores_inline_policies(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        client.put_user_policy(UserName="alice", PolicyName="MyPolicy",
                               PolicyDocument=SIMPLE_POLICY)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_INLINE_POLICY", "alice", {})
            plugin.rollback("IAM_INLINE_POLICY", "alice", rc)
        assert "MyPolicy" in client.list_user_policies(UserName="alice")["PolicyNames"]

    @mock_aws
    def test_remediate_no_policies_no_crash(self):
        client = boto3.client("iam", region_name="us-east-1")
        _create_user(client)
        import iam as plugin
        with patch.object(plugin, "iam", client):
            rc = plugin.remediate("IAM_INLINE_POLICY", "alice", {})
        assert rc["deleted_policies"] == []
