"""
Tests for sg.py remediation plugin.
Uses moto + patch.object to inject the fake client into the plugin.
"""
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch


# ── Helpers ────────────────────────────────────────────────────────────────────

def _create_vpc_and_sg(client):
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg_id = client.create_security_group(
        GroupName="test-sg", Description="test", VpcId=vpc["VpcId"]
    )["GroupId"]
    return sg_id


def _add_ssh_rule(client, sg_id):
    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    )


def _add_all_traffic_rule(client, sg_id):
    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    )


def _ingress_rules(client, sg_id):
    return client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissions"]


# ══════════════════════════════════════════════════════════════════════════════
# SG_OPEN_SSH
# ══════════════════════════════════════════════════════════════════════════════

class TestSgOpenSsh:

    @mock_aws
    def test_remediate_removes_ssh_rule(self):
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        _add_ssh_rule(client, sg_id)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            plugin.remediate("SG_OPEN_SSH", sg_id, {})
        rules = _ingress_rules(client, sg_id)
        ssh_open = any(
            r.get("FromPort") == 22 and
            any(ip["CidrIp"] == "0.0.0.0/0" for ip in r.get("IpRanges", []))
            for r in rules
        )
        assert not ssh_open

    @mock_aws
    def test_rollback_restores_ssh_rule(self):
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        _add_ssh_rule(client, sg_id)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            rc = plugin.remediate("SG_OPEN_SSH", sg_id, {})
            plugin.rollback("SG_OPEN_SSH", sg_id, rc)
        rules = _ingress_rules(client, sg_id)
        ssh_open = any(
            r.get("FromPort") == 22 and
            any(ip["CidrIp"] == "0.0.0.0/0" for ip in r.get("IpRanges", []))
            for r in rules
        )
        assert ssh_open

    @mock_aws
    def test_remediate_no_rules_no_crash(self):
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            rc = plugin.remediate("SG_OPEN_SSH", sg_id, {})
        assert rc["removed_rules"] == []


# ══════════════════════════════════════════════════════════════════════════════
# SG_OPEN_ALL
# ══════════════════════════════════════════════════════════════════════════════

class TestSgOpenAll:

    @mock_aws
    def test_remediate_removes_all_traffic_rule(self):
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        _add_all_traffic_rule(client, sg_id)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            plugin.remediate("SG_OPEN_ALL", sg_id, {})
        rules = _ingress_rules(client, sg_id)
        all_open = any(
            r.get("IpProtocol") == "-1" and
            any(ip["CidrIp"] == "0.0.0.0/0" for ip in r.get("IpRanges", []))
            for r in rules
        )
        assert not all_open

    @mock_aws
    def test_rollback_restores_all_traffic_rule(self):
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        _add_all_traffic_rule(client, sg_id)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            rc = plugin.remediate("SG_OPEN_ALL", sg_id, {})
            plugin.rollback("SG_OPEN_ALL", sg_id, rc)
        rules = _ingress_rules(client, sg_id)
        all_open = any(
            r.get("IpProtocol") == "-1" and
            any(ip["CidrIp"] == "0.0.0.0/0" for ip in r.get("IpRanges", []))
            for r in rules
        )
        assert all_open

    @mock_aws
    def test_remediate_returns_removed_rule_count(self):
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        _add_all_traffic_rule(client, sg_id)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            rc = plugin.remediate("SG_OPEN_ALL", sg_id, {})
        assert len(rc["removed_rules"]) == 1

    @mock_aws
    def test_open_all_does_not_remove_ssh_rule(self):
        """SG_OPEN_ALL targets protocol=-1 only, not port-specific rules."""
        client = boto3.client("ec2", region_name="us-east-1")
        sg_id = _create_vpc_and_sg(client)
        _add_ssh_rule(client, sg_id)
        _add_all_traffic_rule(client, sg_id)
        import sg as plugin
        with patch.object(plugin, "ec2", client):
            plugin.remediate("SG_OPEN_ALL", sg_id, {})
        rules = _ingress_rules(client, sg_id)
        assert any(r.get("FromPort") == 22 for r in rules)
