"""Security context tools with stubbed AWS clients: no AWS calls."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from agents.subagents import security_agent
from agents.tools.context import cloudtrail, security
from agents.tools.context.finding_context import NoFindingContext

ACCT = "111122223333"
NOW = datetime.now(timezone.utc)


def finding(rtype, rid, **kw):
    return {"finding_id": "x", "rule_id": "SEC-X", "account_id": ACCT, "region": "us-east-1",
            "resource_type": rtype, "resource_id": rid, **kw}


def ctx(f):
    return SimpleNamespace(invocation_state={"finding": f} if f else {})


def err(code):
    def raise_(**_):
        raise ClientError({"Error": {"Code": code, "Message": "m"}}, "Op")
    return raise_


def client(**methods):
    return SimpleNamespace(**methods)


@pytest.fixture
def aws(monkeypatch):
    """Install fake clients by service name; returns the dict so a test can add more."""
    clients = {}
    session = SimpleNamespace(client=lambda name, region_name=None: clients[name])
    monkeypatch.setattr(security, "finding_session", lambda f: session)
    monkeypatch.setattr(cloudtrail, "finding_session", lambda f: session)
    return clients


# ---------------------------------------------------------------- policy analysis

def test_summarize_policy_separates_public_conditional_and_cross_account():
    doc = {"Statement": [
        {"Sid": "Public", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
        {"Sid": "Vpce", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*",
         "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}},
        {"Sid": "Partner", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
         "Action": ["s3:GetObject"]},
        {"Sid": "Own", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:role/app"}, "Action": "*"},
        {"Sid": "Svc", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject"},
        {"Sid": "Deny", "Effect": "Deny", "Principal": "*", "Action": "*"},
    ]}
    s = security.summarize_policy(doc, ACCT)
    assert s["public_unconditional"] and s["public_with_condition"]
    assert s["external_accounts"] == ["999988887777"]           # own account is not external
    assert s["service_principals"] == ["cloudtrail.amazonaws.com"]
    assert [g["sid"] for g in s["grants"]] == ["Public", "Vpce", "Partner"]
    assert s["grants"][1]["condition_keys"] == ["aws:SourceVpce"]


def test_is_admin():
    assert security._is_admin({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert not security._is_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})


# ---------------------------------------------------------------- 1. resource policy

def test_s3_public_bucket_and_partial_failure(aws):
    aws["s3"] = client(
        get_public_access_block=err("NoSuchPublicAccessBlockConfiguration"),
        get_bucket_policy_status=lambda **_: {"PolicyStatus": {"IsPublic": True}},
        get_bucket_policy=lambda **_: {"Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'},
        get_bucket_acl=err("AccessDenied"))
    aws["s3control"] = client(get_public_access_block=lambda **_: {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "BlockPublicPolicy": False}})
    out = security.get_resource_policy(tool_context=ctx(finding("AWS::S3::Bucket", "data-bucket")))
    assert out["bucket_public_access_block"] == {}               # absent = nothing blocked at bucket level
    assert out["account_public_access_block"]["BlockPublicPolicy"] is False
    assert out["policy_is_public"] is True and out["policy"]["public_unconditional"]
    assert out["public_acl_grants"] is None                      # unknown, not "none"
    assert len(out["errors"]) == 1 and out["errors"][0].startswith("GetBucketAcl: AccessDenied")


def test_lambda_without_policy_but_public_url(aws):
    aws["lambda"] = client(get_policy=err("ResourceNotFoundException"),
                           list_function_url_configs=lambda **_: {"FunctionUrlConfigs": [
                               {"AuthType": "NONE", "FunctionUrl": "https://x.lambda-url"}]})
    out = security.get_resource_policy(tool_context=ctx(finding("AWS::Lambda::Function", "fn")))
    assert out["policy"] == "none" and out["function_urls"][0]["auth_type"] == "NONE"


def test_public_rds_snapshot(aws):
    aws["rds"] = client(describe_db_snapshot_attributes=lambda **_: {"DBSnapshotAttributesResult": {
        "DBSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": ["all"]}]}})
    out = security.get_resource_policy(tool_context=ctx(finding("AWS::RDS::DBSnapshot", "snap")))
    assert out["public"] is True


def test_unsupported_type_says_so(aws):
    out = security.get_resource_policy(tool_context=ctx(finding("AWS::CloudTrail::Trail", "t")))
    assert "no resource policy" in out["note"] and out["errors"] == []


# ---------------------------------------------------------------- 2. network exposure

def test_security_group_open_and_in_use(aws):
    aws["ec2"] = client(
        describe_security_groups=lambda **_: {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}]},
        describe_network_interfaces=lambda **_: {"NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1", "Attachment": {"InstanceId": "i-1"},
             "Association": {"PublicIp": "3.3.3.3"}}]})
    out = security.get_network_exposure(tool_context=ctx(finding("AWS::EC2::SecurityGroup", "sg-1")))
    assert out["open_ingress"] == [
        {"group_id": "sg-1", "protocol": "tcp", "ports": "22-22", "source": "0.0.0.0/0"},
        {"group_id": "sg-1", "protocol": "all", "ports": "all", "source": "::/0"}]
    assert out["in_use"] is True and out["used_by"][0]["public_ip"] == "3.3.3.3"


def test_public_rds_instance(aws):
    aws["rds"] = client(describe_db_instances=lambda **_: {"DBInstances": [{
        "DBInstanceStatus": "available", "PubliclyAccessible": True, "StorageEncrypted": False,
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db"}]}]})
    aws["ec2"] = client(describe_security_groups=lambda **_: {"SecurityGroups": [{"GroupId": "sg-db", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]})
    out = security.get_network_exposure(tool_context=ctx(finding("AWS::RDS::DBInstance", "db1")))
    assert out["publicly_accessible"] is True and out["open_ingress"][0]["ports"] == "5432-5432"


# ---------------------------------------------------------------- 3. principal access

def test_iam_user_admin_through_group_no_mfa_old_key(aws):
    aws["iam"] = client(
        get_user=lambda **_: {"User": {"PasswordLastUsed": NOW - timedelta(days=200)}},
        list_attached_user_policies=lambda **_: {"AttachedPolicies": []},
        list_user_policies=lambda **_: {"PolicyNames": []},
        get_user_policy=lambda **_: pytest.fail("no inline policies to read"),
        list_groups_for_user=lambda **_: {"Groups": [{"GroupName": "admins"}]},
        list_attached_group_policies=lambda **_: {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]},
        get_login_profile=lambda **_: {"LoginProfile": {}},
        list_mfa_devices=lambda **_: {"MFADevices": []},
        list_access_keys=lambda **_: {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": NOW - timedelta(days=400)}]},
        get_access_key_last_used=lambda **_: {"AccessKeyLastUsed": {"LastUsedDate": NOW - timedelta(days=3),
                                                                     "ServiceName": "s3"}})
    out = security.get_principal_access(tool_context=ctx(finding("AWS::IAM::User", f"arn:aws:iam::{ACCT}:user/alice")))
    assert out["is_admin"] and out["groups"] == ["admins"] and out["console_access"] is True
    assert out["mfa_devices"] == 0 and out["password_last_used_days"] == 200
    assert out["access_keys"][0] == {"key_id": "AKIA1", "status": "Active", "age_days": 400,
                                     "last_used_days": 3, "last_service": "s3"}


def test_role_trust_allows_external_account(aws):
    aws["iam"] = client(
        get_role=lambda **_: {"Role": {"RoleLastUsed": {}, "AssumeRolePolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::444455556666:root"}, "Action": "sts:AssumeRole"}]}}},
        list_attached_role_policies=lambda **_: {"AttachedPolicies": []},
        list_role_policies=lambda **_: {"PolicyNames": ["inline"]},
        get_role_policy=lambda **_: {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}})
    out = security.get_principal_access(tool_context=ctx(finding("AWS::IAM::Role", "app-role")))
    assert out["is_admin"] is True                               # via inline */*
    assert out["trust"]["external_accounts"] == ["444455556666"] and out["last_used_days"] is None


def test_deleted_user_is_reported_not_guessed(aws):
    aws["iam"] = client(get_user=err("NoSuchEntity"))
    out = security.get_principal_access(tool_context=ctx(finding("AWS::IAM::User", "gone")))
    assert "not found" in out["note"]


def test_root_account_summary(aws):
    aws["iam"] = client(get_account_summary=lambda **_: {"SummaryMap": {"AccountMFAEnabled": 0,
                                                                         "AccountAccessKeysPresent": 1}},
                        get_account_password_policy=err("NoSuchEntity"))
    out = security.get_principal_access(tool_context=ctx(finding("AWS::IAM::RootAccount", "root")))
    assert out["root_mfa_enabled"] is False and out["root_access_keys_present"] is True
    assert out["password_policy"] == "none"


# ---------------------------------------------------------------- 4. existing detections

def test_signals_guardduty_findings_and_services_not_enabled(aws):
    calls = {}
    aws["guardduty"] = client(
        list_detectors=lambda **_: {"DetectorIds": ["det-1"]},
        list_findings=lambda **kw: calls.setdefault("criteria", kw["FindingCriteria"]) and {"FindingIds": ["gd-1"]},
        get_findings=lambda **_: {"Findings": [{"Type": "CryptoCurrency:EC2/BitcoinTool.B!DNS", "Severity": 8,
                                                "Title": "Bitcoin", "Service": {"Count": 12},
                                                "UpdatedAt": (NOW - timedelta(days=1)).isoformat()}]})
    aws["securityhub"] = client(get_findings=err("InvalidAccessException"))
    aws["accessanalyzer"] = client(list_analyzers=lambda **_: {"analyzers": []})
    out = security.get_security_signals(tool_context=ctx(finding("AWS::EC2::Instance", "i-1")))
    assert calls["criteria"]["Criterion"]["resource.instanceDetails.instanceId"] == {"Eq": ["i-1"]}
    assert out["guardduty"][0]["type"].startswith("CryptoCurrency") and out["guardduty"][0]["updated_days"] == 1
    assert out["security_hub"] == "not enabled" and out["access_analyzer"] == "not enabled"
    assert out["errors"] == []


def test_signals_access_analyzer_on_bucket(aws):
    aws["guardduty"] = client(list_detectors=lambda **_: {"DetectorIds": []})
    aws["securityhub"] = client(get_findings=lambda **kw: {"Findings": [
        {"Title": "S3.2", "Severity": {"Label": "CRITICAL"}, "ProductName": "Security Hub"}]})
    aws["accessanalyzer"] = client(
        list_analyzers=lambda **_: {"analyzers": [{"arn": "arn:aa", "status": "ACTIVE"}]},
        list_findings_v2=lambda **kw: {"findings": [{"findingType": "ExternalAccess", "status": "ACTIVE"}]})
    out = security.get_security_signals(tool_context=ctx(finding("AWS::S3::Bucket", "b")))
    assert out["guardduty"] == "not enabled"
    assert out["security_hub"][0]["severity"] == "CRITICAL"
    assert out["access_analyzer"][0]["type"] == "ExternalAccess"


# ---------------------------------------------------------------- shared rules

@pytest.mark.parametrize("tool", security.SECURITY_TOOLS)
def test_tools_refuse_without_finding(tool):
    with pytest.raises(NoFindingContext):
        tool(tool_context=ctx(None))


def test_cloudtrail_looks_up_events_by_root(aws):
    seen = {}
    aws["cloudtrail"] = client(lookup_events=lambda **kw: seen.update(kw) or {"Events": []})
    out = cloudtrail.get_recent_activity(tool_context=ctx(finding("AWS::IAM::RootAccount", "root")))
    assert seen["LookupAttributes"] == [{"AttributeKey": "Username", "AttributeValue": "root"}]
    assert out["lookup"] == "Username=root"


def test_security_agent_wires_its_tools():
    names = {t.tool_name for t in security.SECURITY_TOOLS}
    assert names == {"get_resource_policy", "get_network_exposure", "get_principal_access", "get_security_signals"}
    assert callable(security_agent.build_agent)
    assert "CLOSE_PATH" in security_agent.SYSTEM_PROMPT and "needs_review" in security_agent.SYSTEM_PROMPT
