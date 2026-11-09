import boto3
from moto import mock_aws

from common import findings_repo
from common.models import Finding

EIP = "884458154630#us-east-1#COST-EC2-004#eipalloc-052066d5ae713256d"


def test_get_finding_from_local_file(monkeypatch):
    monkeypatch.delenv("FINDINGS_TABLE", raising=False)
    assert findings_repo.get_finding(EIP)["rule_id"] == "COST-EC2-004"
    assert findings_repo.get_finding("nope") is None


def test_get_finding_from_dynamodb(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "us-east-1",
                 "FINDINGS_TABLE": "Findings"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        monkeypatch.setattr(findings_repo, "_table", None)
        boto3.client("dynamodb").create_table(
            TableName="Findings", BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}])
        findings_repo.put_findings([Finding(
            rule_id="COST-EC2-004", domain="cost", account_id="884458154630", region="us-east-1",
            resource_id="eipalloc-1", resource_type="AWS::EC2::EIP", severity="CRITICAL",
            title="Unused Elastic IP", recommendation="Release it.", estimated_monthly_saving=3.6)])

        item = findings_repo.get_finding("884458154630#us-east-1#COST-EC2-004#eipalloc-1")
        assert item["severity"] == "CRITICAL" and item["estimated_monthly_saving"] == 3.6
        assert findings_repo.get_finding("missing") is None
        monkeypatch.setattr(findings_repo, "_table", None)
