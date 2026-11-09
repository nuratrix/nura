"""Context tools read the finding from invocation_state; AWS clients are stubbed."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from agents.tools.context import cloudtrail, finding_context, tags

FINDING = {"finding_id": "x", "rule_id": "COST-EC2-003", "account_id": "222222222222",
           "region": "eu-west-1", "resource_type": "AWS::EC2::Volume", "resource_id": "vol-1"}


def ctx(finding=FINDING):
    return SimpleNamespace(invocation_state={"finding": finding} if finding else {})


class FakeSession:
    def __init__(self, clients):
        self.clients, self.created = clients, []

    def client(self, name, region_name=None):
        self.created.append((name, region_name))
        return self.clients[name]


@pytest.fixture
def session(monkeypatch):
    holder = {}

    def install(**clients):
        s = FakeSession(clients)
        holder["finding"] = None

        def fake(finding):
            holder["finding"] = finding
            return s
        monkeypatch.setattr(tags, "finding_session", fake)
        monkeypatch.setattr(cloudtrail, "finding_session", fake)
        return s, holder
    return install


def test_arn_built_from_finding():
    assert finding_context.resource_arn(FINDING) == "arn:aws:ec2:eu-west-1:222222222222:volume/vol-1"
    assert finding_context.resource_arn({**FINDING, "resource_type": "AWS::S3::Bucket",
                                         "resource_id": "b"}) == "arn:aws:s3:::b"
    assert finding_context.resource_arn({**FINDING, "resource_type": "AWS::IAM::RootAccount"}) is None


def test_tools_refuse_without_finding():
    with pytest.raises(finding_context.NoFindingContext):
        tags.get_resource_tags(tool_context=ctx(None))


def test_tags_uses_finding_resource(session):
    calls = []
    tagging = SimpleNamespace(get_resources=lambda **kw: calls.append(kw) or {"ResourceTagMappingList": [
        {"Tags": [{"Key": "Environment", "Value": "prod"}, {"Key": "Name", "Value": "data"}]}]})
    s, holder = session(resourcegroupstaggingapi=tagging)

    out = tags.get_resource_tags(tool_context=ctx())
    assert holder["finding"] is FINDING
    assert calls == [{"ResourceARNList": ["arn:aws:ec2:eu-west-1:222222222222:volume/vol-1"]}]
    assert out["notable_tags"] == {"Environment": "prod"}


def test_tags_error_is_returned_not_raised(session):
    def boom(**kw):
        raise RuntimeError("AccessDenied")
    session(resourcegroupstaggingapi=SimpleNamespace(get_resources=boom))
    assert "AccessDenied" in tags.get_resource_tags(tool_context=ctx())["error"]


def _event(name, read_only, user="alice"):
    return {"EventName": name, "EventTime": datetime(2026, 11, 4, tzinfo=timezone.utc), "Username": user,
            "CloudTrailEvent": json.dumps({"readOnly": read_only, "sourceIPAddress": "1.2.3.4"})}


def test_cloudtrail_filters_read_only_and_uses_finding(session):
    calls = []
    ct = SimpleNamespace(lookup_events=lambda **kw: calls.append(kw) or {
        "Events": [_event("DetachVolume", False), _event("DescribeVolumes", True)]})
    s, _ = session(cloudtrail=ct)

    out = cloudtrail.get_recent_activity(tool_context=ctx(), days=500)
    assert calls[0]["LookupAttributes"] == [{"AttributeKey": "ResourceName", "AttributeValue": "vol-1"}]
    assert s.created == [("cloudtrail", "eu-west-1")]
    assert out["days"] == 90                       # clamped
    assert [e["event"] for e in out["events"]] == ["DetachVolume"]
    assert out["last_event"]["user"] == "alice"


def test_cloudtrail_global_resources_use_us_east_1(session):
    s, _ = session(cloudtrail=SimpleNamespace(lookup_events=lambda **kw: {"Events": []}))
    out = cloudtrail.get_recent_activity(
        tool_context=ctx({**FINDING, "resource_type": "AWS::IAM::User", "resource_id": "bob"}))
    assert s.created == [("cloudtrail", "us-east-1")] and out["event_count"] == 0
