import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from common import decision_log, notify

FINDING = {"finding_id": "884458154630#us-east-1#COST-EC2-004#eipalloc-1", "rule_id": "COST-EC2-004",
           "domain": "cost", "account_id": "884458154630", "region": "us-east-1",
           "resource_type": "AWS::EC2::EIP", "resource_id": "eipalloc-1", "severity": "HIGH",
           "title": "Unassociated Elastic IP", "estimated_monthly_saving": 3.6}
SYNTHESIS = {"trace_id": "ab" * 16, "opinions": [{"agent": "cost-agent", "action": "DELETE",
                                                  "tool_calls": [{"tool": "get_resource_tags"}]}]}
DECISION = {"outcome": "RESOLVED", "actions": ["DELETE"], "requires_human": True, "trace_id": "ab" * 16,
            "observations": [{"agent": "cost-agent", "type": "data_quality", "detail": "no tags"}],
            "overruled": [],
            "execution": {"mode": "APPROVAL", "action": "DELETE", "remediation": "release_elastic_ip",
                          "reason": "rule requires approval before remediation"}}


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1", "AWS_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        monkeypatch.setattr(decision_log, "_s3", None)
        monkeypatch.setattr(notify, "_sns", None)
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="decisionlog", ObjectLockEnabledForBucket=True)

        sns, sqs = boto3.client("sns"), boto3.client("sqs")
        topic = sns.create_topic(Name="Findings")["TopicArn"]
        q = sqs.create_queue(QueueName="review")["QueueUrl"]
        q_arn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn,
                      Attributes={"FilterPolicy": json.dumps({"requires_human": ["true"]})})
        monkeypatch.setenv("FINDINGS_TOPIC_ARN", topic)
        yield s3, sqs, q


def test_decision_written_locked_and_complete(aws):
    s3, _, _ = aws
    rec = decision_log.write_decision(FINDING, SYNTHESIS, DECISION)
    assert rec["key"].startswith("decisions/") and "/884458154630/COST-EC2-004/eipalloc-1/" in rec["key"]

    obj = s3.get_object(Bucket="decisionlog", Key=rec["key"])
    assert obj["ObjectLockMode"] == "GOVERNANCE"
    body = json.loads(obj["Body"].read())
    assert body["decision"]["execution"]["mode"] == "APPROVAL"
    assert body["synthesis"]["opinions"][0]["tool_calls"]   # digest kept in the audit record
    assert body["trace_id"] == "ab" * 16


def test_locked_record_cannot_be_deleted(aws):
    s3, _, _ = aws
    rec = decision_log.write_decision(FINDING, SYNTHESIS, DECISION)
    version = s3.head_object(Bucket="decisionlog", Key=rec["key"])["VersionId"]
    with pytest.raises(ClientError):
        s3.delete_object(Bucket="decisionlog", Key=rec["key"], VersionId=version)


def test_each_decision_gets_its_own_record(aws):
    a = decision_log.write_decision(FINDING, SYNTHESIS, DECISION)
    b = decision_log.write_decision(FINDING, SYNTHESIS, DECISION)
    assert a["key"] != b["key"]


def test_publish_reaches_filtered_subscriber(aws):
    _, sqs, q = aws
    rec = {"bucket": "decisionlog", "key": "decisions/x.json"}
    notify.publish_decision(FINDING, DECISION, rec)

    msgs = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10)["Messages"]
    envelope = json.loads(msgs[0]["Body"])
    assert envelope["Subject"].startswith("[ACTION NEEDED] HIGH RESOLVED")
    assert envelope["MessageAttributes"]["execution_mode"]["Value"] == "APPROVAL"
    msg = json.loads(envelope["Message"])
    assert msg["message_type"] == "resolution"
    assert msg["decision_record"] == "s3://decisionlog/decisions/x.json"
    assert msg["observations"][0]["type"] == "data_quality"
    assert "tool_calls" not in json.dumps(msg)            # digests stay in S3


def test_filter_policy_skips_decisions_without_human(aws):
    _, sqs, q = aws
    notify.publish_decision(FINDING, {**DECISION, "requires_human": False}, {"bucket": "b", "key": "k"})
    assert "Messages" not in sqs.receive_message(QueueUrl=q)


@pytest.mark.parametrize("outcome,kind", [("SUPPRESSED", "suppression"), ("ESCALATED", "escalation"),
                                          ("DEFERRED", "escalation"), ("NO_ACTION", "resolution")])
def test_message_types(outcome, kind):
    msg = notify.decision_message(FINDING, {**DECISION, "outcome": outcome}, {"bucket": "b", "key": "k"})
    assert msg["message_type"] == kind


def test_subject_capped_at_100():
    long = {**FINDING, "title": "x" * 300}
    msg = notify.decision_message(long, DECISION, {"bucket": "b", "key": "k"})
    assert len(notify._subject(msg)) == 100
