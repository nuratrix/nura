import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from common import decision_log
from pipeline import stream_triage

EIP = "884458154630#us-east-1#COST-EC2-004#eipalloc-1"


def record(seq, finding_id=EIP, severity="CRITICAL", event="INSERT"):
    return {"eventName": event, "dynamodb": {"SequenceNumber": seq, "NewImage": {
        "finding_id": {"S": finding_id}, "rule_id": {"S": "COST-EC2-004"}, "domain": {"S": "cost"},
        "account_id": {"S": "884458154630"}, "region": {"S": "us-east-1"},
        "resource_id": {"S": "eipalloc-1"}, "resource_type": {"S": "AWS::EC2::EIP"},
        "title": {"S": "Unused Elastic IP"},
        "severity": {"S": severity}, "recommendation": {"S": "Release it."},
        "estimated_monthly_saving": {"N": "3.6"}, "expires_at": {"N": "1800000000"},
        "evidence": {"M": {"associated": {"BOOL": False}}}}}}


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "us-east-1",
                 "DECISION_LOG_BUCKET": "decisionlog", "DECISION_LOG_RETENTION_DAYS": "1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        s3, sqs = boto3.client("s3"), boto3.client("sqs")
        s3.create_bucket(Bucket="decisionlog", ObjectLockEnabledForBucket=True)
        url = sqs.create_queue(QueueName="nura-high-critical")["QueueUrl"]
        monkeypatch.setenv("HIGH_CRITICAL_QUEUE_URL", url)
        monkeypatch.setattr(stream_triage, "_c", {})
        monkeypatch.setattr(decision_log, "_s3", None)
        yield s3, sqs, url
        monkeypatch.setattr(decision_log, "_s3", None)


def objects(s3):
    return [o["Key"] for o in s3.list_objects_v2(Bucket="decisionlog").get("Contents", [])]


def test_high_critical_queued_same_body_as_batch_triage(aws):
    s3, sqs, url = aws
    assert stream_triage.handler({"Records": [record("1")]}, None) == {"batchItemFailures": []}
    body = json.loads(sqs.receive_message(QueueUrl=url)["Messages"][0]["Body"])
    assert set(body) == {"finding_id", "rule_id", "domain", "severity", "recommendation", "requested_at"}
    assert body["finding_id"] == EIP and body["severity"] == "CRITICAL"
    assert objects(s3) == []                                   # agents write the decision, not triage


@pytest.mark.parametrize("severity", ["LOW", "MEDIUM"])
def test_low_medium_written_to_decision_log_not_queued(aws, severity):
    s3, sqs, url = aws
    assert stream_triage.handler({"Records": [record("1", severity=severity)]}, None) == {"batchItemFailures": []}
    assert "Messages" not in sqs.receive_message(QueueUrl=url)
    [key] = objects(s3)
    assert key.startswith("triage/") and "/884458154630/COST-EC2-004/eipalloc-1/" in key
    obj = s3.get_object(Bucket="decisionlog", Key=key)
    assert obj["ObjectLockMode"] == "GOVERNANCE"
    rec = json.loads(obj["Body"].read())
    assert rec["finding"]["estimated_monthly_saving"] == 3.6   # numbers, not "3.6" strings
    assert rec["finding"]["evidence"] == {"associated": False}


def test_stream_record_matches_batch_record(aws):
    """Inline Lambda copy and common.decision_log.write_triage must write the same shape."""
    s3, _, _ = aws
    stream_triage.handler({"Records": [record("1", severity="LOW")]}, None)
    finding = json.loads(s3.get_object(Bucket="decisionlog", Key=objects(s3)[0])["Body"].read())["finding"]
    decision_log.write_triage(finding)

    a, b = (json.loads(s3.get_object(Bucket="decisionlog", Key=k)["Body"].read()) for k in sorted(objects(s3)))
    for r in (a, b):
        r.pop("decided_at")
    assert a == b
    ka, kb = (k.rsplit("/", 1)[0] for k in objects(s3))
    assert ka == kb                                            # same key layout


def test_failure_checkpoints_at_the_failed_record(aws, monkeypatch):
    _, sqs, _ = aws
    real = stream_triage._client("sqs")
    calls = []

    class Flaky:
        def send_message(self, **kw):
            calls.append(kw)
            if len(calls) == 2:
                raise RuntimeError("throttled")
            return real.send_message(**kw)

    monkeypatch.setitem(stream_triage._c, "sqs", Flaky())
    out = stream_triage.handler({"Records": [record("1"), record("2", "b"), record("3", "c")]}, None)
    assert out == {"batchItemFailures": [{"itemIdentifier": "2"}]}   # 2 and 3 retried, 1 not resent
    assert len(calls) == 2


def test_fits_cloudformation_inline_limit():
    assert len(Path(stream_triage.__file__).read_text(encoding="utf-8")) < 4096
