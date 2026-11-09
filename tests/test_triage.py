import json

import boto3
import pytest
from moto import mock_aws

from common import decision_log
from pipeline.triage import triage


@pytest.fixture
def sqs_queue(monkeypatch):
    """Fake SQS queue + Object Lock decisionlog bucket, in memory for the duration of the test."""
    # Fake credentials so boto3 never touches your real AWS account
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("DECISION_LOG_BUCKET", "decisionlog")
    with mock_aws():
        monkeypatch.setattr(decision_log, "_s3", None)
        boto3.client("s3").create_bucket(Bucket="decisionlog", ObjectLockEnabledForBucket=True)
        sqs = boto3.client("sqs")
        url = sqs.create_queue(QueueName="high-critical-findings")["QueueUrl"]
        monkeypatch.setenv("High_Critical_Queue_Url", url)
        yield sqs, url
        monkeypatch.setattr(decision_log, "_s3", None)


def read_all_messages(sqs, url):
    messages = []
    while True:
        batch = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10).get("Messages", [])
        if not batch:
            return messages
        messages += [json.loads(m["Body"]) for m in batch]


def test_triage_splits_by_severity(sqs_queue):
    assert triage() == {"logged": 26, "queued": 24, "errors": 0}


def test_high_and_critical_land_in_sqs(sqs_queue):
    sqs, url = sqs_queue
    triage()
    messages = read_all_messages(sqs, url)

    assert len(messages) == 24
    assert {m["severity"] for m in messages} == {"HIGH", "CRITICAL"}
    assert len({m["finding_id"] for m in messages}) == 24   # no duplicates
    assert {"finding_id", "rule_id", "domain", "severity",
            "recommendation", "requested_at"} <= messages[0].keys()


def test_low_and_medium_land_in_decision_log(sqs_queue):
    triage()
    s3 = boto3.client("s3")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="decisionlog")["Contents"]]
    assert len(keys) == 26 and all(k.startswith("triage/") for k in keys)   # never under decisions/

    obj = s3.get_object(Bucket="decisionlog", Key=keys[0])
    assert obj["ObjectLockMode"] == "GOVERNANCE"
    record = json.loads(obj["Body"].read())
    assert record["record_type"] == "triage"
    assert record["finding"]["severity"] in ("LOW", "MEDIUM")
    assert record["decision"]["outcome"] == "LOGGED"
    assert record["decision"]["recommendation"] == record["finding"]["recommendation"]
    assert record["finding_id"] == record["finding"]["finding_id"]
