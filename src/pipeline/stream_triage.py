"""Findings DynamoDB stream -> triage. HIGH/CRITICAL: nura-high-critical queue (agents).
LOW/MEDIUM: locked triage record in the decision log (no agents).
Inlined by deploy/deploy_intake.ps1 (CloudFormation ZipFile): keep under 4 KB, boto3 only.
The event filter (judgment-intake.yaml) passes new findings and escalations into HIGH/CRITICAL
only, so rescans that just bump last_seen_at never reach this code. Message body = triage.py's;
record = common.decision_log.write_triage's (tests/test_stream_triage.py checks both).
"""
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeDeserializer

log = logging.getLogger()
log.setLevel(logging.INFO)
_c = {}
FIELDS = ("finding_id", "rule_id", "domain", "severity", "recommendation")


def _client(name):
    if name not in _c:
        _c[name] = boto3.client(name)
    return _c[name]


def _plain(v):
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (list, set)):
        return [_plain(x) for x in v]
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    return v


def message(f):
    return {**{k: f[k] for k in FIELDS if k in f},
            "requested_at": datetime.now(timezone.utc).isoformat()}


def triage_record(f):
    now = datetime.now(timezone.utc)
    safe = lambda s: str(s).replace("/", "_").replace("#", "_")
    key = (f"triage/{now:%Y/%m/%d}/{safe(f.get('account_id'))}/{safe(f.get('rule_id'))}/"
           f"{safe(f.get('resource_id'))}/{now:%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}.json")
    record = {"schema_version": "1.0", "record_type": "triage", "decided_at": now.isoformat(),
              "finding_id": f.get("finding_id"), "finding": f, "decision": {
                  "outcome": "LOGGED", "actions": [], "requires_human": False,
                  "recommendation": f.get("recommendation"),
                  "reason": f"{f.get('severity')} finding: recorded with its catalog recommendation; "
                            "not sent to the judgment agents (HIGH/CRITICAL only)."}}
    _client("s3").put_object(
        Bucket=os.environ["DECISION_LOG_BUCKET"], Key=key,
        Body=json.dumps(record, indent=2, default=str).encode(), ContentType="application/json",
        IfNoneMatch="*", ObjectLockMode=os.environ.get("DECISION_LOG_LOCK_MODE", "GOVERNANCE"),
        ObjectLockRetainUntilDate=now + timedelta(days=int(os.environ["DECISION_LOG_RETENTION_DAYS"])),
        ChecksumAlgorithm="SHA256")
    return key


def handler(event, context):
    des = TypeDeserializer()
    for record in event["Records"]:
        try:
            img = record["dynamodb"]["NewImage"]
            f = _plain({k: des.deserialize(v) for k, v in img.items()})
            if f.get("severity") in ("HIGH", "CRITICAL"):
                _client("sqs").send_message(QueueUrl=os.environ["HIGH_CRITICAL_QUEUE_URL"],
                                            MessageBody=json.dumps(message(f)))
                done = {"queued": f["finding_id"]}
            else:
                done = {"logged": f.get("finding_id"), "key": triage_record(f)}
            log.info(json.dumps({**done, "severity": f.get("severity"), "event": record["eventName"]}))
        except Exception:
            # Stream checkpoint: this record and everything after it are retried, in order.
            log.exception("triage failed for stream record %s", record["dynamodb"].get("SequenceNumber"))
            return {"batchItemFailures": [{"itemIdentifier": record["dynamodb"]["SequenceNumber"]}]}
    return {"batchItemFailures": []}
