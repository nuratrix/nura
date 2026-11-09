"""Publish decisions to the Findings SNS topic for human review, email and Teams.

Topic: env FINDINGS_TOPIC_ARN. The message is a compact summary plus a pointer to the
full record in the decision log; the tool-call digests stay in S3 (SNS max is 256 KB).

Subscribers filter on message attributes, e.g. a human-review queue:
    {"requires_human": ["true"]}
or an email digest of suppressions only:
    {"message_type": ["suppression"]}
"""
from __future__ import annotations

import json
import os

import boto3

_sns = None

# outcome -> message_type (resolutions, suppressions, escalations)
MESSAGE_TYPES = {
    "RESOLVED": "resolution", "NO_ACTION": "resolution",
    "SUPPRESSED": "suppression",
    "ESCALATED": "escalation", "DEFERRED": "escalation",
}


def _client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns", region_name=os.getenv("AWS_REGION", "us-east-1"))
    return _sns


def decision_message(finding: dict, decision: dict, record: dict) -> dict:
    execution = decision.get("execution") or {}
    return {
        "message_type": MESSAGE_TYPES.get(decision.get("outcome"), "resolution"),
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "account_id": finding.get("account_id"),
        "region": finding.get("region"),
        "resource": {"type": finding.get("resource_type"), "id": finding.get("resource_id")},
        "estimated_monthly_saving": finding.get("estimated_monthly_saving"),
        "outcome": decision.get("outcome"),
        "actions": decision.get("actions"),
        "requires_human": decision.get("requires_human", False),
        "execution": {k: execution.get(k) for k in ("mode", "action", "remediation", "reason")},
        "reason": decision.get("reason"),
        "overruled": [{k: o.get(k) for k in ("agent", "action", "rule_id", "reason")}
                      for o in decision.get("overruled") or []],
        "observations": decision.get("observations") or [],
        "decision_record": f"s3://{record['bucket']}/{record['key']}",
        "trace_id": decision.get("trace_id"),
    }


def _subject(msg: dict) -> str:
    flag = "[ACTION NEEDED] " if msg["requires_human"] else ""
    s = f"{flag}{msg['severity']} {msg['outcome']}: {msg['title']} ({msg['resource']['id']})"
    return s[:100]   # SNS subject limit


def publish_decision(finding: dict, decision: dict, record: dict) -> str:
    """Publish a decision summary. Returns the SNS MessageId."""
    msg = decision_message(finding, decision, record)
    attrs = {
        "message_type": msg["message_type"],
        "outcome": msg["outcome"] or "UNKNOWN",
        "severity": msg["severity"] or "UNKNOWN",
        "requires_human": "true" if msg["requires_human"] else "false",
        "execution_mode": msg["execution"]["mode"] or "NONE",
        "domain": finding.get("domain") or "unknown",
        "account_id": msg["account_id"] or "unknown",
    }
    resp = _client().publish(
        TopicArn=os.environ["FINDINGS_TOPIC_ARN"],
        Subject=_subject(msg),
        Message=json.dumps(msg, indent=2, default=str),
        MessageAttributes={k: {"DataType": "String", "StringValue": v} for k, v in attrs.items()},
    )
    return resp["MessageId"]
