"""Decision log: WORM audit record of every decision, in S3 with Object Lock.

Bucket: env DECISION_LOG_BUCKET (default "decisionlog"). The bucket has Object Lock
enabled but no default retention, so every object is locked explicitly here:
DECISION_LOG_LOCK_MODE (GOVERNANCE | COMPLIANCE, default GOVERNANCE) for
DECISION_LOG_RETENTION_DAYS (default 2555, ~7 years). No lifecycle expiry: no TTL.

Records are never overwritten: each decision gets its own key, and the PUT is
conditional (If-None-Match), so a retry or clash fails instead of replacing evidence.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import boto3

SCHEMA_VERSION = "1.0"
_s3 = None


def _client():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


PREFIXES = {"decision": "decisions", "triage": "triage"}   # agent judgments vs. LOW/MEDIUM


def decision_key(finding: dict, decided_at: datetime, record_type: str = "decision") -> str:
    """<prefix>/YYYY/MM/DD/<account>/<rule_id>/<resource_id>/<timestamp>-<uuid>.json"""
    safe = lambda s: str(s).replace("/", "_").replace("#", "_")
    return (f"{PREFIXES[record_type]}/{decided_at:%Y/%m/%d}/{safe(finding.get('account_id'))}/"
            f"{safe(finding.get('rule_id'))}/{safe(finding.get('resource_id'))}/"
            f"{decided_at:%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}.json")


def _write(record_type: str, finding: dict, body: dict) -> dict:
    """Write one locked, immutable record. Returns {"bucket", "key", "retain_until"}."""
    bucket = os.getenv("DECISION_LOG_BUCKET", "decisionlog")
    decided_at = datetime.now(timezone.utc)
    retain_until = decided_at + timedelta(days=int(os.getenv("DECISION_LOG_RETENTION_DAYS", "2555")))
    key = decision_key(finding, decided_at, record_type)

    record = {
        "schema_version": SCHEMA_VERSION,
        "record_type": record_type,
        "decided_at": decided_at.isoformat(),
        "finding_id": finding.get("finding_id"),
        **body,
    }
    _client().put_object(
        Bucket=bucket, Key=key,
        Body=json.dumps(record, indent=2, default=str).encode("utf-8"),
        ContentType="application/json",
        IfNoneMatch="*",                                   # never overwrite an existing record
        ObjectLockMode=os.getenv("DECISION_LOG_LOCK_MODE", "GOVERNANCE"),
        ObjectLockRetainUntilDate=retain_until,
        ChecksumAlgorithm="SHA256",                        # Object Lock PUTs require a checksum
    )
    return {"bucket": bucket, "key": key, "retain_until": retain_until.isoformat()}


def write_decision(finding: dict, synthesis: dict, decision: dict) -> dict:
    """Agent judgment of a HIGH/CRITICAL finding, under decisions/."""
    return _write("decision", finding, {
        "trace_id": synthesis.get("trace_id"),
        "finding": finding,
        "synthesis": synthesis,     # every opinion, observation and tool-call digest
        "decision": decision,
    })


# --- triage (LOW / MEDIUM) -------------------------------------------------
# Deterministic: no agents, no LLM. The record keeps the finding and the scanner's
# catalog recommendation, so every finding Nura ever raised is in the WORM log.
# src/pipeline/stream_triage.py writes the same record shape inline (boto3 only).

def triage_decision(finding: dict) -> dict:
    return {
        "outcome": "LOGGED",
        "actions": [],
        "requires_human": False,
        "recommendation": finding.get("recommendation"),
        "reason": f"{finding.get('severity')} finding: recorded with its catalog recommendation; "
                  "not sent to the judgment agents (HIGH/CRITICAL only).",
    }


def write_triage(finding: dict) -> dict:
    """LOW/MEDIUM finding, under triage/."""
    return _write("triage", finding, {"finding": finding, "decision": triage_decision(finding)})


def save_findings_2_decisionlog(findings) -> list[dict]:
    """Batch triage: one triage record per Finding. Returns the written {"bucket", "key", ...}."""
    return [write_triage(f.to_item()) for f in findings]
