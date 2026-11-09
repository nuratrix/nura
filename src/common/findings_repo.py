"""Findings table access (governance account).

Table: env FINDINGS_TABLE. Key: finding_id = account#region#rule#resource.
Each save sets last_seen_at and pushes expires_at out TTL_DAYS; first_seen_at is
kept from the first save. A finding that stops being detected is not deleted:
it stays until its TTL lapses, so readers filter on last_seen_at for "current".
"""
import json
import os
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from common.models import Finding

import boto3
from boto3.dynamodb.conditions import Key

TTL_DAYS = 90
_table = None
FIELDS = set(Finding.__dataclass_fields__)
DEFAULT_FILE = Path(__file__).resolve().parents[2] / "data" / "sample_findings.json"


def _findings_table():
    global _table
    if _table is None:
        _table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    return _table


def _to_dynamo(value):
    """floats -> Decimal (DynamoDB rejects float)."""
    return json.loads(json.dumps(value, default=str), parse_float=Decimal)


def _from_dynamo(value):
    """Decimal -> int/float so callers can json.dumps the result."""
    if isinstance(value, list):
        return [_from_dynamo(v) for v in value]
    if isinstance(value, dict):
        return {k: _from_dynamo(v) for k, v in value.items()}
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def put_findings(findings):
    """Upsert Finding objects; returns how many were written."""
    table = _findings_table()
    for f in findings:
        item = _to_dynamo(f.to_item())
        finding_id = item.pop("finding_id")
        seen_at = item.pop("detected_at")
        item["last_seen_at"] = seen_at
        item["expires_at"] = int(
            (datetime.fromisoformat(seen_at) + timedelta(days=TTL_DAYS)).timestamp())
        names = {f"#{k}": k for k in item}
        values = {f":{k}": v for k, v in item.items()}
        values[":first"] = seen_at
        table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in item)
                             + ", #first_seen_at = if_not_exists(#first_seen_at, :first)",
            ExpressionAttributeNames={**names, "#first_seen_at": "first_seen_at"},
            ExpressionAttributeValues=values)
    return len(findings)


def _to_finding(item):
    # Drop finding_id and DynamoDB-only extras (last_seen_at, expires_at, ...)
    return Finding(**{k: v for k, v in item.items() if k in FIELDS})


def get_findings(source=None):
    """Returns (findings, errors). source: path to a JSON file, or 'dynamodb'."""
    source = source or os.environ.get("FINDINGS_SOURCE", str(DEFAULT_FILE))
    if source == "dynamodb":
        table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
        items, kwargs = [], {}
        while True:
            page = table.scan(**kwargs)
            items += page["Items"]
            if "LastEvaluatedKey" not in page:
                break
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
        from common.findings_repo import _from_dynamo
        items = _from_dynamo(items)
    else:
        items = json.loads(Path(source).read_text(encoding="utf-8"))

    findings, errors = [], []
    for item in items:
        try:
            findings.append(_to_finding(item))
        except TypeError as e:
            errors.append(f"{item.get('finding_id', '?')}: {e}")
    return findings, errors



def get_finding(finding_id):
    """One finding as a dict, or None. DynamoDB when FINDINGS_TABLE is set (AgentCore,
    Lambda); otherwise the local JSON file (FINDINGS_SOURCE or data/sample_findings.json)."""
    if os.environ.get("FINDINGS_TABLE"):
        item = _findings_table().get_item(Key={"finding_id": finding_id}).get("Item")
        return _from_dynamo(item) if item else None
    source = os.environ.get("FINDINGS_SOURCE", str(DEFAULT_FILE))
    items = json.loads(Path(source).read_text(encoding="utf-8"))
    return next((i for i in items if i.get("finding_id") == finding_id), None)


def _query(index, key, value, since=None):
    cond = Key(key).eq(value)
    if since:
        cond = cond & Key("last_seen_at").gte(since)
    kwargs = {"IndexName": index, "KeyConditionExpression": cond, "ScanIndexForward": False}
    items = []
    while True:
        resp = _findings_table().query(**kwargs)
        items += resp["Items"]
        if "LastEvaluatedKey" not in resp:
            return _from_dynamo(items)
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def findings_for_account(account_id, since=None):
    """Newest first. `since`: ISO timestamp, e.g. the start of the last scan."""
    return _query("by-account", "account_id", account_id, since)


def findings_by_severity(severity, since=None):
    return _query("by-severity", "severity", severity, since)


def findings_for_resource(resource_id, since=None):
    return _query("by-resource", "resource_id", resource_id, since)
