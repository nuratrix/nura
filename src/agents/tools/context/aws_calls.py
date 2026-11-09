"""Shared plumbing for the context tools.

Every tool makes several independent read-only AWS calls. One denied, missing or throttled
call must not hide the others, so each goes through call(): failures are recorded in the
tool's `errors` list and the tool carries on. An error code that means "not configured"
(no bucket policy, no password policy) is returned as ABSENT: that is a fact, not a failure.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

MAX_ITEMS = 10
ABSENT = object()   # the thing asked for isn't configured / doesn't exist


def call(errors: list, label: str, fn, *args, absent: tuple = (), **kwargs):
    """Run one AWS call. Returns the response, ABSENT for an error code meaning
    'not configured', or None after recording the failure in `errors`."""
    try:
        return fn(*args, **kwargs)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in absent:
            return ABSENT
        errors.append(f"{label}: {code or type(e).__name__}: {e.response.get('Error', {}).get('Message', '')}")
    except Exception as e:  # noqa: BLE001 - endpoint, throttling, parameter errors
        errors.append(f"{label}: {type(e).__name__}: {e}")
    return None


def ok(resp) -> dict:
    """A response usable as a dict: {} for a failed or ABSENT call."""
    return resp if isinstance(resp, dict) else {}


def now() -> datetime:
    return datetime.now(timezone.utc)


def ago(**delta) -> datetime:
    return now() - timedelta(**delta)


def days_since(ts) -> int | None:
    if not ts:
        return None
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now() - ts).days


def iso(ts) -> str | None:
    return ts.isoformat() if hasattr(ts, "isoformat") else ts


def as_list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def name_of(resource_id: str) -> str:
    """Last path segment of an ARN (user/role names), or the id itself."""
    return resource_id.rsplit("/", 1)[-1] if resource_id.startswith("arn:") else resource_id


def result(finding: dict, errors: list, **facts) -> dict:
    return {"resource_type": finding["resource_type"], "resource_id": finding["resource_id"],
            **facts, "errors": errors}


def not_covered(finding: dict, tool_name: str, hint: str = "") -> dict:
    return result(finding, [], note=f"{tool_name} reads nothing for {finding['resource_type']}. {hint}".strip())
