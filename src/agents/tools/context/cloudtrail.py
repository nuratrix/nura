"""Recent CloudTrail management events on the finding's resource: who touched it, and when."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from strands import ToolContext, tool

from agents.tools.context.finding_context import current_finding, finding_session

MAX_EVENTS = 50
# IAM and other global services log to us-east-1.
GLOBAL_TYPES = ("AWS::IAM::", "AWS::Organizations::")


@tool(context=True)
def get_recent_activity(tool_context: ToolContext, days: int = 30, include_read_only: bool = False) -> dict:
    """Get recent CloudTrail management events on the resource this finding is about.

    The resource, account and region come from the finding under review. Use this to see
    whether the resource is still in use, was changed recently, and by whom.

    Args:
        days: How far back to look, 1-90 (CloudTrail event history keeps 90 days).
        include_read_only: Also return read-only events (Describe*/Get*/List*). Default False.
    """
    finding = current_finding(tool_context)
    days = max(1, min(int(days), 90))
    region = "us-east-1" if finding["resource_type"].startswith(GLOBAL_TYPES) else finding["region"]
    client = finding_session(finding).client("cloudtrail", region_name=region)

    end = datetime.now(timezone.utc)
    kwargs = {"LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": finding["resource_id"]}],
              "StartTime": end - timedelta(days=days), "EndTime": end, "MaxResults": MAX_EVENTS}
    events, scanned = [], 0
    try:
        while len(events) < MAX_EVENTS:
            resp = client.lookup_events(**kwargs)
            for e in resp.get("Events", []):
                scanned += 1
                detail = json.loads(e.get("CloudTrailEvent") or "{}")
                read_only = detail.get("readOnly", str(e.get("ReadOnly", "")).lower() == "true")
                if read_only and not include_read_only:
                    continue
                events.append({
                    "time": e["EventTime"].isoformat() if hasattr(e["EventTime"], "isoformat") else e["EventTime"],
                    "event": e.get("EventName"),
                    "user": e.get("Username") or detail.get("userIdentity", {}).get("arn"),
                    "source_ip": detail.get("sourceIPAddress"),
                    "read_only": read_only,
                    "error": detail.get("errorCode"),
                })
            if "NextToken" not in resp:
                break
            kwargs["NextToken"] = resp["NextToken"]
    except Exception as e:  # access denied, throttling (LookupEvents allows 2 calls/s)
        return {"resource_id": finding["resource_id"], "region": region, "error": f"{type(e).__name__}: {e}"}

    events = events[:MAX_EVENTS]
    return {
        "resource_id": finding["resource_id"], "region": region, "days": days,
        "event_count": len(events), "events_scanned": scanned,
        "last_event": events[0] if events else None,   # LookupEvents returns newest first
        "events": events,
        "note": None if events else f"No {'' if include_read_only else 'write '}events in the last {days} days.",
    }


CLOUDTRAIL_TOOLS = [get_recent_activity]
