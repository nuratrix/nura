"""Tags of the finding's resource: ownership, environment, approved exceptions."""
from __future__ import annotations

from strands import ToolContext, tool

from agents.tools.context.finding_context import current_finding, finding_session, resource_arn

# Tag keys (lower-cased) the agents care about, surfaced separately so the model sees them first.
NOTABLE = {"env", "environment", "stage", "owner", "team", "cost-center", "costcenter",
           "application", "app", "project", "data-classification", "backup", "retention",
           "do-not-delete", "nura:exception", "nura:approved-change", "change-ticket"}


@tool(context=True)
def get_resource_tags(tool_context: ToolContext) -> dict:
    """Get the tags on the resource this finding is about (environment, owner, exceptions).

    Takes no arguments: the resource, account and region come from the finding under review.
    """
    finding = current_finding(tool_context)
    arn = resource_arn(finding)
    if arn is None:
        return {"resource_id": finding["resource_id"], "tags": {},
                "note": f"{finding['resource_type']} has no taggable ARN; no tags to read."}

    client = finding_session(finding).client("resourcegroupstaggingapi")
    try:
        resp = client.get_resources(ResourceARNList=[arn])
    except Exception as e:  # access denied, unsupported type, throttling
        return {"resource_arn": arn, "error": f"{type(e).__name__}: {e}"}

    mappings = resp.get("ResourceTagMappingList", [])
    if not mappings:
        return {"resource_arn": arn, "tags": {},
                "note": "No tags found (untagged, deleted, or a type the tagging API doesn't cover)."}

    tags = {t["Key"]: t["Value"] for t in mappings[0].get("Tags", [])}
    notable = {k: v for k, v in tags.items() if k.lower() in NOTABLE}
    return {"resource_arn": arn, "notable_tags": notable, "tags": tags}


TAG_TOOLS = [get_resource_tags]
