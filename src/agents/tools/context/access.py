"""Access Analyzer context: what external or unused access exists, and what is actually used.

security.get_principal_access says how powerful an identity is and when it was last used;
this module adds Access Analyzer's own view (analyzers, the external-access finding's
details) and IAM's service-last-accessed data: which granted services an identity has
really called. Read-only; the resource comes from the finding under review.
"""
from __future__ import annotations

import time

from strands import ToolContext, tool

from agents.tools.context.aws_calls import ABSENT, MAX_ITEMS, call, days_since, iso, name_of, ok, result
from agents.tools.context.finding_context import current_finding, finding_session

POLL_SECONDS, POLL_TRIES = 1.0, 10


def _analyzers(aa, errors) -> list[dict] | None:
    resp = call(errors, "ListAnalyzers", aa.list_analyzers)
    if resp is None:
        return None
    out = []
    for a in resp.get("analyzers", []):
        rules = call(errors, "ListArchiveRules", aa.list_archive_rules, analyzerName=a["name"])
        out.append({"name": a["name"], "arn": a["arn"], "type": a.get("type"), "status": a.get("status"),
                    "archive_rules": None if rules is None else len(rules.get("archiveRules", []))})
    return out


@tool(context=True)
def get_analyzer_findings(tool_context: ToolContext) -> dict:
    """IAM Access Analyzer's view of the finding.

    Analyzer finding: who outside the zone of trust can reach the resource (principal,
    actions, conditions, public or not, the policy that grants it), status and dates.
    Analyzer finding type "missing analyzer": analyzers in this region, their type (account
    or organization, external or unused access) and archive rules. An organization analyzer
    in the management or delegated-admin account covers member accounts even when the member
    has none of its own.
    Takes no arguments: the finding id and account come from the finding under review.
    """
    f = current_finding(tool_context)
    rtype, rid, errors = f["resource_type"], f["resource_id"], []
    aa = finding_session(f).client("accessanalyzer")
    analyzers = _analyzers(aa, errors)

    if rtype != "AWS::AccessAnalyzer::Finding":
        active = [a for a in analyzers or [] if a["status"] == "ACTIVE"]
        return result(f, errors, analyzers=analyzers,
                      external_access_analyzer=None if analyzers is None else
                      any(a["type"] in ("ACCOUNT", "ORGANIZATION") for a in active),
                      unused_access_analyzer=None if analyzers is None else
                      any(a["type"].endswith("UNUSED_ACCESS") for a in active))

    finding_id = name_of(rid)
    for a in analyzers or []:
        resp = call(errors, f"GetFindingV2 {a['name']}", aa.get_finding_v2, analyzerArn=a["arn"], id=finding_id,
                    absent=("ResourceNotFoundException", "ValidationException"))
        if not isinstance(resp, dict):
            continue
        details = []
        for d in resp.get("findingDetails", [])[:MAX_ITEMS]:
            ext = d.get("externalAccessDetails")
            if ext:
                details.append({"principal": ext.get("principal"), "actions": (ext.get("action") or [])[:MAX_ITEMS],
                                "condition": ext.get("condition"), "is_public": ext.get("isPublic"),
                                "granted_by": [s.get("type") for s in ext.get("sources", [])]})
            else:   # unused-access finding detail types
                kind, body = next(iter(d.items()), (None, {}))
                details.append({"kind": kind, "service": (body or {}).get("serviceNamespace"),
                                "last_accessed": iso((body or {}).get("lastAccessed"))})
        return result(f, errors, analyzer=a["name"], status=resp.get("status"), finding_type=resp.get("findingType"),
                      resource=resp.get("resource"), resource_type_aa=resp.get("resourceType"),
                      resource_owner=resp.get("resourceOwnerAccount"),
                      created_days_ago=days_since(resp.get("createdAt")),
                      updated_days_ago=days_since(resp.get("updatedAt")), details=details)
    return result(f, errors, analyzers=analyzers,
                  note=None if analyzers is None else f"finding {finding_id} not found in any analyzer (resolved or archived?)")


def _principal_arn(f, iam, errors) -> str | None:
    rtype, rid, acct = f["resource_type"], f["resource_id"], f["account_id"]
    if rid.startswith("arn:"):
        return rid
    if rtype == "AWS::IAM::Role":
        return f"arn:aws:iam::{acct}:role/{rid}"
    if rtype == "AWS::IAM::User":
        return f"arn:aws:iam::{acct}:user/{rid}"
    if rtype == "AWS::IAM::AccessKey":
        user = ok(call(errors, "GetAccessKeyLastUsed", iam.get_access_key_last_used, AccessKeyId=rid)).get("UserName")
        return f"arn:aws:iam::{acct}:user/{user}" if user else None
    return None


@tool(context=True)
def get_service_last_accessed(tool_context: ToolContext) -> dict:
    """Which AWS services an IAM role or user is allowed to use, and which it actually used.

    From IAM's service-last-accessed data (tracked for up to 400 days): services granted,
    services used with how many days ago, and how many granted services were never used. For
    an access key the key's user is analysed. An identity that uses one service of fifty is a
    least-privilege candidate even if it is not unused.
    Takes no arguments: the identity comes from the finding under review.
    """
    f = current_finding(tool_context)
    errors = []
    iam = finding_session(f).client("iam")
    arn = _principal_arn(f, iam, errors)
    if not arn:
        return result(f, errors, note=f"{f['resource_type']} is not an IAM role, user or access key")
    job = call(errors, "GenerateServiceLastAccessedDetails", iam.generate_service_last_accessed_details, Arn=arn,
               absent=("NoSuchEntity",))
    if job is ABSENT:
        return result(f, errors, principal=arn, note="identity not found (deleted?)")
    if job is None:
        return result(f, errors, principal=arn)
    resp = None
    for _ in range(POLL_TRIES):
        resp = call(errors, "GetServiceLastAccessedDetails", iam.get_service_last_accessed_details,
                    JobId=job["JobId"])
        if resp is None or resp.get("JobStatus") != "IN_PROGRESS":
            break
        time.sleep(POLL_SECONDS)
    if resp is None or resp.get("JobStatus") != "COMPLETED":
        return result(f, errors, principal=arn, note=f"report not ready ({(resp or {}).get('JobStatus')})")
    services = resp.get("ServicesLastAccessed", [])
    used = sorted(({"service": s["ServiceNamespace"], "days_ago": days_since(s.get("LastAuthenticated"))}
                   for s in services if s.get("LastAuthenticated")), key=lambda s: s["days_ago"])
    return result(f, errors, principal=arn, services_granted=len(services), services_used=len(used),
                  never_used=len(services) - len(used), most_recent=used[:MAX_ITEMS],
                  tracking_note="IAM tracks service access for up to 400 days.")


ACCESS_TOOLS = [get_analyzer_findings, get_service_last_accessed]
