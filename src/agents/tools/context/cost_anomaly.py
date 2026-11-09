"""Cost anomaly context: what AWS Cost Anomaly Detection saw, and where the spend moved.

Cost Explorer is global (us-east-1) and bills $0.01 per API request, so these tools make few,
aggregated calls. The account comes from the finding: in a member account Cost Explorer
shows that account's spend; in the management account it shows the organization's, so the
breakdown is always filtered to the finding's linked account.
"""
from __future__ import annotations

from datetime import date, timedelta

from strands import ToolContext, tool

from agents.tools.context.aws_calls import ABSENT, MAX_ITEMS, call, ok, result
from agents.tools.context.finding_context import current_finding, finding_session

GROUP_BY = {"SERVICE", "USAGE_TYPE", "REGION", "LINKED_ACCOUNT", "OPERATION"}
# Short names scanners use -> Cost Explorer SERVICE values (searched only when not listed here).
SERVICE_ALIASES = {
    "amazon ec2": "Amazon Elastic Compute Cloud - Compute", "ec2": "Amazon Elastic Compute Cloud - Compute",
    "amazon rds": "Amazon Relational Database Service", "rds": "Amazon Relational Database Service",
    "amazon s3": "Amazon Simple Storage Service", "s3": "Amazon Simple Storage Service",
    "aws lambda": "AWS Lambda", "lambda": "AWS Lambda", "amazon cloudwatch": "AmazonCloudWatch",
    "amazon dynamodb": "Amazon DynamoDB", "amazon vpc": "Amazon Virtual Private Cloud",
}


def _ce(f):
    return finding_session(f).client("ce", region_name="us-east-1")


def _anomaly(a: dict) -> dict:
    impact = a.get("Impact", {})
    return {"id": a.get("AnomalyId"), "start": a.get("AnomalyStartDate"), "end": a.get("AnomalyEndDate"),
            "dimension": a.get("DimensionValue"), "total_impact_usd": impact.get("TotalImpact"),
            "max_daily_impact_usd": impact.get("MaxImpact"), "expected_usd": impact.get("TotalExpectedSpend"),
            "actual_usd": impact.get("TotalActualSpend"), "impact_pct": impact.get("TotalImpactPercentage"),
            "feedback": a.get("Feedback"),
            "root_causes": [{k: rc.get(k) for k in ("Service", "Region", "LinkedAccount", "UsageType")}
                            for rc in a.get("RootCauses", [])[:5]]}


@tool(context=True)
def get_anomaly_details(tool_context: ToolContext) -> dict:
    """AWS Cost Anomaly Detection facts for the finding.

    Anomaly finding: the anomaly's dates, expected vs actual spend, impact, root causes
    (service, region, account, usage type) and any feedback already given (e.g. marked
    "PLANNED_ACTIVITY"). Spike findings: anomalies AWS detected in the last 14 days, to see
    whether AWS also flagged it. Monitor / subscription findings: the monitors and alert
    subscriptions that exist, their thresholds and subscribers.
    Takes no arguments: the anomaly and account come from the finding under review.
    """
    f = current_finding(tool_context)
    rtype, rid, errors = f["resource_type"], f["resource_id"], []
    ce = _ce(f)

    if rtype in ("AWS::CostExplorer::AnomalyMonitor", "AWS::CostExplorer::AnomalySubscription"):
        mons = call(errors, "GetAnomalyMonitors", ce.get_anomaly_monitors)
        subs = call(errors, "GetAnomalySubscriptions", ce.get_anomaly_subscriptions)
        return result(f, errors,
                      monitors=None if mons is None else [
                          {"name": m.get("MonitorName"), "type": m.get("MonitorType"),
                           "dimension": m.get("MonitorDimension"), "last_evaluated": m.get("LastEvaluatedDate")}
                          for m in mons.get("AnomalyMonitors", [])],
                      subscriptions=None if subs is None else [
                          {"name": x.get("SubscriptionName"), "frequency": x.get("Frequency"),
                           "threshold": x.get("ThresholdExpression") or x.get("Threshold"),
                           "subscriber_types": sorted({y.get("Type") for y in x.get("Subscribers", [])}),
                           "monitors": len(x.get("MonitorArnList", []))}
                          for x in subs.get("AnomalySubscriptions", [])])

    days = 90 if rtype == "AWS::CostExplorer::Anomaly" else 14
    resp = call(errors, "GetAnomalies", ce.get_anomalies, MaxResults=100,
                DateInterval={"StartDate": (date.today() - timedelta(days=days)).isoformat(),
                              "EndDate": date.today().isoformat()})
    anomalies = [_anomaly(a) for a in ok(resp).get("Anomalies", [])]
    if rtype == "AWS::CostExplorer::Anomaly":
        match = next((a for a in anomalies if a["id"] and (a["id"] == rid or a["id"].endswith(rid))), None)
        return result(f, errors, anomaly=match,
                      note=None if match or resp is None else f"anomaly {rid} not found in the last {days} days")
    return result(f, errors, days=days, anomalies_detected=None if resp is None else len(anomalies),
                  anomalies=sorted(anomalies, key=lambda a: -(a["total_impact_usd"] or 0))[:MAX_ITEMS])


def _resolve_service(ce, name: str | None, errors: list) -> str | None:
    """Findings say 'Amazon EC2'; Cost Explorer says 'Amazon Elastic Compute Cloud - Compute'."""
    if not name:
        return None
    if name.lower() in SERVICE_ALIASES:
        return SERVICE_ALIASES[name.lower()]
    end = date.today()
    resp = call(errors, "GetDimensionValues", ce.get_dimension_values, Dimension="SERVICE", SearchString=name,
                TimePeriod={"Start": (end - timedelta(days=30)).isoformat(), "End": end.isoformat()})
    values = [v["Value"] for v in ok(resp).get("DimensionValues", [])]
    return next((v for v in values if v == name), values[0] if values else None)


@tool(context=True)
def get_spend_breakdown(tool_context: ToolContext, group_by: str = "USAGE_TYPE", days: int = 14) -> dict:
    """Daily spend for the finding's account, split to show where an increase came from.

    Filtered to the finding's account and, when the finding names them, its service and
    region. Returns the daily totals, and for each group the average daily spend in the
    last 3 days vs the days before, sorted by the size of the increase.

    Args:
        group_by: SERVICE, USAGE_TYPE (default), REGION, LINKED_ACCOUNT or OPERATION.
        days: How far back to look, 7-60.
    """
    f = current_finding(tool_context)
    errors, ev = [], f.get("evidence") or {}
    group_by = group_by.upper() if group_by.upper() in GROUP_BY else "USAGE_TYPE"
    days = max(7, min(int(days), 60))
    ce = _ce(f)

    filters = [{"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [f["account_id"]]}}]
    service = _resolve_service(ce, ev.get("service") or ev.get("service_name"), errors)
    if service:
        filters.append({"Dimensions": {"Key": "SERVICE", "Values": [service]}})
    if ev.get("region") and group_by != "REGION":
        filters.append({"Dimensions": {"Key": "REGION", "Values": [ev["region"]]}})
    end = date.today()
    resp = call(errors, "GetCostAndUsage", ce.get_cost_and_usage,
                TimePeriod={"Start": (end - timedelta(days=days)).isoformat(), "End": end.isoformat()},
                Granularity="DAILY", Metrics=["UnblendedCost"],
                Filter=filters[0] if len(filters) == 1 else {"And": filters},
                GroupBy=[{"Type": "DIMENSION", "Key": group_by}], absent=("DataUnavailableException",))
    if resp is ABSENT or resp is None:
        return result(f, errors, note="no cost data" if resp is ABSENT else None)

    by_day = resp.get("ResultsByTime", [])
    daily = [round(sum(float(g["Metrics"]["UnblendedCost"]["Amount"]) for g in d.get("Groups", [])), 2)
             for d in by_day]
    recent, before = by_day[-3:], by_day[:-3]
    groups: dict[str, list[float]] = {}
    for i, d in enumerate(by_day):
        for g in d.get("Groups", []):
            groups.setdefault(g["Keys"][0], [0.0] * len(by_day))[i] = float(g["Metrics"]["UnblendedCost"]["Amount"])

    def avg(xs):
        return round(sum(xs) / len(xs), 2) if xs else 0.0

    movers = sorted(({"group": k, "recent_daily_usd": avg(v[-len(recent):]),
                      "baseline_daily_usd": avg(v[:len(before)]),
                      "increase_daily_usd": round(avg(v[-len(recent):]) - avg(v[:len(before)]), 2)}
                     for k, v in groups.items()), key=lambda m: -m["increase_daily_usd"])
    return result(f, errors, account=f["account_id"], service=service, region=ev.get("region"),
                  group_by=group_by, days=days, dates=[d["TimePeriod"]["Start"] for d in by_day],
                  daily_total_usd=daily, top_movers=movers[:8],
                  note=None if service or not ev.get("service") else f"service '{ev.get('service')}' not matched; "
                                                                       "showing all services")


COST_ANOMALY_TOOLS = [get_anomaly_details, get_spend_breakdown]
