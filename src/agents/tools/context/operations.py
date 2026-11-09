"""Operational context: is the resource healthy, is it used, and what changed recently.

Shared by the incident, infrastructure and cost-anomaly agents. Like every context tool,
the resource, account and region come from the finding under review, never from the model,
and every call is read-only. Log tools return counts, never log lines: logs can hold
customer data.
"""
from __future__ import annotations

import json
import re

from strands import ToolContext, tool

from agents.tools.context.aws_calls import (ABSENT, MAX_ITEMS, ago, call, days_since, iso, name_of, now, ok,
                                            result)
from agents.tools.context.finding_context import current_finding, finding_session

# ---------------------------------------------------------------- metrics

# resource_type -> (namespace, dimension name, [(metric, statistic)])
METRICS: dict[str, tuple[str, str, list[tuple[str, str]]]] = {
    "AWS::EC2::Instance": ("AWS/EC2", "InstanceId", [
        ("CPUUtilization", "Average"), ("CPUUtilization", "Maximum"), ("NetworkIn", "Sum"),
        ("NetworkOut", "Sum"), ("StatusCheckFailed", "Maximum")]),
    "AWS::EC2::Volume": ("AWS/EBS", "VolumeId", [("VolumeReadOps", "Sum"), ("VolumeWriteOps", "Sum")]),
    "AWS::EC2::NatGateway": ("AWS/NATGateway", "NatGatewayId", [
        ("BytesOutToDestination", "Sum"), ("BytesInFromDestination", "Sum"), ("ActiveConnectionCount", "Maximum")]),
    "AWS::RDS::DBInstance": ("AWS/RDS", "DBInstanceIdentifier", [
        ("CPUUtilization", "Average"), ("CPUUtilization", "Maximum"), ("DatabaseConnections", "Maximum"),
        ("FreeStorageSpace", "Minimum")]),
    "AWS::Lambda::Function": ("AWS/Lambda", "FunctionName", [
        ("Invocations", "Sum"), ("Errors", "Sum"), ("Throttles", "Sum"), ("Duration", "Maximum")]),
}


def _elb_dimensions(rid: str) -> list[dict] | None:
    """LoadBalancer / TargetGroup dimension values are the ARN suffix (app/name/id, targetgroup/name/id)."""
    m = re.search(r":(loadbalancer|targetgroup)/(.+)$", rid)
    if not m:
        return None
    if m.group(1) == "loadbalancer":
        return [{"Name": "LoadBalancer", "Value": m.group(2)}]
    return [{"Name": "TargetGroup", "Value": f"targetgroup/{m.group(2)}"}]


def _series(points: list, stat: str) -> dict:
    points = sorted(points, key=lambda p: p["Timestamp"])
    values = [p[stat] for p in points]
    if not values:
        return {"datapoints": 0}
    agg = sum(values) if stat == "Sum" else (max(values) if stat == "Maximum" else
                                            min(values) if stat == "Minimum" else sum(values) / len(values))
    return {"datapoints": len(values), "total" if stat == "Sum" else stat.lower(): round(agg, 2),
            "latest": round(values[-1], 2), "series": [round(v, 2) for v in values[-14:]]}


@tool(context=True)
def get_resource_metrics(tool_context: ToolContext, days: int = 14) -> dict:
    """CloudWatch utilization and error metrics for the finding's resource.

    EC2 instance: CPU, network, status checks. EBS volume: read/write ops. NAT gateway: bytes
    and connections. RDS instance: CPU, connections, free storage. Lambda: invocations, errors,
    throttles, duration. Load balancer / target group (ARN ids): requests, 5xx, healthy hosts.
    A metric with 0 datapoints usually means the resource is idle, stopped or gone.

    Args:
        days: How far back to look, 1-63. Daily points above 2 days, hourly otherwise.
    """
    f = current_finding(tool_context)
    rtype, rid, errors = f["resource_type"], f["resource_id"], []
    days = max(1, min(int(days), 63))

    if rtype in METRICS:
        namespace, dim, metrics = METRICS[rtype]
        dims = [{"Name": dim, "Value": name_of(rid)}]
    elif rtype in ("AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::TargetGroup"):
        namespace, dims = "AWS/ApplicationELB", _elb_dimensions(rid)
        metrics = ([("RequestCount", "Sum"), ("HTTPCode_Target_5XX_Count", "Sum"), ("TargetResponseTime", "Maximum")]
                   if rtype.endswith("LoadBalancer") else
                   [("HealthyHostCount", "Minimum"), ("UnHealthyHostCount", "Maximum")])
        if dims is None:
            return result(f, errors, note="metrics need the load balancer / target group ARN; the finding has a name.")
    else:
        return result(f, errors, note=f"no metric set defined for {rtype}.")

    cw = finding_session(f).client("cloudwatch")
    period = 86400 if days > 2 else 3600
    out = {}
    for metric, stat in metrics:
        resp = call(errors, f"GetMetricStatistics {metric}", cw.get_metric_statistics,
                    Namespace=namespace, MetricName=metric, Dimensions=dims, StartTime=ago(days=days),
                    EndTime=now(), Period=period, Statistics=[stat])
        if resp is not None:
            out[f"{metric}.{stat}"] = _series(resp.get("Datapoints", []), stat)
    return result(f, errors, days=days, period="daily" if period == 86400 else "hourly", metrics=out)


# ---------------------------------------------------------------- alarms

def _alarm(a: dict) -> dict:
    return {"name": a.get("AlarmName"), "state": a.get("StateValue"),
            "since": iso(a.get("StateUpdatedTimestamp")), "metric": a.get("MetricName"),
            "namespace": a.get("Namespace"), "reason": (a.get("StateReason") or "")[:200],
            "actions_enabled": a.get("ActionsEnabled")}


@tool(context=True)
def get_alarms(tool_context: ToolContext) -> dict:
    """CloudWatch alarms relevant to the finding, and how widespread alarming is right now.

    For an alarm finding: the alarm, how long it has been in ALARM, and its recent state
    changes (flapping or steady). For any other resource: alarms on that resource. Always:
    how many alarms in the account/region are firing now (one alarm vs. a wider outage).
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    rtype, rid, errors = f["resource_type"], f["resource_id"], []
    cw = finding_session(f).client("cloudwatch")

    firing = call(errors, "DescribeAlarms ALARM", cw.describe_alarms, StateValue="ALARM", MaxRecords=100)
    firing_alarms = ok(firing).get("MetricAlarms", []) + ok(firing).get("CompositeAlarms", [])
    facts: dict = {"alarms_firing_in_region": None if firing is None else len(firing_alarms),
                   "firing_sample": [a.get("AlarmName") for a in firing_alarms[:MAX_ITEMS]]}

    if rtype == "AWS::CloudWatch::Alarm":
        name = name_of(rid.split(":alarm:")[-1])
        resp = call(errors, "DescribeAlarms", cw.describe_alarms, AlarmNames=[name])
        alarm = next(iter(ok(resp).get("MetricAlarms", []) + ok(resp).get("CompositeAlarms", [])), None)
        hist = call(errors, "DescribeAlarmHistory", cw.describe_alarm_history, AlarmName=name,
                    HistoryItemType="StateUpdate", StartDate=ago(days=7), EndDate=now(), MaxRecords=20)
        changes = [{"time": iso(h.get("Timestamp")), "summary": h.get("HistorySummary")}
                   for h in ok(hist).get("AlarmHistoryItems", [])]
        facts.update(alarm=_alarm(alarm) if alarm else None,
                     note=None if alarm or resp is None else "alarm not found (deleted?)",
                     dimensions=(alarm or {}).get("Dimensions"),
                     state_changes_7d=None if hist is None else len(changes), recent_changes=changes[:MAX_ITEMS])
        return result(f, errors, **facts)

    key = name_of(rid)
    resp = call(errors, "DescribeAlarms", cw.describe_alarms, MaxRecords=100)
    mine = [a for a in ok(resp).get("MetricAlarms", [])
            if any(key in str(d.get("Value", "")) for d in a.get("Dimensions", []))]
    facts.update(alarms_on_resource=None if resp is None else [_alarm(a) for a in mine[:MAX_ITEMS]])
    return result(f, errors, **facts)


# ---------------------------------------------------------------- service health

def _health_events(f: dict, service: str, errors: list) -> list | str | None:
    """Open AWS Health issues for the service in the finding's region (Business/Enterprise support)."""
    health = finding_session(f).client("health", region_name="us-east-1")
    resp = call(errors, "Health DescribeEvents", health.describe_events,
                filter={"services": [service], "regions": [f["region"]], "eventStatusCodes": ["open"]},
                absent=("SubscriptionRequiredException",))
    if resp is ABSENT:
        return "AWS Health API not available (needs Business or Enterprise support)"
    return None if resp is None else [{"type": e.get("eventTypeCode"), "start": iso(e.get("startTime")),
                                       "category": e.get("eventTypeCategory")} for e in resp.get("events", [])]


@tool(context=True)
def get_service_health(tool_context: ToolContext) -> dict:
    """Current health of the finding's resource as the owning AWS service reports it.

    Target group: target states and reason codes. ECS service (ARN id): running vs desired,
    deployments and recent service events. RDS instance: status, pending maintenance and
    recent events. EC2 instance: system and instance status checks, scheduled events. Lambda:
    state and when the code was last updated. Log group: error counts in the last hour
    (counts only). Also open AWS Health issues for that service in the region, when available.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, errors = finding_session(f), f["resource_type"], f["resource_id"], []

    if rtype == "AWS::ElasticLoadBalancingV2::TargetGroup":
        elb = s.client("elbv2")
        tg_arn = rid if rid.startswith("arn:") else (ok(call(
            errors, "DescribeTargetGroups", elb.describe_target_groups, Names=[rid]))
            .get("TargetGroups") or [{}])[0].get("TargetGroupArn")
        if not tg_arn:
            return result(f, errors, note="target group not found")
        th = call(errors, "DescribeTargetHealth", elb.describe_target_health, TargetGroupArn=tg_arn)
        states: dict[str, int] = {}
        reasons: dict[str, int] = {}
        for t in ok(th).get("TargetHealthDescriptions", []):
            h = t.get("TargetHealth", {})
            states[h.get("State")] = states.get(h.get("State"), 0) + 1
            if h.get("Reason"):
                reasons[h["Reason"]] = reasons.get(h["Reason"], 0) + 1
        return result(f, errors, target_states=states, reasons=reasons,
                      aws_health=_health_events(f, "ELASTICLOADBALANCING", errors))

    if rtype == "AWS::ECS::Service":
        m = re.match(r"arn:aws[\w-]*:ecs:[^:]+:\d+:service/([^/]+)/(.+)$", rid)
        if not m:
            return result(f, errors, note="ECS service id must be its ARN (service/cluster/name).")
        resp = call(errors, "DescribeServices", s.client("ecs").describe_services,
                    cluster=m.group(1), services=[m.group(2)])
        svc = next(iter(ok(resp).get("services", [])), None)
        if not svc:
            return result(f, errors, note="service not found" if resp else None)
        return result(f, errors, status=svc.get("status"), desired=svc.get("desiredCount"),
                      running=svc.get("runningCount"), pending=svc.get("pendingCount"),
                      deployments=[{"status": d.get("status"), "rollout": d.get("rolloutState"),
                                    "created": iso(d.get("createdAt")), "task_definition": name_of(d.get("taskDefinition", "")),
                                    "running": d.get("runningCount"), "failed_tasks": d.get("failedTasks")}
                                   for d in svc.get("deployments", [])],
                      recent_events=[{"time": iso(e.get("createdAt")), "message": e.get("message", "")[:200]}
                                     for e in svc.get("events", [])[:5]],
                      aws_health=_health_events(f, "ECS", errors))

    if rtype == "AWS::RDS::DBInstance":
        rds = s.client("rds")
        db = next(iter(ok(call(errors, "DescribeDBInstances", rds.describe_db_instances,
                                DBInstanceIdentifier=rid, absent=("DBInstanceNotFound",))).get("DBInstances", [])), None)
        maint = call(errors, "DescribePendingMaintenanceActions", rds.describe_pending_maintenance_actions,
                     Filters=[{"Name": "db-instance-id", "Values": [rid]}])
        events = call(errors, "DescribeEvents", rds.describe_events, SourceIdentifier=rid,
                      SourceType="db-instance", Duration=1440)
        return result(f, errors, status=(db or {}).get("DBInstanceStatus"),
                      note=None if db else "instance not found",
                      pending_maintenance=[a.get("Action") for r in ok(maint).get("PendingMaintenanceActions", [])
                                           for a in r.get("PendingMaintenanceActionDetails", [])],
                      events_24h=[{"time": iso(e.get("Date")), "message": e.get("Message", "")[:200]}
                                  for e in ok(events).get("Events", [])[-MAX_ITEMS:]],
                      aws_health=_health_events(f, "RDS", errors))

    if rtype == "AWS::EC2::Instance":
        resp = call(errors, "DescribeInstanceStatus", s.client("ec2").describe_instance_status,
                    InstanceIds=[rid], IncludeAllInstances=True)
        st = next(iter(ok(resp).get("InstanceStatuses", [])), None)
        if not st:
            return result(f, errors, note="instance not found" if resp else None)
        return result(f, errors, state=st.get("InstanceState", {}).get("Name"),
                      system_status=st.get("SystemStatus", {}).get("Status"),
                      instance_status=st.get("InstanceStatus", {}).get("Status"),
                      scheduled_events=[{"code": e.get("Code"), "not_before": iso(e.get("NotBefore"))}
                                        for e in st.get("Events", [])],
                      aws_health=_health_events(f, "EC2", errors))

    if rtype == "AWS::Lambda::Function":
        conf = call(errors, "GetFunctionConfiguration", s.client("lambda").get_function_configuration,
                    FunctionName=rid, absent=("ResourceNotFoundException",))
        if conf is ABSENT:
            return result(f, errors, note="function not found (deleted?)")
        c = ok(conf)
        return result(f, errors, state=c.get("State"), last_update_status=c.get("LastUpdateStatus"),
                      code_updated=c.get("LastModified"),
                      code_updated_days_ago=days_since(c.get("LastModified", "").replace("+0000", "+00:00") or None),
                      runtime=c.get("Runtime"), timeout_s=c.get("Timeout"), memory_mb=c.get("MemorySize"),
                      aws_health=_health_events(f, "LAMBDA", errors))

    if rtype == "AWS::Logs::LogGroup":
        logs = s.client("logs")
        counts = {}
        for pattern in ("FATAL", "ERROR", "Exception"):
            resp = call(errors, f"FilterLogEvents {pattern}", logs.filter_log_events, logGroupName=rid,
                        filterPattern=pattern, startTime=int(ago(hours=1).timestamp() * 1000), limit=1000)
            if resp is not None and resp is not ABSENT:
                n = len(resp.get("events", []))
                counts[pattern] = f"{n}+" if resp.get("nextToken") else n
        return result(f, errors, matches_last_hour=counts, note="counts only; log lines are not read")

    return result(f, errors, note=f"no service health check defined for {rtype}.")


# ---------------------------------------------------------------- recent changes

# Write events that are routine plumbing, not changes anyone would call a deployment.
NOISE = {"AssumeRole", "AssumeRoleWithWebIdentity", "Decrypt", "Encrypt", "GenerateDataKey", "CreateLogStream",
         "PutLogEvents", "ConsoleLogin", "StartQuery", "CreateGrant", "RetireGrant", "UpdateInstanceInformation",
         "SendCommand", "PutMetricData", "SetTaskStatus", "ReportTaskProgress", "PutEvaluations",
         "SubmitContainerStateChange", "SubmitTaskStateChange", "GetSessionToken", "GetFederationToken"}
PAGES = 4


@tool(context=True)
def get_recent_changes(tool_context: ToolContext, hours: int = 24) -> dict:
    """Write activity across the finding's account and region in the last N hours.

    Answers "what changed just before this started?": deployments, configuration changes,
    launches and deletions by anyone, not only on this resource (use get_recent_activity
    for this resource's own history). Routine plumbing events are left out. Returns counts
    by event and the most recent changes with who made them.

    Args:
        hours: How far back to look, 1-168.
    """
    f = current_finding(tool_context)
    errors, hours = [], max(1, min(int(hours), 168))
    ct = finding_session(f).client("cloudtrail")
    kwargs = {"LookupAttributes": [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
              "StartTime": ago(hours=hours), "EndTime": now(), "MaxResults": 50}
    changes, by_event, scanned, truncated = [], {}, 0, False
    for page in range(PAGES):
        resp = call(errors, "LookupEvents", ct.lookup_events, **kwargs)
        if resp is None:
            break
        for e in resp.get("Events", []):
            scanned += 1
            name = e.get("EventName")
            if name in NOISE:
                continue
            detail = json.loads(e.get("CloudTrailEvent") or "{}")
            by_event[name] = by_event.get(name, 0) + 1
            changes.append({"time": iso(e.get("EventTime")), "event": name, "source": e.get("EventSource"),
                            "user": e.get("Username") or detail.get("userIdentity", {}).get("arn"),
                            "resources": [r.get("ResourceName") for r in e.get("Resources", [])][:3],
                            "error": detail.get("errorCode")})
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
        truncated = page == PAGES - 1
    return result(f, errors, region=f["region"], hours=hours, events_scanned=scanned, truncated=truncated,
                  changes_by_event=dict(sorted(by_event.items(), key=lambda kv: -kv[1])[:20]),
                  recent_changes=changes[:20],
                  note=None if changes or errors else f"No write events in the last {hours} hours.")


OPERATIONS_TOOLS = [get_resource_metrics, get_alarms, get_service_health, get_recent_changes]
