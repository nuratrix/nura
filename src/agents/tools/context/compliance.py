"""Compliance context: the control's live evidence, and which frameworks actually apply.

A compliance finding says a control failed when the scanner looked. Before it is reported
the agent checks the evidence itself: is it still failing, is it satisfied another way (an
organization trail created in the management account, an organization Config rule), and
does the account even claim that framework. Read-only; the resource comes from the finding.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from strands import ToolContext, tool

from agents.orchestrator.routing import rulesets_dir
from agents.tools.context.aws_calls import ABSENT, MAX_ITEMS, as_list, call, days_since, ok, result
from agents.tools.context.finding_context import current_finding, finding_session

# CIS CloudWatch monitoring controls: what the metric filter pattern must mention.
CIS_MONITORS = {
    "root_login": ("Root", "userIdentity.type"),
    "console_auth_failures": ("ConsoleLogin", "Failed authentication"),
    "iam_policy_changes": ("DeleteGroupPolicy", "PutUserPolicy"),
    "security_group_changes": ("AuthorizeSecurityGroupIngress", "RevokeSecurityGroupEgress"),
}


def _trails(s, errors) -> dict:
    ct = s.client("cloudtrail")
    resp = call(errors, "DescribeTrails", ct.describe_trails, includeShadowTrails=True)
    trails = []
    for t in ok(resp).get("trailList", [])[:MAX_ITEMS]:
        st = call(errors, f"GetTrailStatus {t.get('Name')}", ct.get_trail_status, Name=t["TrailARN"])
        trails.append({"name": t.get("Name"), "home_region": t.get("HomeRegion"),
                       "owner_account": t["TrailARN"].split(":")[4],
                       "multi_region": t.get("IsMultiRegionTrail"), "organization_trail": t.get("IsOrganizationTrail"),
                       "log_file_validation": t.get("LogFileValidationEnabled"), "kms_key": bool(t.get("KmsKeyId")),
                       "cloudwatch_logs": bool(t.get("CloudWatchLogsLogGroupArn")),
                       "logging": ok(st).get("IsLogging") if st else None,
                       "last_delivery_days_ago": days_since(ok(st).get("LatestDeliveryTime"))})
    good = [t for t in trails if t["multi_region"] and t["logging"]]
    return {"trails": None if resp is None else trails,
            "covered_by_logging_multi_region_trail": None if resp is None else bool(good),
            "covered_by_organization_trail": None if resp is None else any(t["organization_trail"] for t in good)}


def _config_recorder(s, errors) -> dict:
    cfg = s.client("config")
    rec = call(errors, "DescribeConfigurationRecorders", cfg.describe_configuration_recorders)
    st = call(errors, "DescribeConfigurationRecorderStatus", cfg.describe_configuration_recorder_status)
    ch = call(errors, "DescribeDeliveryChannels", cfg.describe_delivery_channels)
    statuses = {x.get("name"): x for x in ok(st).get("ConfigurationRecordersStatus", [])}
    return {"recorders": None if rec is None else [
        {"name": r.get("name"), "all_supported": r.get("recordingGroup", {}).get("allSupported"),
         "include_global": r.get("recordingGroup", {}).get("includeGlobalResourceTypes"),
         "recording": statuses.get(r.get("name"), {}).get("recording"),
         "last_status": statuses.get(r.get("name"), {}).get("lastStatus"),
         "last_error": statuses.get(r.get("name"), {}).get("lastErrorCode")}
        for r in rec.get("ConfigurationRecorders", [])],
        "delivery_channels": None if ch is None else len(ch.get("DeliveryChannels", []))}


def _config_rule_name(f: dict) -> str | None:
    ev = f.get("evidence") or {}
    if ev.get("config_rule"):
        return ev["config_rule"]
    m = re.search(r"Config rule ([a-z0-9-]+)", f.get("title") or "")
    return m.group(1) if m else None


def _config_rule(s, f, errors) -> dict:
    cfg = s.client("config")
    name = _config_rule_name(f)
    out: dict = {**_config_recorder(s, errors), "config_rule": name}
    if not name:
        rules = call(errors, "DescribeConfigRules", cfg.describe_config_rules)
        out["rules_in_region"] = None if rules is None else len(rules.get("ConfigRules", []))
        return out
    # Deployed rules are often prefixed (securityhub-..., OrgConfigRule-...): match on the managed identifier too.
    rules = call(errors, "DescribeConfigRules", cfg.describe_config_rules)
    matches = [r for r in ok(rules).get("ConfigRules", [])
               if name in r.get("ConfigRuleName", "")
               or r.get("Source", {}).get("SourceIdentifier", "").lower() == name.replace("-", "_")]
    found = []
    for r in matches[:5]:
        rn = r["ConfigRuleName"]
        comp = call(errors, "DescribeComplianceByConfigRule", cfg.describe_compliance_by_config_rule,
                    ConfigRuleNames=[rn])
        detail = call(errors, "GetComplianceDetailsByConfigRule", cfg.get_compliance_details_by_config_rule,
                      ConfigRuleName=rn, ComplianceTypes=["NON_COMPLIANT"], Limit=MAX_ITEMS)
        c = next(iter(ok(comp).get("ComplianceByConfigRules", [])), {}).get("Compliance", {})
        found.append({"deployed_name": rn, "state": r.get("ConfigRuleState"),
                      "created_by": r.get("CreatedBy"), "compliance": c.get("ComplianceType"),
                      "non_compliant_resources": [x["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
                                                  .get("ResourceId") for x in ok(detail).get("EvaluationResults", [])]})
    out.update(deployed=None if rules is None else bool(found), matching_rules=found)
    return out


def _password_policy(s, errors) -> dict:
    pp = call(errors, "GetAccountPasswordPolicy", s.client("iam").get_account_password_policy,
              absent=("NoSuchEntity",))
    return {"password_policy": None if pp is None else ("none" if pp is ABSENT else pp["PasswordPolicy"])}


def _root(s, errors) -> dict:
    summary = ok(call(errors, "GetAccountSummary", s.client("iam").get_account_summary)).get("SummaryMap")
    return {"root_mfa_enabled": summary.get("AccountMFAEnabled") == 1 if summary else None,
            "root_access_keys_present": summary.get("AccountAccessKeysPresent") == 1 if summary else None}


def _metric_filters(s, errors) -> dict:
    logs, cw = s.client("logs"), s.client("cloudwatch")
    filters, token = [], None
    for _ in range(5):
        resp = call(errors, "DescribeMetricFilters", logs.describe_metric_filters,
                    **({"nextToken": token} if token else {}))
        if resp is None:
            break
        filters += resp.get("metricFilters", [])
        token = resp.get("nextToken")
        if not token:
            break
    alarms = call(errors, "DescribeAlarms", cw.describe_alarms, MaxRecords=100)
    alarmed = {a.get("MetricName") for a in ok(alarms).get("MetricAlarms", [])}
    monitors = {}
    for key, needles in CIS_MONITORS.items():
        hits = [m for m in filters if all(n in (m.get("filterPattern") or "") for n in needles)]
        monitors[key] = {"filter": bool(hits), "log_group": hits[0].get("logGroupName") if hits else None,
                         "alarmed": any(t.get("metricName") in alarmed for m in hits
                                        for t in m.get("metricTransformations", []))}
    return {"metric_filters_scanned": len(filters), "cis_monitors": monitors, **_trails(s, errors)}


def _s3(s, f, errors) -> dict:
    s3, bucket = s.client("s3"), f["resource_id"]
    enc = call(errors, "GetBucketEncryption", s3.get_bucket_encryption, Bucket=bucket,
               absent=("ServerSideEncryptionConfigurationNotFoundError",))
    rules = ok(enc).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    pol = call(errors, "GetBucketPolicy", s3.get_bucket_policy, Bucket=bucket, absent=("NoSuchBucketPolicy",))
    doc = json.loads(pol["Policy"]) if isinstance(pol, dict) else {}
    tls = any(st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition", {}))
              for st in as_list(doc.get("Statement")))
    return {"default_encryption": None if enc is None else [
        r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") for r in rules] or "none",
        "enforces_tls": None if pol is None else tls,
        "note": "Since Jan 2023 S3 encrypts every new object with SSE-S3 by default."}


def _vpc_flow_logs(s, f, errors) -> dict:
    fl = call(errors, "DescribeFlowLogs", s.client("ec2").describe_flow_logs,
              Filter=[{"Name": "resource-id", "Values": [f["resource_id"]]}])
    return {"flow_logs": None if fl is None else [
        {"status": x.get("FlowLogStatus"), "traffic": x.get("TrafficType")} for x in fl.get("FlowLogs", [])]}


def _default_sg(s, f, errors) -> dict:
    ec2 = s.client("ec2")
    resp = call(errors, "DescribeSecurityGroups", ec2.describe_security_groups, GroupIds=[f["resource_id"]],
                absent=("InvalidGroup.NotFound",))
    g = next(iter(ok(resp).get("SecurityGroups", [])), None)
    if not g:
        return {"exists": False if resp is ABSENT or resp else None}
    enis = call(errors, "DescribeNetworkInterfaces", ec2.describe_network_interfaces,
                Filters=[{"Name": "group-id", "Values": [g["GroupId"]]}])
    return {"exists": True, "is_default": g.get("GroupName") == "default",
            "inbound_rules": len(g.get("IpPermissions", [])), "outbound_rules": len(g.get("IpPermissionsEgress", [])),
            "network_interfaces_using": None if enis is None else len(enis.get("NetworkInterfaces", []))}


@tool(context=True)
def get_control_evidence(tool_context: ToolContext) -> dict:
    """Live evidence for the control this compliance finding is about.

    CloudTrail: every trail visible in the account including organization trails, whether
    one is multi-region and logging, validation, KMS, CloudWatch Logs. AWS Config recorder:
    recording, all resource types, delivery channel. Config rule: whether it is deployed
    under any name (Security Hub and organization rules are prefixed), its compliance and
    non-compliant resources. Password policy, root MFA and root access keys. CIS metric
    filters (root login, console failures, IAM and security group changes) and their alarms.
    S3: default encryption and TLS enforcement. VPC: flow logs. Security group: rules on a
    default group and whether anything uses it. For IAM users, roles and keys use
    get_principal_access; for RDS use get_resource_state.
    Takes no arguments: the control comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, errors = finding_session(f), f["resource_type"], f["resource_id"], []
    if rtype == "AWS::CloudTrail::Trail":
        return result(f, errors, **_trails(s, errors))
    if rtype == "AWS::Config::ConfigurationRecorder":
        return result(f, errors, **_config_recorder(s, errors))
    if rtype == "AWS::Config::ConfigRule":
        return result(f, errors, **_config_rule(s, f, errors))
    if rtype in ("AWS::IAM::AccountPasswordPolicy", "AWS::IAM::PasswordPolicy"):
        return result(f, errors, **_password_policy(s, errors))
    if rtype == "AWS::IAM::RootAccount" or (rtype == "AWS::IAM::User" and rid.endswith("root")):
        return result(f, errors, **_root(s, errors))
    if rtype == "AWS::Logs::MetricFilter":
        return result(f, errors, **_metric_filters(s, errors))
    if rtype == "AWS::S3::Bucket":
        return result(f, errors, **_s3(s, f, errors))
    if rtype == "AWS::EC2::VPC":
        return result(f, errors, **_vpc_flow_logs(s, f, errors))
    if rtype == "AWS::EC2::SecurityGroup":
        return result(f, errors, **_default_sg(s, f, errors))
    return result(f, errors, note=f"no control evidence defined for {rtype}; "
                                  "use get_principal_access (IAM) or get_resource_state (RDS, EC2).")


@lru_cache(maxsize=1)
def _rule_index() -> dict[str, dict]:
    index = {}
    for path in sorted(rulesets_dir().glob("*.json")):
        for r in json.loads(path.read_text(encoding="utf-8")).get("rules", []):
            index[r["rule_id"]] = r
    return index


@tool(context=True)
def get_compliance_scope(tool_context: ToolContext) -> dict:
    """Which frameworks this finding maps to, and which ones the account actually tracks.

    The rule's control mappings (CIS, SOC 2, NIST, PCI ... as recorded in the ruleset), the
    Security Hub standards enabled in the account/region, and the AWS Config conformance packs
    deployed. A control from a framework the account neither enables nor deploys is weaker
    evidence of an obligation than one it does.
    Takes no arguments: the rule and account come from the finding under review.
    """
    f = current_finding(tool_context)
    s, errors = finding_session(f), []
    rule = _rule_index().get(f.get("rule_id"), {})
    sh = call(errors, "SecurityHub GetEnabledStandards", s.client("securityhub").get_enabled_standards,
              absent=("InvalidAccessException",))
    packs = call(errors, "DescribeConformancePacks", s.client("config").describe_conformance_packs)
    return result(f, errors, rule_id=f.get("rule_id"), rule_controls=rule.get("controls"),
                  security_hub_standards="Security Hub not enabled" if sh is ABSENT else None if sh is None else [
                      {"standard": x.get("StandardsArn", "").split("/", 1)[-1], "status": x.get("StandardsStatus")}
                      for x in sh.get("StandardsSubscriptions", [])],
                  conformance_packs=None if packs is None else [
                      p.get("ConformancePackName") for p in packs.get("ConformancePackDetails", [])])


COMPLIANCE_TOOLS = [get_control_evidence, get_compliance_scope]
