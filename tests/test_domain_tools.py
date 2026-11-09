"""Context tools for the seven domain agents, with stubbed AWS clients: no AWS calls."""
import importlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from agents.orchestrator import routing
from agents.tools.context import access, compliance, cost_anomaly, infra, network, operations, resilience

ACCT = "111122223333"
NOW = datetime.now(timezone.utc)
MODULES = (access, compliance, cost_anomaly, infra, network, operations, resilience)


def finding(rtype, rid, **kw):
    return {"finding_id": "x", "rule_id": kw.pop("rule_id", "X-1"), "account_id": ACCT, "region": "us-east-1",
            "resource_type": rtype, "resource_id": rid, **kw}


def ctx(f):
    return SimpleNamespace(invocation_state={"finding": f})


def err(code):
    def raise_(*_, **__):
        raise ClientError({"Error": {"Code": code, "Message": "m"}}, "Op")
    return raise_


def client(**methods):
    return SimpleNamespace(**methods)


@pytest.fixture
def aws(monkeypatch):
    clients = {}
    session = SimpleNamespace(client=lambda name, region_name=None: clients[name])
    for m in MODULES:
        monkeypatch.setattr(m, "finding_session", lambda f: session)
    monkeypatch.setattr(network, "base_session", lambda: session)
    return clients


def run(tool, f, **kw):
    return tool._tool_func(ctx(f), **kw)


# ---------------------------------------------------------------- operations

def test_metrics_summarise_series(aws):
    calls = []

    def stats(**kw):
        calls.append(kw)
        stat = kw["Statistics"][0]
        return {"Datapoints": [{"Timestamp": NOW - timedelta(days=i), stat: float(i)} for i in range(3)]}
    aws["cloudwatch"] = client(get_metric_statistics=stats)
    out = run(operations.get_resource_metrics, finding("AWS::EC2::NatGateway", "nat-1"), days=30)
    assert calls[0]["Dimensions"] == [{"Name": "NatGatewayId", "Value": "nat-1"}] and calls[0]["Period"] == 86400
    assert out["metrics"]["BytesOutToDestination.Sum"]["total"] == 3.0
    assert out["metrics"]["ActiveConnectionCount.Maximum"]["maximum"] == 2.0


def test_metrics_need_elb_arn_and_known_type(aws):
    assert "ARN" in run(operations.get_resource_metrics, finding("AWS::ElasticLoadBalancingV2::TargetGroup", "tg"))["note"]
    assert "no metric set" in run(operations.get_resource_metrics, finding("AWS::S3::Bucket", "b"))["note"]


def test_alarm_finding_reports_flapping_and_wider_outage(aws):
    alarm = {"AlarmName": "high-5xx", "StateValue": "ALARM", "StateUpdatedTimestamp": NOW, "Dimensions": []}

    def describe(**kw):
        if kw.get("StateValue"):
            return {"MetricAlarms": [alarm, {"AlarmName": "other"}]}
        return {"MetricAlarms": [alarm]}
    aws["cloudwatch"] = client(describe_alarms=describe, describe_alarm_history=lambda **_: {
        "AlarmHistoryItems": [{"Timestamp": NOW, "HistorySummary": "OK to ALARM"}] * 6})
    out = run(operations.get_alarms, finding("AWS::CloudWatch::Alarm", "high-5xx"))
    assert out["alarms_firing_in_region"] == 2 and out["state_changes_7d"] == 6
    assert out["alarm"]["state"] == "ALARM" and not out["errors"]


def test_target_group_health_and_health_api_unavailable(aws):
    aws["elbv2"] = client(
        describe_target_groups=lambda **kw: {"TargetGroups": [{"TargetGroupArn": "arn:tg"}]},
        describe_target_health=lambda **kw: {"TargetHealthDescriptions": [
            {"TargetHealth": {"State": "unhealthy", "Reason": "Target.Timeout"}},
            {"TargetHealth": {"State": "unhealthy", "Reason": "Target.Timeout"}},
            {"TargetHealth": {"State": "healthy"}}]})
    aws["health"] = client(describe_events=err("SubscriptionRequiredException"))
    out = run(operations.get_service_health, finding("AWS::ElasticLoadBalancingV2::TargetGroup", "tg-web"))
    assert out["target_states"] == {"unhealthy": 2, "healthy": 1}
    assert out["reasons"] == {"Target.Timeout": 2}
    assert "Business or Enterprise" in out["aws_health"] and not out["errors"]


def test_log_group_health_returns_counts_not_lines(aws):
    aws["logs"] = client(filter_log_events=lambda **kw: {
        "events": [{"message": "secret"}] * (3 if kw["filterPattern"] == "ERROR" else 0),
        **({"nextToken": "t"} if kw["filterPattern"] == "Exception" else {})})
    out = run(operations.get_service_health, finding("AWS::Logs::LogGroup", "/app"))
    assert out["matches_last_hour"] == {"FATAL": 0, "ERROR": 3, "Exception": "0+"}
    assert "secret" not in json.dumps(out)


def test_recent_changes_skip_noise_and_count(aws):
    def ev(name, user="dev"):
        return {"EventName": name, "EventTime": NOW, "Username": user, "EventSource": "x", "Resources": []}
    pages = [{"Events": [ev("AssumeRole"), ev("UpdateService"), ev("Decrypt")], "NextToken": "n"},
             {"Events": [ev("UpdateService"), ev("RunInstances")]}]
    aws["cloudtrail"] = client(lookup_events=lambda **kw: pages[1] if kw.get("NextToken") else pages[0])
    out = run(operations.get_recent_changes, finding("AWS::ECS::Service", "svc"), hours=6)
    assert out["changes_by_event"] == {"UpdateService": 2, "RunInstances": 1}
    assert out["events_scanned"] == 5 and not out["truncated"]


# ---------------------------------------------------------------- infra

def test_snapshot_dependencies(aws):
    aws["ec2"] = client(
        describe_snapshots=lambda **_: {"Snapshots": [{"VolumeId": "vol-gone", "StartTime": NOW - timedelta(days=300),
                                                       "Tags": [{"Key": "aws:backup:source-resource", "Value": "x"}]}]},
        describe_images=lambda **_: {"Images": [{"ImageId": "ami-1"}]},
        describe_volumes=err("InvalidVolume.NotFound"))
    out = run(infra.get_resource_state, finding("AWS::EC2::Snapshot", "snap-1"))
    assert out["age_days"] == 300 and out["used_by_amis"] == ["ami-1"]
    assert out["source_volume_exists"] is False and out["managed_by_aws_backup"] is True


def test_stopped_instance_and_missing_instance(aws):
    inst = {"State": {"Name": "stopped"}, "StateTransitionReason": "User initiated (2020-01-02 10:11:12 GMT)",
            "Tags": [{"Key": "aws:autoscaling:groupName", "Value": "asg"}], "BlockDeviceMappings": []}
    aws["ec2"] = client(describe_instances=lambda **_: {"Reservations": [{"Instances": [inst]}]},
                        describe_instance_attribute=lambda **_: {"DisableApiTermination": {"Value": True}})
    out = run(infra.get_resource_state, finding("AWS::EC2::Instance", "i-1"))
    assert out["stopped_days"] > 2000 and out["auto_scaling_group"] == "asg" and out["termination_protection"]
    aws["ec2"] = client(describe_instances=err("InvalidInstanceID.NotFound"))
    assert run(infra.get_resource_state, finding("AWS::EC2::Instance", "i-2"))["exists"] is False


def test_nat_gateway_route_tables(aws):
    aws["ec2"] = client(describe_nat_gateways=lambda **_: {"NatGateways": [{"State": "available"}]},
                        describe_route_tables=lambda **_: {"RouteTables": [{"Associations": [{}, {}]}]})
    out = run(infra.get_resource_state, finding("AWS::EC2::NatGateway", "nat-1"))
    assert out["route_tables_using"] == 1 and out["subnets_routed"] == 2


# ---------------------------------------------------------------- network

def test_subnet_falls_back_to_main_route_table(aws):
    def route_tables(**kw):
        if kw["Filters"][0]["Name"] == "association.subnet-id":
            return {"RouteTables": []}
        return {"RouteTables": [{"Routes": [{"GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0"}]}]}
    aws["ec2"] = client(describe_subnets=lambda **_: {"Subnets": [{"VpcId": "vpc-1", "MapPublicIpOnLaunch": True}]},
                        describe_route_tables=route_tables,
                        describe_network_interfaces=lambda **_: {"NetworkInterfaces": [{"Association": {}}, {}]})
    out = run(network.get_network_config, finding("AWS::EC2::Subnet", "subnet-1"))
    assert out["routes_to_internet_gateway"] is True and out["network_interfaces"] == 2


def test_nacl_open_entries_in_order(aws):
    acl = {"IsDefault": False, "Associations": [], "Entries": [
        {"RuleNumber": 200, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "Egress": False},
        {"RuleNumber": 100, "RuleAction": "deny", "Protocol": "6", "CidrBlock": "0.0.0.0/0", "Egress": False,
         "PortRange": {"From": 22, "To": 22}},
        {"RuleNumber": 100, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "Egress": True},
        {"RuleNumber": 32767, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "Egress": False}]}
    aws["ec2"] = client(describe_network_acls=lambda **_: {"NetworkAcls": [acl]})
    out = run(network.get_network_config, finding("AWS::EC2::NetworkAcl", "acl-1"))
    assert [(e["rule"], e["action"], e["ports"]) for e in out["open_inbound_entries"]] == \
        [(100, "deny", "22-22"), (200, "allow", "all")]


def test_peering_other_account_outside_org(aws):
    aws["ec2"] = client(describe_vpc_peering_connections=lambda **_: {"VpcPeeringConnections": [{
        "Status": {"Code": "active"}, "RequesterVpcInfo": {"OwnerId": ACCT},
        "AccepterVpcInfo": {"OwnerId": "999988887777"}}]})
    aws["organizations"] = client(describe_account=err("AccountNotFoundException"))
    out = run(network.get_network_config, finding("AWS::EC2::VPCPeeringConnection", "pcx-1"))
    assert out["other_account"] == "999988887777" and out["other_account_in_org"] is False


def test_vpc_controls(aws):
    aws["ec2"] = client(describe_vpcs=lambda **_: {"Vpcs": [{"IsDefault": False}]},
                        describe_internet_gateways=lambda **_: {"InternetGateways": [{}]},
                        describe_network_interfaces=lambda **_: {"NetworkInterfaces": []},
                        describe_flow_logs=lambda **kw: {"FlowLogs": []})
    aws["route53resolver"] = client(list_resolver_query_log_config_associations=lambda **_: {
        "ResolverQueryLogConfigAssociations": [{"Status": "ACTIVE"}]},
        list_firewall_rule_group_associations=err("AccessDeniedException"))
    out = run(network.get_network_config, finding("AWS::Route53Resolver::ResolverQueryLoggingConfig", "vpc-1"))
    assert out["flow_logs"] == [] and out["dns_query_logging"] == ["ACTIVE"]
    assert out["dns_firewall_rule_groups"] is None and "AccessDenied" in out["errors"][0]


# ---------------------------------------------------------------- compliance

def test_org_trail_satisfies_trail_control(aws):
    trail = {"Name": "org", "TrailARN": "arn:aws:cloudtrail:us-east-1:999988887777:trail/org",
             "IsMultiRegionTrail": True, "IsOrganizationTrail": True}
    aws["cloudtrail"] = client(describe_trails=lambda **_: {"trailList": [trail]},
                               get_trail_status=lambda **_: {"IsLogging": True, "LatestDeliveryTime": NOW})
    out = run(compliance.get_control_evidence, finding("AWS::CloudTrail::Trail", "account-trail"))
    assert out["covered_by_organization_trail"] and out["trails"][0]["owner_account"] == "999988887777"


def test_config_rule_found_under_prefixed_name(aws):
    rule = {"ConfigRuleName": "securityhub-restricted-ssh-abc", "ConfigRuleState": "ACTIVE",
            "Source": {"SourceIdentifier": "INCOMING_SSH_DISABLED"}}
    aws["config"] = client(
        describe_configuration_recorders=lambda: {"ConfigurationRecorders": []},
        describe_configuration_recorder_status=lambda: {"ConfigurationRecordersStatus": []},
        describe_delivery_channels=lambda: {"DeliveryChannels": []},
        describe_config_rules=lambda **_: {"ConfigRules": [rule]},
        describe_compliance_by_config_rule=lambda **_: {"ComplianceByConfigRules": [
            {"Compliance": {"ComplianceType": "NON_COMPLIANT"}}]},
        get_compliance_details_by_config_rule=lambda **_: {"EvaluationResults": [
            {"EvaluationResultIdentifier": {"EvaluationResultQualifier": {"ResourceId": "sg-1"}}}]})
    f = finding("AWS::Config::ConfigRule", "account",
                title="Config rule restricted-ssh not deployed or non-compliant: SSH open")
    out = run(compliance.get_control_evidence, f)
    assert out["config_rule"] == "restricted-ssh" and out["deployed"] is True
    assert out["matching_rules"][0]["non_compliant_resources"] == ["sg-1"]


def test_cis_metric_filters(aws):
    aws["logs"] = client(describe_metric_filters=lambda **_: {"metricFilters": [
        {"filterPattern": '{ $.userIdentity.type = "Root" }', "logGroupName": "ct",
         "metricTransformations": [{"metricName": "RootLogin"}]}]})
    aws["cloudwatch"] = client(describe_alarms=lambda **_: {"MetricAlarms": [{"MetricName": "RootLogin"}]})
    aws["cloudtrail"] = client(describe_trails=lambda **_: {"trailList": []})
    out = run(compliance.get_control_evidence, finding("AWS::Logs::MetricFilter", "account"))
    assert out["cis_monitors"]["root_login"] == {"filter": True, "log_group": "ct", "alarmed": True}
    assert out["cis_monitors"]["console_auth_failures"]["filter"] is False


def test_root_controls_on_iam_user_type(aws):
    aws["iam"] = client(get_account_summary=lambda: {"SummaryMap": {"AccountMFAEnabled": 1,
                                                                    "AccountAccessKeysPresent": 0}})
    out = run(compliance.get_control_evidence, finding("AWS::IAM::User", "root"))
    assert out["root_mfa_enabled"] is True and out["root_access_keys_present"] is False


def test_compliance_scope(aws):
    aws["securityhub"] = client(get_enabled_standards=err("InvalidAccessException"))
    aws["config"] = client(describe_conformance_packs=lambda: {"ConformancePackDetails": [
        {"ConformancePackName": "cis-pack"}]})
    out = run(compliance.get_compliance_scope, finding("AWS::CloudTrail::Trail", "t", rule_id="COMP-CIS-012"))
    assert out["security_hub_standards"] == "Security Hub not enabled"
    assert out["conformance_packs"] == ["cis-pack"] and "rule_controls" in out


# ---------------------------------------------------------------- resilience

def _backup(**extra):
    base = dict(list_backup_plans=lambda: {"BackupPlansList": [{"BackupPlanName": "daily", "BackupPlanId": "p1"}]},
                get_backup_plan=lambda **_: {"BackupPlan": {"Rules": [{"RuleName": "r", "Lifecycle": {
                    "DeleteAfterDays": 35}, "CopyActions": [
                    {"DestinationBackupVaultArn": "arn:aws:backup:us-west-2:999988887777:backup-vault:dr"}]}]}},
                list_backup_selections=lambda **_: {"BackupSelectionsList": [{}]},
                list_backup_jobs=lambda **kw: {"BackupJobs": [
                    {"StatusMessage": "Insufficient privileges", "CreatedBy": {"BackupPlanId": "p1"}}] * 3
                    if kw["ByState"] == "FAILED" else [{}]},
                list_restore_jobs=lambda **_: {"RestoreJobs": []},
                list_restore_testing_plans=lambda: {"RestoreTestingPlans": []})
    return client(**{**base, **extra})


def test_backup_jobs_plans_and_in_flight(aws):
    aws["backup"] = _backup()
    out = run(resilience.get_backup_posture, finding("AWS::Backup::BackupPlan", "daily"))
    assert out["this_plan"]["rules"][0] == {"rule": "r", "schedule": None, "retention_days": 35,
                                            "copy_to_regions": ["us-west-2"], "copy_to_accounts": ["999988887777"]}
    assert out["failed_jobs_7d"] == 3 and out["failure_reasons"] == {"Insufficient privileges": 3}
    assert out["failed_by_plan"] == {"p1": 3} and out["backup_jobs_running"] == 1


def test_protected_resource_recovery_points(aws):
    seen = {}
    aws["backup"] = _backup(
        describe_protected_resource=err("ResourceNotFoundException"),
        list_recovery_points_by_resource=lambda **kw: seen.update(kw) or {"RecoveryPoints": [
            {"CreationDate": NOW - timedelta(days=9), "BackupVaultName": "v"}]})
    out = run(resilience.get_backup_posture, finding("AWS::RDS::DBInstance", "db1"))
    assert seen["ResourceArn"] == f"arn:aws:rds:us-east-1:{ACCT}:db:db1"
    assert out["protected_by_aws_backup"] is False and out["last_backup_days_ago"] == 9


def test_vault_policy_and_key(aws):
    policy = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "backup:DeleteRecoveryPoint"}]}
    aws["backup"] = _backup(describe_backup_vault=lambda **_: {"EncryptionKeyArn": "k", "Locked": False},
                            get_backup_vault_access_policy=lambda **_: {"Policy": json.dumps(policy)})
    aws["kms"] = client(describe_key=lambda **_: {"KeyMetadata": {"KeyManager": "AWS"}})
    out = run(resilience.get_backup_posture, finding("AWS::Backup::BackupVault", "prod-vault"))
    assert out["vault"]["encryption_key_manager"] == "AWS" and out["vault"]["denies_delete"] is True


# ---------------------------------------------------------------- cost anomaly

def test_anomaly_details_match(aws):
    aws["ce"] = client(get_anomalies=lambda **_: {"Anomalies": [
        {"AnomalyId": "arn:aws:ce::1:anomaly/anomaly-7f3e2a", "Impact": {"TotalImpact": 142.0},
         "RootCauses": [{"Service": "Amazon EC2", "Region": "us-east-1"}], "Feedback": "PLANNED_ACTIVITY"}]})
    out = run(cost_anomaly.get_anomaly_details, finding("AWS::CostExplorer::Anomaly", "anomaly-7f3e2a"))
    assert out["anomaly"]["total_impact_usd"] == 142.0 and out["anomaly"]["feedback"] == "PLANNED_ACTIVITY"


def test_spend_breakdown_movers_and_service_alias(aws):
    seen = {}

    def day(i, a, b):
        return {"TimePeriod": {"Start": f"d{i}"}, "Groups": [
            {"Keys": ["BoxUsage"], "Metrics": {"UnblendedCost": {"Amount": str(a)}}},
            {"Keys": ["DataTransfer"], "Metrics": {"UnblendedCost": {"Amount": str(b)}}}]}

    def cau(**kw):
        seen.update(kw)
        return {"ResultsByTime": [day(i, 10, 1) for i in range(7)] + [day(7 + i, 40, 1) for i in range(3)]}
    aws["ce"] = client(get_cost_and_usage=cau, get_dimension_values=err("ShouldNotBeCalled"))
    f = finding("AWS::CostExplorer::ServiceSpike", "spike", evidence={"service": "Amazon EC2"})
    out = run(cost_anomaly.get_spend_breakdown, f, group_by="usage_type", days=10)
    services = [x["Dimensions"]["Values"] for x in seen["Filter"]["And"] if x["Dimensions"]["Key"] == "SERVICE"]
    assert services == [["Amazon Elastic Compute Cloud - Compute"]] and not out["errors"]
    assert out["top_movers"][0] == {"group": "BoxUsage", "recent_daily_usd": 40.0, "baseline_daily_usd": 10.0,
                                    "increase_daily_usd": 30.0}


# ---------------------------------------------------------------- access

def test_analyzer_finding_searched_across_analyzers(aws):
    aws["accessanalyzer"] = client(
        list_analyzers=lambda: {"analyzers": [{"name": "a1", "arn": "arn:1", "type": "ACCOUNT_UNUSED_ACCESS",
                                               "status": "ACTIVE"},
                                              {"name": "a2", "arn": "arn:2", "type": "ORGANIZATION", "status": "ACTIVE"}]},
        list_archive_rules=lambda **_: {"archiveRules": []},
        get_finding_v2=lambda **kw: err("ResourceNotFoundException")() if kw["analyzerArn"] == "arn:1" else {
            "status": "ACTIVE", "findingType": "ExternalAccess", "findingDetails": [{"externalAccessDetails": {
                "principal": {"AWS": "999988887777"}, "action": ["s3:GetObject"], "isPublic": False,
                "condition": {}, "sources": [{"type": "POLICY"}]}}]})
    out = run(access.get_analyzer_findings, finding("AWS::AccessAnalyzer::Finding", "f-1"))
    assert out["analyzer"] == "a2" and out["details"][0]["actions"] == ["s3:GetObject"] and not out["errors"]


def test_missing_analyzer_reports_types(aws):
    aws["accessanalyzer"] = client(list_analyzers=lambda: {"analyzers": [
        {"name": "u", "arn": "arn:u", "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE"}]},
        list_archive_rules=lambda **_: {"archiveRules": [{}]})
    out = run(access.get_analyzer_findings, finding("AWS::AccessAnalyzer::Analyzer", "us-east-1"))
    assert out["external_access_analyzer"] is False and out["unused_access_analyzer"] is True


def test_service_last_accessed_polls(aws, monkeypatch):
    monkeypatch.setattr(access.time, "sleep", lambda s: None)
    replies = iter([{"JobStatus": "IN_PROGRESS"}, {"JobStatus": "COMPLETED", "ServicesLastAccessed": [
        {"ServiceNamespace": "s3", "LastAuthenticated": NOW - timedelta(days=3)},
        {"ServiceNamespace": "ec2"}, {"ServiceNamespace": "iam"}]}])
    aws["iam"] = client(generate_service_last_accessed_details=lambda **kw: {"JobId": "j"},
                        get_service_last_accessed_details=lambda **kw: next(replies))
    out = run(access.get_service_last_accessed, finding("AWS::IAM::Role", "old-etl-role"))
    assert out["principal"] == f"arn:aws:iam::{ACCT}:role/old-etl-role"
    assert (out["services_granted"], out["services_used"], out["never_used"]) == (3, 1, 2)


# ---------------------------------------------------------------- agents

ALLOWED_TOOL_ARGS = {"days", "hours", "include_read_only", "group_by"}


@pytest.mark.parametrize("agent_id", sorted(routing.AGENT_MODULES))
def test_every_agent_builds_and_tools_take_no_resource_argument(agent_id, monkeypatch):
    monkeypatch.setattr("agents.subagents.model.base_session", lambda *a, **k: None)
    agent = importlib.import_module(routing.AGENT_MODULES[agent_id]).build_agent()
    assert agent.tool_names, agent_id
    for name in agent.tool_names:
        spec = agent.tool_registry.registry[name].tool_spec
        args = set(spec["inputSchema"]["json"].get("properties", {}))
        assert args <= ALLOWED_TOOL_ARGS, f"{agent_id}.{name} lets the model choose {args - ALLOWED_TOOL_ARGS}"
