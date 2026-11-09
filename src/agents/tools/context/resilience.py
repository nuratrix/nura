"""Backup and DR context: is the resource recoverable, and is anything running right now.

Backup-DR is often the *secondary* agent: before infra deletes a snapshot or cost cuts a
retention period, it checks whether that copy is the only recovery point, whether a backup
or restore is in flight, and whether a DR test is scheduled. Read-only; the resource comes
from the finding under review.
"""
from __future__ import annotations

from strands import ToolContext, tool

from agents.tools.context.aws_calls import ABSENT, MAX_ITEMS, ago, call, days_since, iso, name_of, ok, result
from agents.tools.context.finding_context import current_finding, finding_session, resource_arn
from agents.tools.context.security import summarize_policy

# Resource types whose ARN AWS Backup can protect (resource_arn knows how to build them).
PROTECTABLE = {"AWS::EC2::Instance", "AWS::EC2::Volume", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster",
               "AWS::S3::Bucket", "AWS::DynamoDB::Table", "AWS::EFS::FileSystem"}


def _plans(backup, errors: list) -> list[dict] | None:
    resp = call(errors, "ListBackupPlans", backup.list_backup_plans)
    if resp is None:
        return None
    plans = []
    for p in resp.get("BackupPlansList", [])[:MAX_ITEMS]:
        detail = ok(call(errors, f"GetBackupPlan {p.get('BackupPlanName')}", backup.get_backup_plan,
                         BackupPlanId=p["BackupPlanId"])).get("BackupPlan", {})
        sel = call(errors, "ListBackupSelections", backup.list_backup_selections, BackupPlanId=p["BackupPlanId"])
        rules = []
        for r in detail.get("Rules", []):
            copies = [c.get("DestinationBackupVaultArn", "") for c in r.get("CopyActions", [])]
            rules.append({"rule": r.get("RuleName"), "schedule": r.get("ScheduleExpression"),
                          "retention_days": (r.get("Lifecycle") or {}).get("DeleteAfterDays"),
                          "copy_to_regions": sorted({c.split(":")[3] for c in copies if c.count(":") > 3}),
                          "copy_to_accounts": sorted({c.split(":")[4] for c in copies if c.count(":") > 4})})
        plans.append({"name": p.get("BackupPlanName"), "id": p["BackupPlanId"],
                      "last_run": iso(p.get("LastExecutionDate")), "rules": rules,
                      "selections": None if sel is None else len(sel.get("BackupSelectionsList", []))})
    return plans


def _jobs(backup, errors: list, resource_arn_: str | None) -> dict:
    by_res = {"ByResourceArn": resource_arn_} if resource_arn_ else {}
    failed = call(errors, "ListBackupJobs FAILED", backup.list_backup_jobs, ByState="FAILED",
                  ByCreatedAfter=ago(days=7), **by_res)
    running = call(errors, "ListBackupJobs RUNNING", backup.list_backup_jobs, ByState="RUNNING", **by_res)
    restores = call(errors, "ListRestoreJobs RUNNING", backup.list_restore_jobs, ByStatus="RUNNING")
    fails = ok(failed).get("BackupJobs", [])
    messages: dict[str, int] = {}
    for j in fails:
        m = (j.get("StatusMessage") or "unknown")[:160]
        messages[m] = messages.get(m, 0) + 1
    return {"failed_jobs_7d": None if failed is None else len(fails),
            "failure_reasons": dict(sorted(messages.items(), key=lambda kv: -kv[1])[:5]),
            "failed_by_plan": {pid: sum(1 for j in fails if (j.get("CreatedBy") or {}).get("BackupPlanId") == pid)
                               for pid in {(j.get("CreatedBy") or {}).get("BackupPlanId") for j in fails} if pid},
            "backup_jobs_running": None if running is None else len(running.get("BackupJobs", [])),
            "restore_jobs_running": None if restores is None else len(restores.get("RestoreJobs", []))}


def _vault(s, backup, name: str, acct: str, errors: list) -> dict:
    v = call(errors, "DescribeBackupVault", backup.describe_backup_vault, BackupVaultName=name,
             absent=("ResourceNotFoundException",))
    if v is ABSENT:
        return {"exists": False}
    v = ok(v)
    pol = call(errors, "GetBackupVaultAccessPolicy", backup.get_backup_vault_access_policy, BackupVaultName=name,
               absent=("ResourceNotFoundException",))
    key_manager = None
    if v.get("EncryptionKeyArn"):
        key = call(errors, "KMS DescribeKey", s.client("kms").describe_key, KeyId=v["EncryptionKeyArn"])
        key_manager = ok(key).get("KeyMetadata", {}).get("KeyManager")
    return {"exists": True if v else None, "recovery_points": v.get("NumberOfRecoveryPoints"),
            "encryption_key_manager": key_manager, "vault_lock": v.get("Locked"),
            "lock_min_retention_days": v.get("MinRetentionDays"),
            "access_policy": None if pol is None else "none" if pol is ABSENT else summarize_policy(pol["Policy"], acct),
            "denies_delete": isinstance(pol, dict) and "DeleteRecoveryPoint" in pol.get("Policy", "")
            and '"Deny"' in pol.get("Policy", "")}


@tool(context=True)
def get_backup_posture(tool_context: ToolContext) -> dict:
    """Backup and recovery facts for the finding's resource and its account/region.

    Always: backup plans (schedule, retention, cross-region and cross-account copies, how many
    selections), failed backup jobs in the last 7 days with reasons, and backup or restore jobs
    running now (a change during one should wait). Restore testing plans (DR tests).
    Protectable resource (EC2, EBS, RDS, S3, DynamoDB, EFS): its recovery points, the newest one's
    age, and whether AWS Backup protects it. Backup vault: encryption key (customer or AWS
    managed), vault lock, access policy and whether it denies deleting recovery points.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, errors = finding_session(f), f["resource_type"], f["resource_id"], []
    backup = s.client("backup")
    arn = resource_arn(f) if rtype in PROTECTABLE else None

    facts: dict = {"plans": _plans(backup, errors), **_jobs(backup, errors, arn)}
    tests = call(errors, "ListRestoreTestingPlans", backup.list_restore_testing_plans)
    facts["restore_testing_plans"] = None if tests is None else [
        {"name": t.get("RestoreTestingPlanName"), "schedule": t.get("ScheduleExpression"),
         "last_run": iso(t.get("LastExecutionTime"))} for t in tests.get("RestoreTestingPlans", [])]

    if arn:
        prot = call(errors, "DescribeProtectedResource", backup.describe_protected_resource, ResourceArn=arn,
                    absent=("ResourceNotFoundException",))
        rps = call(errors, "ListRecoveryPointsByResource", backup.list_recovery_points_by_resource,
                   ResourceArn=arn, absent=("ResourceNotFoundException",))
        points = ok(rps).get("RecoveryPoints", [])
        newest = max((p.get("CreationDate") for p in points if p.get("CreationDate")), default=None)
        facts.update(protected_by_aws_backup=None if prot is None else prot is not ABSENT,
                     last_backup_days_ago=days_since(ok(prot).get("LastBackupTime") or newest),
                     recovery_points=None if rps is None else len(points),
                     recovery_point_vaults=sorted({p.get("BackupVaultName") for p in points})[:MAX_ITEMS])
    elif rtype == "AWS::Backup::BackupVault":
        facts["vault"] = _vault(s, backup, name_of(rid.split("backup-vault:")[-1]), f["account_id"], errors)
    elif rtype == "AWS::Backup::BackupPlan" and facts["plans"] is not None:
        facts["this_plan"] = next((p for p in facts["plans"] if rid in (p["name"], p["id"])), None)
    return result(f, errors, **facts)


RESILIENCE_TOOLS = [get_backup_posture]
