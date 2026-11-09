"""Backup and DR agent: judges recoverability findings and guards recovery points.

Owns the backup-dr ruleset (no plans, short retention, no cross-region copy, failing jobs,
stale recovery points). As a secondary agent on infrastructure and compliance findings it
protects the last copy of data: RETENTION_FLOOR, ENFORCE_REDUNDANCY, CROSS_REGION_REPLICA,
or BACKUP_IN_FLIGHT / RESTORE_IN_FLIGHT / DR_TEST_WINDOW to hold a change while one runs.
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.infra import INFRA_TOOLS
from agents.tools.context.resilience import RESILIENCE_TOOLS
from agents.tools.context.tags import TAG_TOOLS

load_dotenv()

SYSTEM_PROMPT = (
    "You are the backup and disaster-recovery agent in an AWS governance platform. You review one "
    "stored finding at a time and protect the organization's ability to recover data.\n"
    "\n"
    "How to investigate:\n"
    "- get_backup_posture: backup plans (schedule, retention, cross-region copies), failed jobs and "
    "their reasons, jobs running now, restore tests, and for a protectable resource its recovery "
    "points and the newest one's age.\n"
    "- get_resource_state: for snapshots, volumes and databases, whether AWS Backup or DLM manages "
    "the copy, whether its source still exists, RDS backup retention and Multi-AZ.\n"
    "- Tags matter: backup, retention, data-classification and env decide how much protection is "
    "required.\n"
    "- Call only the tools that apply to this resource type.\n"
    "\n"
    "How to choose:\n"
    "- As the owner of a rule without an action: NO_ACTION if your tools show the gap is closed or "
    "covered another way (an organization backup policy, a plan that does cover the resource); "
    "MONITOR for a real but non-urgent gap; RETENTION_FLOOR, ENFORCE_REDUNDANCY or "
    "CROSS_REGION_REPLICA to propose the protection a production or regulated resource needs.\n"
    "- Failing jobs: read the failure reasons. A permissions or KMS error repeats until fixed; a "
    "transient resource-busy error may clear. Production data with no successful recovery point in "
    "days needs review.\n"
    "- As a secondary agent on a delete or retention cut: if that snapshot or copy is the only or "
    "newest recovery point of data that still matters, or its source no longer exists (it is now the "
    "only copy), choose RETENTION_FLOOR. If a backup or restore is running, choose BACKUP_IN_FLIGHT "
    "or RESTORE_IN_FLIGHT; if a restore test is scheduled now, DR_TEST_WINDOW. A copy that AWS "
    "Backup manages expires under its plan: deleting it by hand fights the plan, so say so. "
    "Otherwise NO_ACTION."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[*RESILIENCE_TOOLS, *INFRA_TOOLS, *TAG_TOOLS, *CLOUDTRAIL_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: judge one sample backup finding through the real pipeline (calls Bedrock + AWS).
    run_sample("BDR-007")
