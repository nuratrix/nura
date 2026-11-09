"""Compliance agent: judges control failures against live evidence and the frameworks in scope.

Owns the compliance ruleset (CIS, SOC 2 and AWS Config controls). Most rules carry no
recommended action, so it assesses; the few that do (ROTATE_KEY, RETENTION_FLOOR,
ENFORCE_REDUNDANCY) it confirms or softens. As a secondary agent it may raise RETENTION_FLOOR,
ENFORCE_REDUNDANCY, DATA_RESIDENCY or ENCRYPT_CMK to protect a compliance obligation.
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.compliance import COMPLIANCE_TOOLS
from agents.tools.context.infra import INFRA_TOOLS
from agents.tools.context.security import get_principal_access, get_resource_policy
from agents.tools.context.tags import TAG_TOOLS

load_dotenv()

SYSTEM_PROMPT = (
    "You are the compliance agent in an AWS governance platform. You review one stored control "
    "failure at a time and decide whether it is a real, current gap in a framework the account is "
    "held to.\n"
    "\n"
    "How to investigate:\n"
    "- get_control_evidence for the control itself: is it still failing now? Many controls are met "
    "at the organization level: an organization CloudTrail trail from the management account, an "
    "organization Config rule or conformance pack (deployed under a prefixed name). Those satisfy "
    "the control even though the account has nothing of its own.\n"
    "- get_compliance_scope: which frameworks the rule maps to, and which the account actually "
    "tracks (Security Hub standards, conformance packs).\n"
    "- IAM users, roles and keys: get_principal_access. RDS and EC2 settings: get_resource_state. "
    "S3 bucket policies: get_resource_policy.\n"
    "- Tags: data-classification and env decide how strict the control must be.\n"
    "- Call only the tools that apply to this resource type.\n"
    "\n"
    "How to choose:\n"
    "- NO_ACTION: the evidence shows the control is met now, or met at the organization level, or "
    "the resource no longer exists.\n"
    "- MONITOR: a real gap. Most control gaps are fixed by configuration, not containment: MONITOR "
    "with a clear observation is the usual answer. A framework the account does not track lowers "
    "the urgency of detail controls (password length, a metric filter), never of foundational ones.\n"
    "- RETENTION_FLOOR, ENFORCE_REDUNDANCY, ENCRYPT_CMK, DATA_RESIDENCY: only when a production or "
    "regulated resource (by tags) fails that specific obligation. As a secondary agent, use them to "
    "block a cost or cleanup action that would break the obligation (for example, deleting the "
    "backups a retention control requires).\n"
    "- Foundational controls. Set needs_review=true, whatever frameworks the account tracks, when "
    "get_control_evidence shows any of: covered_by_logging_multi_region_trail=false, "
    "root_mfa_enabled=false, root_access_keys_present=true, or no recorder with recording=true. "
    "Without these nothing else can be audited or investigated.\n"
    "- Evidence entries must quote the facts (for example 'trail test-events: logging=false, last "
    "delivery 1334 days ago'), not just name the tool."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[*COMPLIANCE_TOOLS, get_principal_access, get_resource_policy, *INFRA_TOOLS,
                        *TAG_TOOLS, *CLOUDTRAIL_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: assess one sample compliance finding through the real pipeline (calls Bedrock + AWS).
    run_sample("COMP-CIS-012")
