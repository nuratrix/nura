"""Access analyzer agent: judges external and unused access findings.

Owns the access-analyzer ruleset (no analyzer, external/public access, unused keys and roles,
console users without MFA). Its rules carry no recommended action, so it assesses: NO_ACTION,
MONITOR, or REVOKE proposed to a person.
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.access import ACCESS_TOOLS
from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.security import get_principal_access, get_resource_policy
from agents.tools.context.tags import TAG_TOOLS

load_dotenv()

SYSTEM_PROMPT = (
    "You are the access analyzer agent in an AWS governance platform. You review one stored "
    "finding at a time about who can access what, and whether that access is still needed.\n"
    "\n"
    "How to investigate:\n"
    "- Unused keys, roles and users: get_principal_access (admin power, MFA, key age and last use, "
    "role last used, who may assume a role) and get_service_last_accessed (which granted services "
    "were actually used). An unused identity with admin power is far riskier than an unused "
    "read-only one.\n"
    "- External or public access findings: get_analyzer_findings for the principal, actions, "
    "conditions and whether it is public; get_resource_policy for the resource's own policy.\n"
    "- Missing analyzer findings: get_analyzer_findings lists analyzers in the region; an "
    "organization analyzer elsewhere may already cover this account, which you cannot see from "
    "here: record that as a data_quality observation rather than assuming a gap.\n"
    "- Tags (owner, nura:exception) and recent CloudTrail activity on the identity.\n"
    "- Call only the tools that apply to this resource type.\n"
    "\n"
    "How to choose:\n"
    "- REVOKE: access that is public or external without a limiting condition and not documented "
    "as intended; an access key or role unused for longer than the rule's threshold that still "
    "has meaningful permissions; a console user without MFA who has admin power.\n"
    "- MONITOR: real but limited (read-only, conditioned by aws:PrincipalOrgID or aws:SourceVpce, "
    "recently used, a break-glass identity documented by tags).\n"
    "- NO_ACTION: your tools show the access is gone, the identity was used recently, or an "
    "approved exception covers it.\n"
    "- Revoking a role or key used by an automated workload breaks it: when last use is recent or "
    "unknown, set needs_review."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[get_principal_access, *ACCESS_TOOLS, get_resource_policy, *TAG_TOOLS, *CLOUDTRAIL_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: assess one sample access finding through the real pipeline (calls Bedrock + AWS).
    run_sample("IAM-AA-004")
