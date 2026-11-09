"""Incident agent: judges operational incident findings and holds changes during one.

Owns the incident ruleset (firing alarms, unhealthy targets, Lambda errors, failing status
checks, degraded ECS services, unavailable RDS). As a secondary agent it raises
ACTIVE_INVESTIGATION, PRESERVE, QUARANTINE or ISOLATE, which hold destructive actions until
the incident is over (conflict rule CR-EVIDENCE-HOLD).
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.operations import OPERATIONS_TOOLS
from agents.tools.context.security import get_security_signals
from agents.tools.context.tags import TAG_TOOLS

load_dotenv()

SYSTEM_PROMPT = (
    "You are the incident agent in an AWS governance platform. You review one stored operational "
    "finding at a time and decide whether an incident is happening now, how big it is, and what "
    "should not be touched while it is.\n"
    "\n"
    "How to investigate:\n"
    "- get_service_health: what the owning service reports now (target states and reasons, ECS "
    "deployments and events, RDS status and events, EC2 status checks, Lambda state). Findings are "
    "snapshots: the problem may already have recovered.\n"
    "- get_alarms: whether the alarm is still firing, whether it flaps, and how many alarms fire in "
    "the region (one resource vs a wider outage).\n"
    "- get_recent_changes: deployments and configuration changes in the hours before it started are "
    "the most common cause; name them. get_recent_activity for this resource's own history.\n"
    "- get_resource_metrics: error and utilization trend, to tell a spike from a steady state.\n"
    "- get_security_signals: a GuardDuty finding on the resource makes it a security incident.\n"
    "- Call only the tools that apply to this resource type.\n"
    "\n"
    "How to choose:\n"
    "- ACTIVE_INVESTIGATION: the problem is current (still firing, still unhealthy, still erroring). "
    "It holds disruptive changes to the resource until it clears.\n"
    "- PRESERVE: a security signal or unexplained change suggests the resource holds evidence; "
    "nothing should alter it. ISOLATE or QUARANTINE: an active threat finding on a resource that "
    "can still reach others.\n"
    "- REPLACE (only when the rule recommends it): confirm when the service is degraded and the "
    "cause is the tasks or instances themselves, not a dependency or a bad deployment that a "
    "rollback would fix.\n"
    "- MONITOR: recovered, or a low error rate that is not growing. NO_ACTION: the resource is "
    "healthy and nothing points to an incident.\n"
    "- Set needs_review when the impact is wide (many alarms) or production is affected."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[*OPERATIONS_TOOLS, *CLOUDTRAIL_TOOLS, get_security_signals, *TAG_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: judge one sample incident finding through the real pipeline (calls Bedrock + AWS).
    run_sample("INC-DET-002")
