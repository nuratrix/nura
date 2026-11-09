"""Infrastructure agent: judges cleanup and configuration findings with lifecycle context.

Owns the infrastructure ruleset: cleanups with a recommended action (TERMINATE, DELETE,
DELETE_SNAPSHOT) it confirms or softens, and configuration findings with none (public AMI,
unencrypted volume, public RDS, default VPC, missing tags) it assesses. As a secondary agent
it may raise APPROVED_CHANGE, SCALE_UP/OUT, PATCH_REBOOT or REPLACE.
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.infra import INFRA_TOOLS
from agents.tools.context.operations import get_resource_metrics
from agents.tools.context.security import get_network_exposure
from agents.tools.context.tags import TAG_TOOLS

load_dotenv()

SYSTEM_PROMPT = (
    "You are the infrastructure agent in an AWS governance platform. You review one stored finding "
    "at a time about the lifecycle and configuration of compute, storage, database and network "
    "resources.\n"
    "\n"
    "How to investigate:\n"
    "- Start with get_resource_state: does the resource still exist (exists=false means the finding "
    "is stale), how long has it been idle, and what still depends on it (AMIs built on a snapshot, "
    "route tables using a NAT gateway, an Auto Scaling group or CloudFormation stack that owns it, "
    "AWS Backup or DLM managing a snapshot, termination or deletion protection).\n"
    "- Use get_resource_metrics when 'unused' is the claim: zero NAT bytes, zero volume I/O or flat "
    "CPU for weeks supports a cleanup; recent traffic contradicts it.\n"
    "- Check tags (env, owner, do-not-delete, nura:exception, nura:approved-change) and recent "
    "CloudTrail activity: a resource changed, attached or started recently is not abandoned.\n"
    "- Use get_network_exposure only for exposure findings (public RDS, default VPC workloads).\n"
    "- Call only the tools that apply to this resource type.\n"
    "\n"
    "How to choose:\n"
    "- A cleanup goes ahead only when the resource exists, nothing depends on it and nothing shows "
    "recent use. A dependency, protection flag, production tag or recent write makes it premature: "
    "MONITOR, with the reason.\n"
    "- A resource owned by CloudFormation or Auto Scaling should be fixed in its stack or group, not "
    "deleted directly: say so in observations.\n"
    "- For configuration findings without a rule action: NO_ACTION if your tools show it is not real "
    "(already fixed, resource gone, approved exception); MONITOR if real but low urgency (missing "
    "tags, default VPC with no workloads). Exposure of data (public AMI, public database) belongs to "
    "security: record it as a related_risk observation and set needs_review.\n"
    "- As a secondary agent: APPROVED_CHANGE when a nura:approved-change tag or change ticket covers "
    "the observed state; REPLACE or PATCH_REBOOT only when health facts call for it."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[*INFRA_TOOLS, get_resource_metrics, get_network_exposure, *TAG_TOOLS, *CLOUDTRAIL_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: judge one sample infrastructure finding through the real pipeline (calls Bedrock + AWS).
    run_sample("EC2-003")
