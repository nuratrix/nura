"""Cost agent: judges cost findings with context the scanner didn't have.

Called by orchestrator/synthesize.py with invocation_state={"finding": ...}; the tags and
CloudTrail tools read the resource from that finding.
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.cost import COST_TOOLS
from agents.tools.context.tags import TAG_TOOLS

load_dotenv()

SYSTEM_PROMPT = (
    "You are the cost agent in an AWS governance platform. You review one stored finding at a "
    "time and decide whether its cost recommendation should go ahead.\n"
    "- Always check the resource's tags and its recent CloudTrail activity before deciding.\n"
    "- Signs a cleanup is wrong or premature: production tags, a do-not-delete or exception tag, "
    "or recent write activity (attached, started, modified) by a person or pipeline.\n"
    "- Use the Cost Explorer tools only when spend context changes the decision.\n"
    "- Base every statement on tool output or the finding. If a tool fails, say so; never guess."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[*TAG_TOOLS, *CLOUDTRAIL_TOOLS, *COST_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: judge one sample cost finding through the real pipeline (calls Bedrock + AWS).
    run_sample("COST-EC2-001")
