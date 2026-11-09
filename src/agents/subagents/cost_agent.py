"""Cost agent: judges cost findings with context the scanner didn't have.

Called by orchestrator/synthesize.py with invocation_state={"finding": ...}; the tags and
CloudTrail tools read the resource from that finding.
"""
import os

from dotenv import load_dotenv
from strands import Agent
from strands.models import BedrockModel

from agents.tools.context.cloudtrail import CLOUDTRAIL_TOOLS
from agents.tools.context.cost import COST_TOOLS
from agents.tools.context.tags import TAG_TOOLS
from common.aws_session import base_session

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
    model = BedrockModel(
        model_id=os.getenv("BEDROCK_MODEL_ID", "amazon.nova-pro-v1:0"),
        boto_session=base_session(),
        temperature=0.1,
    )
    return Agent(model=model, system_prompt=SYSTEM_PROMPT,
                 tools=[*TAG_TOOLS, *CLOUDTRAIL_TOOLS, *COST_TOOLS],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: judge one sample cost finding through the real pipeline (calls Bedrock + AWS).
    import json
    import sys
    from pathlib import Path

    from agents.orchestrator.orchestrator_agent import decide, handle

    findings = json.loads((Path(__file__).resolve().parents[3] / "data" / "sample_findings.json")
                          .read_text(encoding="utf-8"))
    # --publish: full handle() -> writes the decision log record and publishes to SNS
    publish = "--publish" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--publish"]
    rule_id = args[0] if args else "COST-EC2-001"
    finding = next((f for f in findings if f["rule_id"] == rule_id), None)
    if finding is None:
        sys.exit(f"No sample finding for {rule_id}")
    if publish:
        print(json.dumps(handle(finding), indent=2, default=str))
    else:
        result, decision = decide(finding)
        print(json.dumps({"synthesis": result, "decision": decision}, indent=2, default=str))
