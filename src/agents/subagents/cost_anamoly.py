"""Cost anomaly agent: judges spend spikes and anomaly-detection coverage.

Owns the cost-anomaly ruleset (detected anomalies, service/account/region spikes, missing
monitors and alert subscriptions). Its rules carry no recommended action, so it assesses:
NO_ACTION, MONITOR or SPEND_SPIKE. As a secondary agent, SPEND_SPIKE marks a finding whose
resource is driving unexpected spend (it can also be a symptom of an incident).
"""
from dotenv import load_dotenv
from strands import Agent

from agents.subagents.model import bedrock_model, run_sample
from agents.tools.context.cost_anomaly import COST_ANOMALY_TOOLS
from agents.tools.context.operations import get_recent_changes

load_dotenv()

SYSTEM_PROMPT = (
    "You are the cost anomaly agent in an AWS governance platform. You review one stored finding "
    "at a time about unexpected spend, and decide whether it is a real, unexplained spike.\n"
    "\n"
    "How to investigate:\n"
    "- get_anomaly_details: what AWS Cost Anomaly Detection recorded (expected vs actual, root "
    "causes, feedback such as PLANNED_ACTIVITY), or for coverage findings which monitors and alert "
    "subscriptions exist.\n"
    "- get_spend_breakdown: where the money moved. Group by USAGE_TYPE to see what kind of usage "
    "grew (instance hours, data transfer, requests), by REGION for a new-region spike. Call it at "
    "most twice: Cost Explorer charges per request.\n"
    "- get_recent_changes: launches, scaling and configuration changes when the spike began explain "
    "most spikes; name them with who made them.\n"
    "\n"
    "How to choose:\n"
    "- SPEND_SPIKE: the increase is real, still running and not explained by a planned change or "
    "anomaly feedback. Say the daily increase in dollars and its driver.\n"
    "- MONITOR: real but explained (a launch by a known pipeline, a planned migration), small, or "
    "already over; or a coverage gap (no monitor, no subscription) to fix by configuration.\n"
    "- NO_ACTION: the breakdown shows no increase, or the anomaly was marked planned or a "
    "false positive.\n"
    "- Spend appearing in a region the account never used before, or from an identity that does not "
    "normally launch resources, can be compromise (crypto-mining): set needs_review and record it "
    "as a related_risk observation.\n"
    "- Never invent figures: quote the tool numbers."
)


def build_agent() -> Agent:
    return Agent(model=bedrock_model(), system_prompt=SYSTEM_PROMPT,
                 tools=[*COST_ANOMALY_TOOLS, get_recent_changes],
                 callback_handler=None)   # no streaming to stdout inside the orchestrator


if __name__ == "__main__":
    # Live run: assess one sample anomaly finding through the real pipeline (calls Bedrock + AWS).
    run_sample("COST-ANO-001")
