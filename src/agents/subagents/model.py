"""Shared pieces for the domain agents: the Bedrock model and a live-run entry point."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from strands.models import BedrockModel

from common.aws_session import base_session


def bedrock_model(temperature: float = 0.1) -> BedrockModel:
    """BEDROCK_MODEL_ID (default Nova Pro). Low temperature: judgments should be repeatable."""
    return BedrockModel(model_id=os.getenv("BEDROCK_MODEL_ID", "amazon.nova-pro-v1:0"),
                        boto_session=base_session(), temperature=temperature)


def run_sample(default_rule_id: str, argv: list[str] | None = None) -> None:
    """Judge one finding from data/sample_findings.json through the real pipeline.

        python -m agents.subagents.<agent> [RULE_ID] [--publish]

    --publish runs handle(): writes the decision log record and publishes to SNS.
    Without it, decide() only: prints the synthesis and decision, no writes.
    """
    from agents.orchestrator.orchestrator_agent import decide, handle

    argv = sys.argv[1:] if argv is None else argv
    publish = "--publish" in argv
    args = [a for a in argv if a != "--publish"]
    rule_id = args[0] if args else default_rule_id
    findings = json.loads((Path(__file__).resolve().parents[3] / "data" / "sample_findings.json")
                          .read_text(encoding="utf-8"))
    finding = next((f for f in findings if f["rule_id"] == rule_id), None)
    if finding is None:
        sys.exit(f"No sample finding for {rule_id}")
    if publish:
        print(json.dumps(handle(finding), indent=2, default=str))
    else:
        result, decision = decide(finding)
        print(json.dumps({"synthesis": result, "decision": decision}, indent=2, default=str))
