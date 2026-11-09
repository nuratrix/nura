from agents.orchestrator import conflicts, remediation, routing, synthesize
from common.decision_log import write_decision
from common.findings_repo import get_finding
from common.notify import publish_decision


def decide(finding: dict) -> tuple[dict, dict]:
    """Judge one finding: returns (synthesis, decision). No side effects besides the agents' reads."""
    route = routing.route(finding["rule_id"])                 # code picks agents, not the LLM
    result = synthesize.run(finding, route)                   # the only LLM step
    decision = conflicts.apply(result)                        # deterministic: what should happen
    decision = remediation.attach(decision, finding, route)   # deterministic: how it may happen
    return result, decision


def handle(finding: dict) -> dict:
    """Judge one finding, write it to the decision log, publish it, and return the decision.

    Order matters: the WORM record is written before anyone is notified, so every
    notification points at evidence that already exists. If publishing fails the
    exception propagates and SQS retries the finding; the retry is judged and logged
    again as a separate record (the log keeps every attempt).
    """
    result, decision = decide(finding)
    record = write_decision(finding, result, decision)        # WORM audit, S3 Object Lock
    message_id = publish_decision(finding, decision, record)  # SNS: review, email, Teams
    return {**decision, "decision_record": f"s3://{record['bucket']}/{record['key']}",
            "sns_message_id": message_id}


def handle_by_id(finding_id: str) -> dict:
    finding = get_finding(finding_id)
    if finding is None:
        raise LookupError(f"finding not found: {finding_id}")
    return handle(finding)
