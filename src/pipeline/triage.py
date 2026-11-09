"""
Reads findings from the FINDINGS_SOURCE (a file path or dynamodb). 
Publishes Low/Medium to DecisionLog S3 and queues High/Critical for Orchestrator.
with batch_size=1 calls AgentCore runtime.
"""
import json
import logging
import os
from datetime import datetime, timezone

import boto3
from common.findings_repo import get_findings
from common.decision_log import save_findings_2_decisionlog

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SQS_BATCH = 10  # SendMessageBatch limit

def queue_findings(findings, sqs=None, queue_url=None, now=None):
    """Send HIGH/CRITICAL findings to SQS in batches of 10. Returns how many were sent."""
    sqs = sqs or boto3.client("sqs")
    queue_url = queue_url or os.environ["High_Critical_Queue_Url"]
    now = now or datetime.now(timezone.utc).isoformat()
    failed = []
    for i in range(0, len(findings), SQS_BATCH):
        chunk = findings[i:i + SQS_BATCH]
        resp = sqs.send_message_batch(QueueUrl=queue_url, Entries=[
            {"Id": str(j),   # SQS Ids allow only letters, digits, - and _
             "MessageBody": json.dumps({
                 "finding_id": f.finding_id, "rule_id": f.rule_id, "domain": f.domain,
                 "severity": f.severity, "recommendation": f.recommendation,
                 "requested_at": now})}
            for j, f in enumerate(chunk)])
        failed += [f"{chunk[int(e['Id'])].finding_id}: {e.get('Message', e.get('Code'))}"
                   for e in resp.get("Failed", [])]
    if failed:
        raise RuntimeError(f"{len(failed)} findings not queued: {failed}")
    return len(findings)


def triage():
    findings, errors = get_findings()
    for e in errors:
        logger.warning("Skipped finding: %s", e)

    low, high = [], []
    for f in findings:
        (low if f.severity.upper() in ("LOW", "MEDIUM") else high).append(f)

    save_findings_2_decisionlog(low)
    if high:
        queue_findings(high)
    return {"logged": len(low), "queued": len(high), "errors": len(errors)}


def lambda_handler(event, context):
    return triage()


if __name__ == "__main__":
    print(triage())
    
