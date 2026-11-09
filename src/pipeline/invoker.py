"""SQS nura-high-critical -> AgentCore runtime: one finding per message.
Inlined by deploy/deploy_intake.ps1 (CloudFormation ZipFile): keep under 4 KB.
Acked: runtime says not found / bad request. Retried (3x, then DLQ): anything else.
"""
import json
import logging
import os
import uuid

import boto3
from botocore.config import Config

log = logging.getLogger()
log.setLevel(logging.INFO)
_client = None


def _agentcore():
    global _client
    if _client is None:
        # One judgment takes 1-3 min: the 60s default read timeout would cut it off, and
        # botocore's retry would run the same judgment twice. SQS owns retries instead.
        _client = boto3.client("bedrock-agentcore", config=Config(
            read_timeout=280, connect_timeout=10, retries={"max_attempts": 1}))
    return _client


def judge(finding_id):
    resp = _agentcore().invoke_agent_runtime(
        agentRuntimeArn=os.environ["AGENT_RUNTIME_ARN"],
        qualifier=os.environ.get("AGENT_RUNTIME_QUALIFIER", "DEFAULT"),
        runtimeSessionId=f"nura-judgment-{uuid.uuid4()}",   # >= 33 chars, one per judgment
        contentType="application/json", accept="application/json",
        payload=json.dumps({"finding_id": finding_id}).encode())
    if resp.get("statusCode", 200) >= 400:
        raise RuntimeError(f"runtime returned {resp['statusCode']}")
    return json.loads(resp["response"].read())


def handler(event, context):
    failures = []
    for record in event["Records"]:
        try:
            finding_id = json.loads(record["body"])["finding_id"]
            result = judge(finding_id)
            if "error" in result:   # retrying cannot fix a missing finding
                log.warning(json.dumps({"finding_id": finding_id, "dropped": result["error"]}))
            else:
                log.info(json.dumps({"finding_id": finding_id, **{
                    k: result.get(k) for k in ("outcome", "requires_human", "decision_record",
                                               "sns_message_id")}}))
        except Exception:
            log.exception("judgment failed, message %s", record["messageId"])
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
