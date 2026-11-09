import io
import json
from pathlib import Path

import pytest

from pipeline import invoker


class FakeAgentCore:
    def __init__(self, reply=None, exc=None, status=200):
        self.reply, self.exc, self.status, self.calls = reply, exc, status, []

    def invoke_agent_runtime(self, **kw):
        self.calls.append(kw)
        if self.exc:
            raise self.exc
        return {"statusCode": self.status, "response": io.BytesIO(json.dumps(self.reply).encode())}


def event(*bodies):
    return {"Records": [{"messageId": f"m{i}", "body": b if isinstance(b, str) else json.dumps(b)}
                        for i, b in enumerate(bodies)]}


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setenv("AGENT_RUNTIME_ARN", "arn:aws:bedrock-agentcore:us-east-1:1:runtime/nura_judgment-x")
    def install(**kw):
        client = FakeAgentCore(**kw)
        monkeypatch.setattr(invoker, "_client", client)
        return client
    return install


def test_success_acks_and_sends_finding_id(fake):
    client = fake(reply={"outcome": "RESOLVED", "decision_record": "s3://decisionlog/k"})
    assert invoker.handler(event({"finding_id": "a#b#c#d", "severity": "HIGH"}), None) == {"batchItemFailures": []}
    call = client.calls[0]
    assert json.loads(call["payload"]) == {"finding_id": "a#b#c#d"}
    assert len(call["runtimeSessionId"]) >= 33 and call["qualifier"] == "DEFAULT"


def test_not_found_is_acked_not_retried(fake):
    fake(reply={"error": "finding not found: x"})
    assert invoker.handler(event({"finding_id": "x"}), None)["batchItemFailures"] == []


@pytest.mark.parametrize("kw", [{"exc": TimeoutError("read timeout")}, {"reply": {}, "status": 500}])
def test_runtime_failure_is_retried(fake, kw):
    fake(**kw)
    assert invoker.handler(event({"finding_id": "x"}), None)["batchItemFailures"] == [{"itemIdentifier": "m0"}]


def test_malformed_message_goes_to_retry_then_dlq(fake):
    fake(reply={})
    out = invoker.handler(event("not json", {"no_id": 1}), None)
    assert out["batchItemFailures"] == [{"itemIdentifier": "m0"}, {"itemIdentifier": "m1"}]


def test_fits_cloudformation_inline_limit():
    assert len(Path(invoker.__file__).read_text(encoding="utf-8")) < 4096
