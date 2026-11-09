"""synthesize.run with fake agents: no Bedrock calls."""
from types import SimpleNamespace

import pytest

from agents.orchestrator import conflicts, synthesize
from agents.orchestrator.routing import Route

FINDING = {"finding_id": "111#us-east-1#COST-EC2-003#vol-1", "rule_id": "COST-EC2-003",
           "title": "Unattached EBS volume", "severity": "HIGH", "resource_id": "vol-1",
           "evidence": {"days_unattached": 45}, "recommendation": "Delete vol-1."}


def route(agents, action):
    return Route(rule_id="COST-EC2-003", domain="cost", owner=agents[0], agents=tuple(agents),
                 recommended_action=action, ruleset_version="1.0")


class FakeAgent:
    """Mimics strands.Agent: returns the structured_output_model filled with `action`."""
    def __init__(self, action, calls):
        self.action, self.calls = action, calls

    def __call__(self, prompt, structured_output_model, invocation_state=None):
        self.calls.append(prompt)
        self.invocation_state = invocation_state
        out = structured_output_model(action=self.action, rationale="because", evidence=["tags: env=dev"])
        return SimpleNamespace(structured_output=out)


def loader(answers, calls=None):
    """answers: agent_id -> action | Exception | None (not built)."""
    calls = [] if calls is None else calls

    def load(agent_id):
        a = answers[agent_id]
        if isinstance(a, Exception):
            raise a
        return None if a is None else FakeAgent(a, calls)
    return load


def test_rule_only_when_owner_not_built():
    calls = []
    r = synthesize.run(FINDING, route(["security-agent"], None), loader({"security-agent": None}, calls))
    assert r["mode"] == "rule_only" and calls == []
    assert r["opinions"][0]["action"] == "NO_ACTION" and r["opinions"][0]["source"] == "rule"


def test_built_owner_assesses_rule_without_action():
    calls = []
    r = synthesize.run(FINDING, route(["security-agent"], None), loader({"security-agent": "QUARANTINE"}, calls))
    assert r["mode"] == "agents" and r["opinions"][0]["source"] == "llm"
    assert r["opinions"][0]["action"] == "QUARANTINE"
    assert "recommends no automated action" in calls[0]
    assert "QUARANTINE" in calls[0] and "REVOKE" in calls[0]          # its containment list is offered
    d = conflicts.apply(r)
    assert d["outcome"] == "RESOLVED" and d["actions"] == ["QUARANTINE"]


def test_assessing_owner_cannot_pick_another_domains_action():
    r = synthesize.run(FINDING, route(["security-agent"], None), loader({"security-agent": "DELETE"}))
    op = r["opinions"][0]
    assert (op["action"], op["source"]) == ("NO_ACTION", "fallback")   # rule baseline, error recorded
    assert "error" in op


def test_assessing_owner_failure_keeps_rule_baseline():
    r = synthesize.run(FINDING, route(["security-agent"], None),
                       loader({"security-agent": RuntimeError("throttled")}))
    assert r["mode"] == "agents"
    assert (r["opinions"][0]["action"], r["opinions"][0]["source"]) == ("NO_ACTION", "fallback")


def test_owner_confirms_and_secondary_objects():
    r = synthesize.run(FINDING, route(["cost-agent", "backup-dr-agent"], "DELETE"),
                       loader({"cost-agent": "DELETE", "backup-dr-agent": "RETENTION_FLOOR"}))
    assert [(o["agent"], o["action"], o["source"]) for o in r["opinions"]] == [
        ("cost-agent", "DELETE", "llm"), ("backup-dr-agent", "RETENTION_FLOOR", "llm")]
    assert conflicts.apply(r)["outcome"] == "ESCALATED"   # CR-PROTECT-VS-DELETE


def test_owner_can_soften():
    r = synthesize.run(FINDING, route(["cost-agent"], "DELETE"), loader({"cost-agent": "MONITOR"}))
    assert r["opinions"][0]["action"] == "MONITOR"
    assert conflicts.apply(r)["outcome"] == "NO_ACTION"


def test_owner_cannot_escalate_beyond_rule():
    # TERMINATE isn't in the owner's Literal, so the model can't be built with it -> fallback
    r = synthesize.run(FINDING, route(["cost-agent"], "DELETE"), loader({"cost-agent": "TERMINATE"}))
    op = r["opinions"][0]
    assert op["action"] == "DELETE" and op["source"] == "fallback"


@pytest.mark.parametrize("answer", [RuntimeError("bedrock timeout"), None, ImportError("bad import")])
def test_owner_failure_falls_back_to_rule(answer):
    r = synthesize.run(FINDING, route(["cost-agent"], "DELETE"), loader({"cost-agent": answer}))
    op = r["opinions"][0]
    assert (op["action"], op["source"]) == ("DELETE", "fallback") and "error" in op
    assert conflicts.apply(r)["outcome"] == "RESOLVED"


def test_secondary_failure_escalates():
    r = synthesize.run(FINDING, route(["cost-agent", "backup-dr-agent"], "DELETE"),
                       loader({"cost-agent": "DELETE", "backup-dr-agent": None}))
    assert r["incomplete"][0]["agent"] == "backup-dr-agent"
    d = conflicts.apply(r)
    assert d["outcome"] == "ESCALATED" and "backup-dr-agent" in d["reason"]


def test_secondary_outside_its_list_is_incomplete():
    r = synthesize.run(FINDING, route(["cost-agent", "backup-dr-agent"], "DELETE"),
                       loader({"cost-agent": "DELETE", "backup-dr-agent": "TERMINATE"}))
    assert r["incomplete"] and conflicts.apply(r)["outcome"] == "ESCALATED"


def test_unbuilt_owner_without_action_uses_rule_but_secondaries_run():
    calls = []
    r = synthesize.run(FINDING, route(["compliance-agent", "backup-dr-agent"], None),
                       loader({"compliance-agent": None, "backup-dr-agent": "NO_ACTION"}, calls))
    assert r["opinions"][0]["source"] == "rule" and len(calls) == 1
    assert r["mode"] == "agents"


def test_prompt_lists_allowed_actions():
    calls = []
    synthesize.run(FINDING, route(["cost-agent"], "DELETE"), loader({"cost-agent": "DELETE"}, calls))
    assert "Allowed actions: DELETE, MONITOR, NO_ACTION" in calls[0]
    assert "vol-1" in calls[0]


def test_finding_is_passed_to_tools_via_invocation_state():
    seen = []

    class Spy(FakeAgent):
        def __call__(self, prompt, structured_output_model, invocation_state=None):
            seen.append(invocation_state)
            return super().__call__(prompt, structured_output_model, invocation_state)

    synthesize.run(FINDING, route(["cost-agent"], "DELETE"), lambda _id: Spy("DELETE", []))
    assert seen == [{"finding": FINDING}]


# --- insights: observations, needs_review, tool trace ----------------------

class InsightAgent:
    """Fake agent that calls a tool, then answers with observations / needs_review."""
    def __init__(self, action, needs_review=False):
        self.action, self.needs_review, self.messages = action, needs_review, []

    def __call__(self, prompt, structured_output_model, invocation_state=None):
        self.messages = [
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "get_resource_tags", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "status": "success",
                                                         "content": [{"json": {"tags": {"env": "prod"}}}]}}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t2", "name": "AgentOpinion", "input": {}}}]},
        ]
        out = structured_output_model(
            action=self.action, rationale="r", evidence=["tags: env=prod"],
            observations=[{"type": "related_risk", "detail": "detached at 3am by unknown role",
                           "evidence": "get_recent_activity"}],
            needs_review=self.needs_review,
            review_reason="possible compromise" if self.needs_review else None)
        return SimpleNamespace(structured_output=out)


def test_observations_and_tool_trace_recorded():
    r = synthesize.run(FINDING, route(["cost-agent"], "DELETE"), lambda _id: InsightAgent("DELETE"))
    op = r["opinions"][0]
    assert op["observations"][0]["type"] == "related_risk"
    assert [c["tool"] for c in op["tool_calls"]] == ["get_resource_tags"]   # structured-output tool excluded
    call = op["tool_calls"][0]
    assert call["status"] == "success" and "prod" in call["output_preview"]
    assert len(call["output_sha256"]) == 64

    d = conflicts.apply(r)
    assert d["outcome"] == "RESOLVED"
    assert d["observations"] == [{"agent": "cost-agent", "type": "related_risk",
                                  "detail": "detached at 3am by unknown role", "evidence": "get_recent_activity"}]


def test_needs_review_escalates_but_keeps_recommendation():
    r = synthesize.run(FINDING, route(["cost-agent"], "DELETE"),
                       lambda _id: InsightAgent("DELETE", needs_review=True))
    d = conflicts.apply(r)
    assert d["outcome"] == "ESCALATED" and d["requires_human"]
    assert d["actions"] == ["DELETE"] and d["resolved_outcome"] == "RESOLVED"
    assert "possible compromise" in d["reason"]


def test_tool_output_is_capped_but_hashed_in_full():
    big = "x" * 5000
    calls = synthesize.tool_trace([
        {"content": [{"toolUse": {"toolUseId": "a", "name": "get_recent_activity", "input": {"days": 30}}}]},
        {"content": [{"toolResult": {"toolUseId": "a", "status": "success", "content": [{"text": big}]}}]},
    ])
    assert len(calls[0]["output_preview"]) == synthesize.PREVIEW_CHARS + 3
    assert calls[0]["input"] == {"days": 30}


def test_trace_id_links_to_otel(monkeypatch):
    from opentelemetry.sdk.trace import TracerProvider
    monkeypatch.setattr(synthesize, "tracer", TracerProvider().get_tracer("test"))
    r = synthesize.run(FINDING, route(["security-agent"], None), loader({}))
    assert r["trace_id"] and len(r["trace_id"]) == 32


def test_trace_id_none_without_otel():
    r = synthesize.run(FINDING, route(["security-agent"], None), loader({}))
    assert "trace_id" in r   # None unless an OTel SDK/exporter is configured
