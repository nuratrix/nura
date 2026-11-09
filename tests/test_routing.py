import json
import sys
import types
from pathlib import Path

import pytest

from agents.orchestrator import routing

DATA = Path(__file__).resolve().parents[1] / "data" / "sample_findings.json"


@pytest.fixture(autouse=True)
def fresh_cache():
    routing.reload()
    yield
    routing.reload()


def test_every_sample_finding_routes():
    findings = json.loads(DATA.read_text(encoding="utf-8"))
    for f in findings:
        r = routing.route(f["rule_id"])
        assert r.owner == r.agents[0]
        assert r.domain == f["domain"]


def test_owner_first_from_ruleset():
    r = routing.route("COST-EC2-001")
    assert r.owner == "cost-agent"
    assert r.agents == ("cost-agent",)
    assert r.recommended_action == "STOP"


def test_unknown_rule_raises():
    with pytest.raises(routing.RoutingError):
        routing.route("NOPE-000")


def _write_ruleset(folder, rules):
    folder.mkdir(exist_ok=True)
    (folder / "x.json").write_text(json.dumps({"schema_version": "1.0", "domain": "cost", "rules": rules}))


def _rule(rule_id, agents, enabled=True):
    return {"rule_id": rule_id, "domain": "cost", "enabled": enabled, "agents": agents, "recommended_action": None}


def test_disabled_rule_not_routed(tmp_path, monkeypatch):
    _write_ruleset(tmp_path, [_rule("R-1", ["cost-agent"], enabled=False)])
    monkeypatch.setenv("NURA_RULESETS_DIR", str(tmp_path))
    with pytest.raises(routing.RoutingError):
        routing.route("R-1")


def test_unknown_agent_rejected(tmp_path, monkeypatch):
    _write_ruleset(tmp_path, [_rule("R-1", ["ghost-agent"])])
    monkeypatch.setenv("NURA_RULESETS_DIR", str(tmp_path))
    with pytest.raises(routing.RoutingError, match="unknown"):
        routing.route("R-1")


def test_duplicate_rule_id_rejected(tmp_path, monkeypatch):
    _write_ruleset(tmp_path, [_rule("R-1", ["cost-agent"]), _rule("R-1", ["cost-agent"])])
    monkeypatch.setenv("NURA_RULESETS_DIR", str(tmp_path))
    with pytest.raises(routing.RoutingError, match="duplicate"):
        routing.route("R-1")


def test_load_agent_returns_none_when_not_built(monkeypatch):
    name = "fake_unbuilt_agent"
    monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(routing.AGENT_MODULES, "security-agent", name)
    assert routing.load_agent("security-agent") is None


def test_load_agent_builds_fresh_agent(monkeypatch):
    name = "fake_built_agent"
    mod = types.ModuleType(name)
    mod.build_agent = lambda: object()
    monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setitem(routing.AGENT_MODULES, "security-agent", name)
    assert routing.load_agent("security-agent") is not routing.load_agent("security-agent")
