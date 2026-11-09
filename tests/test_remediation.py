import pytest

from agents.orchestrator import remediation, routing
from agents.orchestrator.routing import Route


@pytest.fixture(autouse=True)
def fresh():
    routing.reload()


def decision(outcome="RESOLVED", actions=("DELETE",), requires_human=False):
    return {"outcome": outcome, "actions": list(actions), "requires_human": requires_human}


def test_eip_release_needs_approval():
    # the run you saw: COST-EC2-004, owner confirmed DELETE
    d = remediation.attach(decision(), {"evidence": {}}, routing.route("COST-EC2-004"))
    assert d["execution"]["mode"] == "APPROVAL"
    assert d["execution"]["remediation"] == "release_elastic_ip"
    assert d["requires_human"] is True


def test_eligible_when_met():
    d = remediation.attach(decision(), {"evidence": {"days_unattached": 45}}, routing.route("COST-EC2-003"))
    assert d["execution"]["mode"] == "APPROVAL"   # eligible, and delete_ebs_volume always needs approval


@pytest.mark.parametrize("evidence", [{"days_unattached": 10}, {}, {"days_unattached": None}])
def test_eligible_when_not_met_is_manual(evidence):
    d = remediation.attach(decision(), {"evidence": evidence}, routing.route("COST-EC2-003"))
    assert d["execution"]["mode"] == "MANUAL" and "not eligible" in d["execution"]["reason"]
    assert d["requires_human"] is False


def test_rule_without_remediation_is_manual():
    d = remediation.attach(decision(actions=("STOP",)), {"evidence": {}}, routing.route("COST-EC2-001"))
    assert d["execution"] == {"mode": "MANUAL", "action": "STOP", "reason": "rule has no automated remediation"}


@pytest.mark.parametrize("dec", [
    decision(outcome="ESCALATED", actions=(), requires_human=True),
    decision(outcome="DEFERRED", actions=("BACKUP_IN_FLIGHT",)),
    decision(outcome="NO_ACTION", actions=("MONITOR",)),
    decision(outcome="RESOLVED", actions=("RETENTION_FLOOR",)),   # rule's DELETE was overruled
])
def test_nothing_to_execute_when_rule_action_did_not_win(dec):
    d = remediation.attach(dec, {"evidence": {"days_unattached": 45}}, routing.route("COST-EC2-003"))
    assert d["execution"]["mode"] == "NONE"
    assert d["requires_human"] == dec["requires_human"]   # unchanged


def test_auto_when_rule_allows_it():
    r = routing.Route("R-1", "incident", "incident-agent", ("incident-agent",), "REPLACE", "1.0",
                      {"action": "restart_ecs_service", "eligible_when": None, "requires_approval": False})
    d = remediation.attach(decision(actions=("REPLACE",)), {"evidence": {}}, r)
    assert d["execution"]["mode"] == "AUTO" and d["requires_human"] is False


def test_agent_proposed_action_on_rule_without_action_needs_a_human():
    r = Route(rule_id="SEC-S3-002", domain="security", owner="security-agent", agents=("security-agent",),
              recommended_action=None, ruleset_version="1.0")
    d = remediation.attach(decision(actions=("QUARANTINE",)), {"evidence": {}}, r)
    assert d["execution"]["mode"] == "PROPOSED" and d["execution"]["action"] == "QUARANTINE"
    assert d["requires_human"] is True


def test_signal_on_rule_without_action_needs_nobody():
    r = Route(rule_id="SEC-S3-002", domain="security", owner="security-agent", agents=("security-agent",),
              recommended_action=None, ruleset_version="1.0")
    d = remediation.attach(decision(outcome="NO_ACTION", actions=("MONITOR",)), {"evidence": {}}, r)
    assert d["execution"]["mode"] == "NONE" and d["requires_human"] is False


def test_agent_review_blocks_remediation():
    d = remediation.attach(decision(outcome="ESCALATED", requires_human=True),
                           {"evidence": {}}, routing.route("COST-EC2-004"))
    assert d["execution"]["mode"] == "NONE" and d["requires_human"]
