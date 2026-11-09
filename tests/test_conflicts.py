import json
from pathlib import Path

from agents.orchestrator import conflict_rules, conflicts, routing

SCHEMA = Path(__file__).resolve().parents[1] / "rulesets" / "schema" / "ruleset.schema.json"


def result(*pairs):
    return {"finding_id": "f-1", "rule_id": "R-1",
            "opinions": [{"agent": a, "action": x, "rationale": "test"} for a, x in pairs]}


# --- table integrity -------------------------------------------------------

def test_actions_match_schema():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    enum = set(schema["$defs"]["rule"]["properties"]["recommended_action"]["enum"]) - {None}
    assert enum == conflict_rules.ACTIONS


def test_agent_ids_match_schema_and_routing():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert set(schema["$defs"]["agent_id"]["enum"]) == set(conflict_rules.DOMAIN_BY_AGENT)
    assert set(routing.AGENT_MODULES) == set(conflict_rules.DOMAIN_BY_AGENT)


def test_every_rule_names_its_winner():
    for pair, rule in conflict_rules.CONFLICT_RULES.items():
        if rule.outcome is not conflict_rules.Outcome.COMPATIBLE:
            assert rule.winner in pair, (pair, rule)


# --- resolution ------------------------------------------------------------

def test_agreement_resolves():
    d = conflicts.apply(result(("cost-agent", "DELETE"), ("backup-dr-agent", "DELETE")))
    assert d["outcome"] == "RESOLVED" and d["actions"] == ["DELETE"]
    assert d["conflict_rules"] == []


def test_signals_never_conflict():
    d = conflicts.apply(result(("cost-agent", "DELETE"), ("backup-dr-agent", "NO_ACTION")))
    assert d["outcome"] == "RESOLVED" and d["actions"] == ["DELETE"]


def test_only_signals_is_no_action():
    d = conflicts.apply(result(("cost-agent", "NO_ACTION"), ("backup-dr-agent", "MONITOR")))
    assert d["outcome"] == "NO_ACTION" and d["actions"] == ["MONITOR"]


def test_retention_floor_beats_snapshot_delete():
    # COST-RDS-004: cost-agent + backup-dr-agent
    d = conflicts.apply(result(("cost-agent", "DELETE_SNAPSHOT"), ("backup-dr-agent", "RETENTION_FLOOR")))
    assert d["outcome"] == "RESOLVED"
    assert d["actions"] == ["RETENTION_FLOOR"]
    assert d["overruled"][0]["agent"] == "cost-agent"
    assert d["overruled"][0]["rule_id"] == "CR-RETENTION-FLOOR"


def test_backup_in_flight_defers_delete():
    d = conflicts.apply(result(("cost-agent", "DELETE"), ("backup-dr-agent", "BACKUP_IN_FLIGHT")))
    assert d["outcome"] == "DEFERRED" and d["actions"] == ["BACKUP_IN_FLIGHT"]


def test_investigation_holds_terminate():
    d = conflicts.apply(result(("infra-agent", "TERMINATE"), ("incident-agent", "ACTIVE_INVESTIGATION")))
    assert d["outcome"] == "DEFERRED" and d["actions"] == ["ACTIVE_INVESTIGATION"]


def test_protection_vs_delete_escalates_with_recommendation():
    d = conflicts.apply(result(("cost-agent", "DELETE"), ("backup-dr-agent", "RETENTION_FLOOR")))
    assert d["outcome"] == "ESCALATED" and d["requires_human"]
    assert d["actions"] == ["RETENTION_FLOOR"]


def test_compatible_actions_both_stand():
    d = conflicts.apply(result(("cost-agent", "DOWNSIZE"), ("backup-dr-agent", "ENFORCE_REDUNDANCY")))
    assert d["outcome"] == "RESOLVED"
    assert d["actions"] == ["DOWNSIZE", "ENFORCE_REDUNDANCY"]


def test_approved_change_suppresses():
    d = conflicts.apply(result(("network-security-agent", "CLOSE_PATH"), ("infra-agent", "APPROVED_CHANGE")))
    assert d["outcome"] == "SUPPRESSED" and d["actions"] == ["APPROVED_CHANGE"]


def test_approved_change_does_not_override_investigation():
    d = conflicts.apply(result(("incident-agent", "ACTIVE_INVESTIGATION"), ("infra-agent", "APPROVED_CHANGE")))
    assert d["outcome"] == "ESCALATED"


def test_unknown_pair_escalates():
    d = conflicts.apply(result(("cost-agent", "REPLACE"), ("security-agent", "ENCRYPT_CMK")))
    assert d["outcome"] == "ESCALATED"
    assert d["conflict_rules"][0]["rule_id"] == "CR-DEFAULT"


def test_three_agents_chain():
    # floor beats snapshot delete, and rightsizing is compatible with the floor
    d = conflicts.apply(result(("cost-agent", "DELETE_SNAPSHOT"), ("backup-dr-agent", "RETENTION_FLOOR"),
                               ("infra-agent", "DOWNSIZE")))
    # DELETE_SNAPSHOT vs DOWNSIZE is not in the table -> escalate, never guess
    assert d["outcome"] == "ESCALATED"


def test_invalid_llm_output_escalates():
    assert conflicts.apply(result(("cost-agent", "NUKE_IT")))["outcome"] == "ESCALATED"
    assert conflicts.apply(result(("ghost-agent", "DELETE")))["outcome"] == "ESCALATED"
    assert conflicts.apply({"finding_id": "f-1", "opinions": []})["outcome"] == "ESCALATED"


def test_decision_is_json_serialisable():
    d = conflicts.apply(result(("cost-agent", "DELETE_SNAPSHOT"), ("backup-dr-agent", "RETENTION_FLOOR")))
    json.dumps(d)
