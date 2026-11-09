"""Static conflict table: how the orchestrator reconciles agents that disagree.

Pure data, no AWS or LLM calls. conflicts.py applies it; rulesets/validate_rule_sets.py
checks that ACTIONS matches the ruleset schema's recommended_action enum.

Each agent states one action for a finding. Two different write actions on the same
finding are looked up here as an unordered pair. A pair not in the table ESCALATES to a
human: an unknown disagreement is never auto-resolved.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import product

# Must stay identical to ruleset.schema.json -> rule.recommended_action enum (minus null).
ACTIONS: frozenset[str] = frozenset({
    # cost / cleanup (destructive)
    "TERMINATE", "DELETE", "DELETE_SNAPSHOT", "STOP",
    # evidence / incident holds
    "PRESERVE", "QUARANTINE", "ISOLATE", "ACTIVE_INVESTIGATION",
    # resilience
    "REMOVE_REDUNDANCY", "ENFORCE_REDUNDANCY", "REDUCE_RETENTION", "RETENTION_FLOOR",
    "BACKUP_IN_FLIGHT", "RESTORE_IN_FLIGHT", "DR_TEST_WINDOW", "CROSS_REGION_REPLICA",
    # capacity
    "DOWNSIZE", "SCHEDULE_OFF", "SCALE_UP", "SCALE_OUT",
    # access / network
    "OPEN_PATH", "CLOSE_PATH", "GRANT", "REVOKE", "BREAK_GLASS_USED",
    # maintenance
    "ROTATE_KEY", "PATCH_REBOOT", "REPLACE",
    # data governance
    "DATA_RESIDENCY", "ENCRYPT_CMK",
    # signals
    "SPEND_SPIKE", "APPROVED_CHANGE", "MONITOR", "NO_ACTION",
})

# Opinions that propose no change. They never conflict with anything.
# An agent that objects to a change must say so with a protective action, not NO_ACTION.
SIGNALS: frozenset[str] = frozenset({"MONITOR", "NO_ACTION"})

# agent_id (ruleset schema enum) -> ruleset domain. Routing and resolution key on these ids.
DOMAIN_BY_AGENT: dict[str, str] = {
    "cost-agent": "cost",
    "cost-anomaly-agent": "cost-anomaly",
    "incident-agent": "incident",
    "security-agent": "security",
    "compliance-agent": "compliance",
    "infra-agent": "infrastructure",
    "network-security-agent": "network-security",
    "access-analyzer-agent": "access-analyzer",
    "backup-dr-agent": "backup-dr",
}


# What each agent may say when it is a *secondary* agent on a finding (not the owner).
# The owner may only confirm the rule's recommended_action or soften it to a signal.
# Both always also allow SIGNALS.
SECONDARY_ACTIONS: dict[str, frozenset[str]] = {
    "cost-agent": frozenset({"DOWNSIZE", "SCHEDULE_OFF", "STOP"}),
    "cost-anomaly-agent": frozenset({"SPEND_SPIKE"}),
    "incident-agent": frozenset({"ACTIVE_INVESTIGATION", "PRESERVE", "QUARANTINE", "ISOLATE"}),
    "security-agent": frozenset({"PRESERVE", "QUARANTINE", "ISOLATE", "ROTATE_KEY", "REVOKE",
                                 "CLOSE_PATH", "ENCRYPT_CMK"}),
    "compliance-agent": frozenset({"RETENTION_FLOOR", "ENFORCE_REDUNDANCY", "DATA_RESIDENCY",
                                   "ENCRYPT_CMK"}),
    "infra-agent": frozenset({"APPROVED_CHANGE", "SCALE_UP", "SCALE_OUT", "PATCH_REBOOT", "REPLACE"}),
    "network-security-agent": frozenset({"CLOSE_PATH", "ISOLATE"}),
    "access-analyzer-agent": frozenset({"REVOKE"}),
    "backup-dr-agent": frozenset({"RETENTION_FLOOR", "ENFORCE_REDUNDANCY", "CROSS_REGION_REPLICA",
                                  "BACKUP_IN_FLIGHT", "RESTORE_IN_FLIGHT", "DR_TEST_WINDOW"}),
}

assert set(SECONDARY_ACTIONS) == set(DOMAIN_BY_AGENT), "SECONDARY_ACTIONS must cover every agent"
assert all(a <= ACTIONS for a in SECONDARY_ACTIONS.values()), "SECONDARY_ACTIONS uses unknown actions"


def allowed_actions(agent_id: str, is_owner: bool, rule_action: str | None) -> frozenset[str]:
    """The only actions an agent's LLM answer may contain for this finding.

    Owner, rule has an action: confirm it or soften it to a signal.
    Owner, rule has none ("assess"): a signal, or one of its domain actions (the same short
      list it has as a secondary). Such a proposal is never executed: remediation.py marks
      it agent-proposed and requires a human.
    Secondary: a signal or its domain actions.
    """
    if is_owner and rule_action:
        return SIGNALS | {rule_action}
    return SIGNALS | SECONDARY_ACTIONS[agent_id]


class Outcome(str, Enum):
    PRECEDENCE = "PRECEDENCE"   # winner stands, loser is suppressed
    DEFER = "DEFER"             # winner stands now, loser is held until the winner's condition clears
    ESCALATE = "ESCALATE"       # a human decides; `winner` is only the recommendation
    COMPATIBLE = "COMPATIBLE"   # both actions stand


@dataclass(frozen=True)
class ConflictRule:
    rule_id: str
    outcome: Outcome
    winner: str | None   # None only for COMPATIBLE, or ESCALATE with no recommendation
    reason: str


DESTRUCTIVE = {"TERMINATE", "DELETE", "DELETE_SNAPSHOT", "STOP", "DOWNSIZE", "SCHEDULE_OFF",
               "REDUCE_RETENTION", "REMOVE_REDUNDANCY"}
EVIDENCE_HOLDS = {"PRESERVE", "QUARANTINE", "ISOLATE", "ACTIVE_INVESTIGATION"}
IN_FLIGHT = {"BACKUP_IN_FLIGHT", "RESTORE_IN_FLIGHT", "DR_TEST_WINDOW"}
DISRUPTIVE = DESTRUCTIVE | {"PATCH_REBOOT", "REPLACE"}
# What an approved change can suppress: anything that would undo it. Never holds,
# in-flight jobs or break-glass, which an approved change says nothing about.
UNDOABLE = (ACTIONS - SIGNALS - EVIDENCE_HOLDS - IN_FLIGHT
            - {"APPROVED_CHANGE", "SPEND_SPIKE", "BREAK_GLASS_USED"})

# (rule_id, winners, losers, outcome, reason). Every winner x loser pair gets this rule.
_GROUPS: list[tuple[str, set[str], set[str], Outcome, str]] = [
    ("CR-EVIDENCE-HOLD", EVIDENCE_HOLDS, DISRUPTIVE, Outcome.DEFER,
     "An open investigation or evidence hold blocks changes that destroy or alter the resource."),
    ("CR-IN-FLIGHT", IN_FLIGHT, DISRUPTIVE, Outcome.DEFER,
     "A backup, restore or DR test is running; wait for it to finish."),
    ("CR-RETENTION-FLOOR", {"RETENTION_FLOOR"}, {"REDUCE_RETENTION", "DELETE_SNAPSHOT"}, Outcome.PRECEDENCE,
     "A compliance or DR retention floor overrides cost-driven retention cuts."),
    ("CR-REDUNDANCY", {"ENFORCE_REDUNDANCY"}, {"REMOVE_REDUNDANCY"}, Outcome.PRECEDENCE,
     "Required redundancy overrides cost-driven removal."),
    ("CR-REPLICA", {"CROSS_REGION_REPLICA"}, {"DELETE_SNAPSHOT", "REDUCE_RETENTION", "REMOVE_REDUNDANCY"},
     Outcome.PRECEDENCE, "Cross-region DR copies are not cost-cleanup candidates."),
    ("CR-RESIDENCY", {"DATA_RESIDENCY"}, {"CROSS_REGION_REPLICA"}, Outcome.PRECEDENCE,
     "Data residency law overrides copying data to another region."),
    ("CR-APPROVED-CHANGE", {"APPROVED_CHANGE"}, UNDOABLE | {"SPEND_SPIKE"}, Outcome.PRECEDENCE,
     "The observed state matches an approved change; the finding is suppressed."),
    ("CR-PROTECT-VS-DELETE", {"RETENTION_FLOOR", "ENFORCE_REDUNDANCY"}, {"DELETE", "TERMINATE"},
     Outcome.ESCALATE, "Deleting a resource under a protection requirement needs a human decision."),
    ("CR-CAPACITY", {"SCALE_UP", "SCALE_OUT"}, {"DOWNSIZE", "SCHEDULE_OFF", "STOP"}, Outcome.ESCALATE,
     "Performance and cost disagree on capacity."),
    ("CR-NETWORK-PATH", {"CLOSE_PATH"}, {"OPEN_PATH"}, Outcome.ESCALATE,
     "Closing a path may cause an outage; closing is recommended, a human confirms."),
    ("CR-LEAST-PRIVILEGE", {"REVOKE"}, {"GRANT"}, Outcome.ESCALATE,
     "Least privilege is recommended, a human confirms."),
    ("CR-BREAK-GLASS", {"BREAK_GLASS_USED"}, {"REVOKE", "ROTATE_KEY"}, Outcome.ESCALATE,
     "Break-glass access is in use; revoking it mid-incident needs a human."),
]

# Pairs that look related but can both be carried out.
_COMPATIBLE: list[tuple[str, set[str], set[str], str]] = [
    ("CR-COMPAT-CONTAIN", {"ROTATE_KEY", "REVOKE", "CLOSE_PATH"}, EVIDENCE_HOLDS,
     "Containment during an investigation is expected."),
    ("CR-COMPAT-RIGHTSIZE", {"DOWNSIZE"}, {"RETENTION_FLOOR", "ENFORCE_REDUNDANCY", "ENCRYPT_CMK"},
     "Rightsizing keeps the retention, redundancy and encryption settings."),
    ("CR-COMPAT-SPIKE", {"SPEND_SPIKE"}, EVIDENCE_HOLDS,
     "A spend spike can be a symptom of the incident under investigation."),
]


def _build() -> dict[frozenset[str], ConflictRule]:
    table: dict[frozenset[str], ConflictRule] = {}

    def add(a: str, b: str, rule: ConflictRule) -> None:
        if a == b:
            return
        key = frozenset((a, b))
        if key in table:
            raise ValueError(f"{sorted(key)} defined by both {table[key].rule_id} and {rule.rule_id}")
        table[key] = rule

    for rule_id, winners, losers, outcome, reason in _GROUPS:
        for w, l in product(sorted(winners), sorted(losers)):
            add(w, l, ConflictRule(rule_id, outcome, w, reason))
    for rule_id, left, right, reason in _COMPATIBLE:
        for a, b in product(sorted(left), sorted(right)):
            add(a, b, ConflictRule(rule_id, Outcome.COMPATIBLE, None, reason))

    for key in table:
        unknown = key - ACTIONS
        if unknown:
            raise ValueError(f"conflict table uses unknown actions {sorted(unknown)}")
        if key & SIGNALS:
            raise ValueError(f"signals never conflict, remove {sorted(key)}")
    return table


CONFLICT_RULES: dict[frozenset[str], ConflictRule] = _build()

DEFAULT_RULE = ConflictRule("CR-DEFAULT", Outcome.ESCALATE, None,
                            "No conflict rule covers these actions; a human decides.")


def lookup(a: str, b: str) -> ConflictRule:
    return CONFLICT_RULES.get(frozenset((a, b)), DEFAULT_RULE)
