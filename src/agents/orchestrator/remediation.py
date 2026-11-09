"""Apply the ruleset's remediation block to a decision: may the action run, and how?

conflicts.apply decides *what* should happen. This decides *how* it may be carried out,
from the rule alone (never the agent):

    execution.mode
      AUTO       remediation exists, finding is eligible, no approval needed
      APPROVAL   remediation exists and is eligible, but a human must approve it first
      MANUAL     the rule's action stands but there is no automated remediation for it
                 (rule has none, or the finding fails eligible_when): a person carries it out
      PROPOSED   the rule has no action, and an agent proposed one (e.g. QUARANTINE on a
                 security finding). Nothing in the ruleset backs it, so a person decides
                 whether and how to carry it out. Never executed automatically.
      NONE       nothing to execute (escalated, deferred, suppressed, softened, or no action)

requires_human is set when a person must approve or decide (APPROVAL, PROPOSED);
MANUAL is a to-do, not a decision.
"""
from __future__ import annotations

from agents.orchestrator.conflict_rules import SIGNALS
from agents.orchestrator.routing import Route

_OPS = {
    "lt": lambda v, x: v < x, "lte": lambda v, x: v <= x,
    "gt": lambda v, x: v > x, "gte": lambda v, x: v >= x,
    "eq": lambda v, x: v == x, "in": lambda v, x: v in x,
}


def attach(decision: dict, finding: dict, route: Route) -> dict:
    execution = _execution(decision, finding, route)
    requires_human = (decision.get("requires_human", False)
                      or execution["mode"] in ("APPROVAL", "PROPOSED"))
    return {**decision, "execution": execution, "requires_human": requires_human}


def _execution(decision: dict, finding: dict, route: Route) -> dict:
    rule_action = route.recommended_action
    proposed = [a for a in decision.get("actions", []) if a not in SIGNALS]
    if decision.get("outcome") == "RESOLVED" and rule_action is None and proposed:
        return {"mode": "PROPOSED", "action": proposed[0], "proposed": proposed,
                "reason": "agent-proposed action; the rule has none, so a person decides"}

    if (decision.get("outcome") != "RESOLVED" or rule_action is None
            or rule_action not in decision.get("actions", [])):
        # the rule's action didn't win (or there is none): nothing of the rule's to execute
        return {"mode": "NONE", "action": None, "reason": "the rule's action is not the decided action"}

    rem = route.remediation
    if rem is None:
        return {"mode": "MANUAL", "action": rule_action, "reason": "rule has no automated remediation"}

    eligible, why = _eligible(rem.get("eligible_when"), finding.get("evidence") or {})
    if not eligible:
        return {"mode": "MANUAL", "action": rule_action, "remediation": rem["action"], "reason": why}

    if rem["requires_approval"]:
        return {"mode": "APPROVAL", "action": rule_action, "remediation": rem["action"],
                "reason": "rule requires approval before remediation"}
    return {"mode": "AUTO", "action": rule_action, "remediation": rem["action"],
            "reason": "rule allows automatic remediation"}


def _eligible(cond: dict | None, evidence: dict) -> tuple[bool, str]:
    if cond is None:
        return True, "eligible for every finding of this rule"
    metric = cond["metric"]
    op = next(k for k in _OPS if k in cond)
    if metric not in evidence or evidence[metric] is None:
        return False, f"not eligible: evidence has no {metric} to check {op} {cond[op]}"
    value = evidence[metric]
    try:
        ok = _OPS[op](value, cond[op])
    except TypeError:
        return False, f"not eligible: {metric}={value!r} can't be compared with {op} {cond[op]}"
    return ok, (f"{metric}={value} {op} {cond[op]}" if ok
                else f"not eligible: {metric}={value} fails {op} {cond[op]}")
