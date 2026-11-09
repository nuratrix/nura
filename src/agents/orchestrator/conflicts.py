"""Deterministic conflict resolution over the sub-agents' opinions.

Input (from synthesize.run):
    {
      "finding_id": "...", "rule_id": "...",
      "opinions": [{"agent": "cost-agent", "action": "DELETE", "rationale": "..."}, ...]
    }
Each agent gives one action from conflict_rules.ACTIONS. The owner's opinion comes first.

Output: a decision dict, JSON-serialisable, written to the decision log and published to SNS.
    outcome  RESOLVED | DEFERRED | SUPPRESSED | ESCALATED | NO_ACTION
    actions  the actions that stand (several when they are COMPATIBLE)
    overruled  opinions that lost, with the conflict rule that overruled them
    observations  every agent's observations, tagged with the agent
    trace_id   OTel trace with the agents' full model and tool spans

An agent's needs_review escalates the decision; `actions` then holds what the rules
resolved, as the recommendation, and `resolved_outcome` what it would have been.

This decides *what* should happen. Whether it may happen automatically is the
ruleset's `remediation` block, not this module.
"""
from __future__ import annotations

from itertools import combinations

from agents.orchestrator.conflict_rules import (
    ACTIONS, DOMAIN_BY_AGENT, SIGNALS, Outcome, lookup,
)


def apply(result: dict) -> dict:
    decision = _resolve(result)
    opinions = result.get("opinions") or []

    # agents' insights travel with the decision (SNS, briefing); they never pick the action
    decision["observations"] = [{"agent": o.get("agent"), **obs}
                                for o in opinions for obs in (o.get("observations") or [])]
    decision["trace_id"] = result.get("trace_id")

    # an agent asked for a person: escalate, keeping what the rules resolved as the recommendation
    reviews = [o for o in opinions if o.get("needs_review")]
    if reviews and decision["outcome"] != "ESCALATED":
        reason = "; ".join(f"{o['agent']}: {o.get('review_reason') or 'review requested'}" for o in reviews)
        decision.update(outcome="ESCALATED", requires_human=True,
                        reason=f"review requested by agent ({reason})",
                        resolved_outcome=decision["outcome"])
    return decision


def _resolve(result: dict) -> dict:
    opinions = result.get("opinions") or []
    base = {"finding_id": result.get("finding_id"), "rule_id": result.get("rule_id")}

    if not opinions:
        return _escalate(base, [], "no agent returned an opinion")

    # a secondary agent that couldn't answer might have objected: never resolve without it
    incomplete = result.get("incomplete") or []
    if incomplete:
        return _escalate(base, [], "agents could not give an opinion: "
                         + ", ".join(f"{i['agent']} ({i['error']})" for i in incomplete))

    invalid = [o for o in opinions
               if o.get("agent") not in DOMAIN_BY_AGENT or o.get("action") not in ACTIONS]
    if invalid:
        return _escalate(base, [], f"invalid opinions (unknown agent or action): {invalid}")

    # distinct write actions, first-seen order so the owner's comes first
    writes = list(dict.fromkeys(o["action"] for o in opinions if o["action"] not in SIGNALS))

    if not writes:
        action = "MONITOR" if any(o["action"] == "MONITOR" for o in opinions) else "NO_ACTION"
        return {**base, "outcome": "NO_ACTION", "actions": [action], "overruled": [],
                "conflict_rules": [], "requires_human": False}

    applied = []
    losers: dict[str, dict] = {}       # action -> the rule that beat it
    escalations = []
    for a, b in combinations(writes, 2):
        rule = lookup(a, b)
        applied.append({"rule_id": rule.rule_id, "actions": sorted((a, b)),
                        "outcome": rule.outcome.value, "winner": rule.winner, "reason": rule.reason})
        if rule.outcome is Outcome.ESCALATE:
            escalations.append(rule)
        elif rule.outcome in (Outcome.PRECEDENCE, Outcome.DEFER):
            loser = b if rule.winner == a else a
            losers.setdefault(loser, {"rule_id": rule.rule_id, "outcome": rule.outcome.value,
                                      "reason": rule.reason})

    if escalations:
        recommended = list(dict.fromkeys(r.winner for r in escalations if r.winner))
        return _escalate(base, applied, "; ".join(dict.fromkeys(r.reason for r in escalations)),
                         recommended)

    winners = [a for a in writes if a not in losers]
    if not winners:
        return _escalate(base, applied, "conflict rules form a cycle; no action wins")

    overruled = [{**o, **losers[o["action"]]} for o in opinions if o["action"] in losers]
    if "APPROVED_CHANGE" in winners:
        outcome = "SUPPRESSED"
    elif any(l["outcome"] == Outcome.DEFER.value for l in losers.values()):
        outcome = "DEFERRED"
    else:
        outcome = "RESOLVED"

    return {**base, "outcome": outcome, "actions": winners, "overruled": overruled,
            "conflict_rules": applied, "requires_human": False}


def _escalate(base: dict, applied: list, reason: str, recommended: list | None = None) -> dict:
    return {**base, "outcome": "ESCALATED", "actions": recommended or [], "overruled": [],
            "conflict_rules": applied, "requires_human": True, "reason": reason}
