"""Collect one opinion per routed agent for a finding. The only LLM step.

1. The rule is the baseline: the owner's default opinion is the rule's recommended_action.
2. Each agent's LLM returns structured output, limited to the actions it is allowed
   (conflict_rules.allowed_actions). The owner may confirm the rule or soften it to
   MONITOR / NO_ACTION; a secondary agent picks from its own short list.
3. If the owner's LLM fails or answers outside its list, its opinion falls back to the
   rule. A secondary agent that fails is reported in `incomplete`, and conflicts.apply
   escalates: a missing objection must never let a destructive action through.
4. No LLM where there is nothing to judge: a single-agent rule with no recommended_action
   is decided from the rule alone.

The action is constrained; insight is not. Besides its action an agent returns:
- observations: typed notes that don't fit the action list (related risks, context,
  data-quality problems, ruleset gaps). They inform people, never the action directly.
- needs_review: the agent asks for a human. conflicts.apply escalates on it.
And each LLM opinion records `tool_calls`: an evidence digest of what the agent saw
(tool, input, capped preview, SHA-256 of the full output). The full trace lives in OTel
(CloudWatch GenAI Observability / Langfuse) under `trace_id`.

Output (input to conflicts.apply):
    {"finding_id", "rule_id", "mode": "rule_only" | "agents", "trace_id",
     "opinions": [{"agent", "role", "action", "rationale", "evidence", "observations",
                   "needs_review", "review_reason", "tool_calls", "source"}],
     "incomplete": [{"agent", "error"}]}
source: "rule" (no LLM), "llm", or "fallback" (LLM failed, rule used).
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Callable, Literal

from opentelemetry import trace
from pydantic import BaseModel, Field, create_model

from agents.orchestrator import routing
from agents.orchestrator.conflict_rules import allowed_actions

log = logging.getLogger(__name__)
tracer = trace.get_tracer("nura.orchestrator")

AgentLoader = Callable[[str], object]   # agent_id -> strands.Agent | None
OPINION_MODEL = "AgentOpinion"          # Strands records structured output as a tool of this name
PREVIEW_CHARS = 500


class Observation(BaseModel):
    type: Literal["related_risk", "context", "data_quality", "ruleset_gap"] = Field(
        description="related_risk: a risk beyond this finding's rule. context: something that changes how "
                    "a person should read this finding. data_quality: missing, contradictory or "
                    "not-found data. ruleset_gap: the rule itself looks wrong or too broad.")
    detail: str = Field(description="One or two sentences.")
    evidence: str | None = Field(default=None, description="The tool output or finding field it comes from.")


class _Opinion(BaseModel):
    """Base for the per-call model; `action` is narrowed to a Literal of allowed actions."""
    action: str
    rationale: str = Field(description="One to three sentences: why this action, based on the evidence.")
    evidence: list[str] = Field(default_factory=list,
                                description="Facts you relied on, each citing the tool or finding field it came from.")
    observations: list[Observation] = Field(
        default_factory=list, description="Anything worth a person's attention that the action can't express.")
    needs_review: bool = Field(
        default=False, description="True if a person must look at this before any action, whatever you chose.")
    review_reason: str | None = Field(default=None, description="Required when needs_review is true.")


def run(finding: dict, route: routing.Route, load_agent: AgentLoader = routing.load_agent) -> dict:
    with tracer.start_as_current_span("nura.judge_finding", attributes={
            "nura.finding_id": finding.get("finding_id") or "", "nura.rule_id": route.rule_id}) as span:
        ctx = span.get_span_context()
        trace_id = format(ctx.trace_id, "032x") if ctx.is_valid else None   # None when OTel isn't configured
        return {"trace_id": trace_id, **_run(finding, route, load_agent)}


def _run(finding: dict, route: routing.Route, load_agent: AgentLoader) -> dict:
    base = {"finding_id": finding.get("finding_id"), "rule_id": route.rule_id}
    rule_action = route.recommended_action

    # 4. nothing to judge -> rule only
    if len(route.agents) == 1 and rule_action is None:
        return {**base, "mode": "rule_only", "incomplete": [],
                "opinions": [_rule_opinion(route.owner, "NO_ACTION", finding, "rule")]}

    opinions, incomplete = [], []
    for agent_id in route.agents:
        is_owner = agent_id == route.owner

        if is_owner and rule_action is None:
            # owner has no write action to propose; only the secondaries are judged
            opinions.append(_rule_opinion(agent_id, "NO_ACTION", finding, "rule"))
            continue

        allowed = allowed_actions(agent_id, is_owner, rule_action)
        try:
            opinions.append(_ask(agent_id, is_owner, allowed, finding, rule_action, load_agent))
        except Exception as e:   # LLM, tool, import or validation failure
            log.warning("%s failed on %s: %s", agent_id, base["finding_id"], e)
            if is_owner:
                # 3. owner falls back to the rule
                opinions.append(_rule_opinion(agent_id, rule_action, finding, "fallback", error=str(e)))
            else:
                incomplete.append({"agent": agent_id, "error": str(e)})

    return {**base, "mode": "agents", "opinions": opinions, "incomplete": incomplete}


def _ask(agent_id, is_owner, allowed, finding, rule_action, load_agent) -> dict:
    agent = load_agent(agent_id)
    if agent is None:
        raise RuntimeError(f"{agent_id} is not built yet")

    model = create_model(OPINION_MODEL, __base__=_Opinion,
                         action=(Literal[tuple(sorted(allowed))], ...))
    # invocation_state reaches every @tool(context=True): context tools read the resource,
    # account and region from the stored finding, not from the model.
    result = agent(_prompt(agent_id, is_owner, allowed, finding, rule_action),
                   structured_output_model=model, invocation_state={"finding": finding})
    out = result.structured_output
    if out is None:
        raise ValueError("agent returned no structured output")
    if out.action not in allowed:   # belt and braces: never trust the model's output
        raise ValueError(f"action {out.action!r} not allowed; allowed: {sorted(allowed)}")

    return {"agent": agent_id, "role": "owner" if is_owner else "secondary",
            "action": out.action, "rationale": out.rationale, "evidence": out.evidence,
            "observations": [o.model_dump() for o in out.observations],
            "needs_review": out.needs_review,
            "review_reason": out.review_reason or ("agent asked for review" if out.needs_review else None),
            "tool_calls": tool_trace(getattr(agent, "messages", [])),
            "source": "llm"}


def tool_trace(messages: list) -> list[dict]:
    """Evidence digest of the agent's tool calls, in call order, from its conversation."""
    uses, results = [], {}
    for msg in messages:
        for block in msg.get("content", []):
            if "toolUse" in block and block["toolUse"].get("name") != OPINION_MODEL:
                uses.append(block["toolUse"])
            elif "toolResult" in block:
                results[block["toolResult"].get("toolUseId")] = block["toolResult"]

    calls = []
    for use in uses:
        res = results.get(use.get("toolUseId"), {})
        output = json.dumps(res.get("content", []), sort_keys=True, default=str)
        calls.append({
            "tool": use.get("name"),
            "input": use.get("input"),
            "status": res.get("status", "missing"),
            "output_preview": output[:PREVIEW_CHARS] + ("..." if len(output) > PREVIEW_CHARS else ""),
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        })
    return calls


def _rule_opinion(agent_id, action, finding, source, error=None) -> dict:
    op = {"agent": agent_id, "role": "owner", "action": action,
          "rationale": finding.get("recommendation", ""), "evidence": [], "observations": [],
          "needs_review": False, "review_reason": None, "tool_calls": [], "source": source}
    if error:
        op["error"] = error
    return op


def _prompt(agent_id, is_owner, allowed, finding, rule_action) -> str:
    facts = {k: finding.get(k) for k in (
        "finding_id", "rule_id", "title", "severity", "account_id", "region", "resource_type",
        "resource_id", "evidence", "estimated_monthly_saving", "recommendation", "detected_at")}
    if is_owner:
        role = (f"You own this finding. The rule recommends {rule_action}. Confirm {rule_action} "
                "unless your tools show context the scanner could not see (for example tags, recent "
                "activity, an approved change) that makes it wrong or premature; then choose MONITOR "
                "or NO_ACTION and say why.")
    else:
        role = ("Another agent owns this finding. Judge it only from your domain. Choose a protective "
                "or domain action if your tools show a reason the owner's action must be blocked, "
                "held or combined with another; otherwise choose NO_ACTION.")
    return (
        f"You are {agent_id}, reviewing a stored governance finding. Do not re-scan; use your tools "
        "only to add context.\n\n"
        f"{role}\n\n"
        f"Allowed actions: {', '.join(sorted(allowed))}. You must choose exactly one.\n"
        "Cite every fact you rely on in `evidence`. If a tool fails or returns nothing, say so; "
        "never guess numbers. Absence of data (no tags, no events) is not proof of anything: if "
        "the resource may not exist or a tool returned nothing, add a data_quality observation.\n\n"
        "Your action list is narrow on purpose; your observations are not. Record anything a "
        "reviewer should know in `observations`, even outside your domain. If something must be "
        "seen by a person before any action is taken, set needs_review with a reason.\n\n"
        f"Finding:\n{json.dumps(facts, indent=2, default=str)}"
    )
