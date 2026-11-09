"""Deterministic routing: which sub-agents judge a finding.

The rulesets decide routing, not the LLM. Each rule lists its agents in
`agents`, owning agent first. This module indexes those lists by rule_id and
loads the sub-agents that synthesize.py calls.
"""
from __future__ import annotations

import importlib
import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

# agent_id (ruleset schema enum) -> module that exposes `build_agent()`.
AGENT_MODULES: dict[str, str] = {
    "cost-agent": "agents.subagents.cost_agent",
    "cost-anomaly-agent": "agents.subagents.cost_anamoly",
    "incident-agent": "agents.subagents.incident_agent",
    "security-agent": "agents.subagents.security_agent",
    "compliance-agent": "agents.subagents.compliance_agent",
    "infra-agent": "agents.subagents.infrastructure_agent",
    "network-security-agent": "agents.subagents.network_security_agent",
    "access-analyzer-agent": "agents.subagents.access_analyzer_agent",
    "backup-dr-agent": "agents.subagents.backup_dr_agent",
}

# src/agents/orchestrator/routing.py -> repo root
_DEFAULT_RULESETS_DIR = Path(__file__).resolve().parents[3] / "rulesets"


class RoutingError(Exception):
    """A finding cannot be routed. Let it fail so the message is retried / dead-lettered."""


@dataclass(frozen=True)
class Route:
    rule_id: str
    domain: str
    owner: str                       # first agent in the rule's list
    agents: tuple[str, ...]          # owner first, then the others that must also evaluate
    recommended_action: str | None   # what conflicts.py reconciles across agents
    ruleset_version: str
    remediation: dict | None = None  # ruleset's remediation block; remediation.py applies it


def rulesets_dir() -> Path:
    """NURA_RULESETS_DIR overrides the repo folder (e.g. /opt/rulesets in a Lambda layer)."""
    return Path(os.getenv("NURA_RULESETS_DIR", _DEFAULT_RULESETS_DIR))


@lru_cache(maxsize=1)
def _routes() -> dict[str, Route]:
    folder = rulesets_dir()
    files = sorted(folder.glob("*.json"))
    if not files:
        raise RoutingError(f"no rulesets found in {folder}")

    routes: dict[str, Route] = {}
    for path in files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        version = doc.get("schema_version", "unknown")
        for rule in doc["rules"]:
            rule_id = rule["rule_id"]
            if rule_id in routes:
                raise RoutingError(f"duplicate rule_id {rule_id} in {path.name}")
            if not rule.get("enabled", True):
                continue
            agents = tuple(rule["agents"])
            unknown = [a for a in agents if a not in AGENT_MODULES]
            if not agents or unknown:
                raise RoutingError(f"{rule_id} in {path.name} has unknown or no agents: {unknown or agents}")
            routes[rule_id] = Route(
                rule_id=rule_id,
                domain=rule["domain"],
                owner=agents[0],
                agents=agents,
                recommended_action=rule.get("recommended_action"),
                ruleset_version=version,
                remediation=rule.get("remediation"),
            )
    return routes


def route(rule_id: str) -> Route:
    """Return the route for a rule. Raises RoutingError for unknown or disabled rules."""
    try:
        return _routes()[rule_id]
    except KeyError:
        raise RoutingError(f"no enabled rule {rule_id} in {rulesets_dir()}") from None


def reload() -> None:
    """Drop the cached rulesets (tests, or after a ruleset update in a warm container)."""
    _routes.cache_clear()


def load_agent(agent_id: str):
    """A fresh Strands Agent for agent_id, or None if that agent isn't built yet.

    Each sub-agent module exposes `build_agent() -> strands.Agent`. A fresh agent per
    finding keeps one finding's conversation out of the next. Import errors propagate;
    synthesize treats them like an unavailable agent.
    """
    module = importlib.import_module(AGENT_MODULES[agent_id])
    build = getattr(module, "build_agent", None)
    if build is None:
        log.warning("%s is not built yet (no build_agent in %s)", agent_id, module.__name__)
        return None
    return build()
