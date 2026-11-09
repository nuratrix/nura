"""The member reader role grants exactly the reads the tools make, and trusts only the runtime."""
import json
from pathlib import Path

import yaml

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
TOOL_SIDS = {"ContextToolsGovernanceAccount", "SecurityAgentToolsGovernanceAccount",
             "DomainAgentToolsGovernanceAccount"}
GOVERNANCE_ONLY = {"organizations:DescribeAccount"}   # network.py calls it with the runtime's own role


class _CfnLoader(yaml.SafeLoader):
    pass


# CloudFormation short tags (!Sub, !Ref, ...) -> plain values, enough to inspect the template.
_CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: (
    loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode)
    else loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
    else loader.construct_mapping(node)))


def _template() -> dict:
    return yaml.load((DEPLOY / "member-reader-role.yaml").read_text(), Loader=_CfnLoader)


def _role() -> dict:
    return _template()["Resources"]["ReaderRole"]["Properties"]


def test_actions_match_the_runtime_tool_statements():
    runtime = json.loads((DEPLOY / "iam" / "runtime-policy.json").read_text())
    expected = set()
    for st in runtime["Statement"]:
        if st["Sid"] in TOOL_SIDS:
            expected |= set(st["Action"] if isinstance(st["Action"], list) else [st["Action"]])
    expected -= GOVERNANCE_ONLY

    [policy] = _role()["Policies"]
    actions = [a for st in policy["PolicyDocument"]["Statement"] for a in st["Action"]]
    assert len(actions) == len(set(actions)), "duplicate actions"
    assert set(actions) == expected, (f"missing: {sorted(expected - set(actions))}, "
                                      f"extra: {sorted(set(actions) - expected)}")


def test_read_only():
    [policy] = _role()["Policies"]
    writes = ("Put", "Create", "Delete", "Update", "Attach", "Detach", "Modify", "Start", "Stop", "Tag")
    verbs = [a.split(":")[1] for st in policy["PolicyDocument"]["Statement"] for a in st["Action"]]
    # GenerateServiceLastAccessedDetails only starts a report job; it changes nothing.
    assert not [v for v in verbs if v.startswith(writes)]
    assert all(st["Effect"] == "Allow" for st in policy["PolicyDocument"]["Statement"])


def test_trust_requires_external_id_and_runtime_role():
    t = _template()
    [st] = _role()["AssumeRolePolicyDocument"]["Statement"]
    assert st["Action"] == "sts:AssumeRole"
    assert st["Principal"]["AWS"].endswith(":iam::${GovernanceAccountId}:root")
    assert st["Condition"]["StringEquals"]["sts:ExternalId"] == "ExternalId"
    principals = st["Condition"]["ArnLike"]["aws:PrincipalArn"]
    assert principals[0].endswith(":role/${RuntimeRoleName}")
    p = t["Parameters"]
    assert p["RuntimeRoleName"]["Default"] == "nura-judgment-runtime"
    assert p["RoleName"]["Default"] == "governance-platform-reader"
    assert p["ExternalId"]["Default"] == "governance-platform"
    assert p["AdditionalPrincipalArn"]["Default"] == ""
