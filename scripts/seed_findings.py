"""Load findings into the Findings DynamoDB table. Each new finding flows through the deployed
pipeline by itself: LOW/MEDIUM -> decision log (triage/), HIGH/CRITICAL -> agents (decisions/).

    uv run python scripts/seed_findings.py COST-EC2-004                  # one rule
    uv run python scripts/seed_findings.py COST-EC2-004 SEC-S3-002       # several
    uv run python scripts/seed_findings.py --all
    uv run python scripts/seed_findings.py --file my_findings.json --all # your own findings
    uv run python scripts/seed_findings.py --account 123456789012 COST-EC2-004

--file     JSON list in the data/sample_findings.json format (default: that file).
--account  rewrite account_id (and so finding_id) so findings point at your account. The
           agents read the real resource, so resource_id must also exist there to be useful.
Table: env FINDINGS_TABLE (default Findings). Writes with put_findings, the scanner's upsert.
Re-loading an unchanged finding is a rescan: it is not triaged or judged again.
"""
import argparse
import dataclasses
import os

from dotenv import load_dotenv

load_dotenv()
os.environ.setdefault("FINDINGS_TABLE", "Findings")

from common.findings_repo import DEFAULT_FILE, get_findings, put_findings  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("rule_ids", nargs="*")
    p.add_argument("--all", action="store_true")
    p.add_argument("--file", default=str(DEFAULT_FILE))
    p.add_argument("--account")
    a = p.parse_args(argv)
    if not a.rule_ids and not a.all:
        p.error("give rule IDs or --all")

    findings, errors = get_findings(a.file)
    for e in errors:
        print("skipped:", e)
    if not a.all:
        findings = [f for f in findings if f.rule_id in a.rule_ids]
        missing = set(a.rule_ids) - {f.rule_id for f in findings}
        if missing:
            p.exit(1, f"No finding in {a.file} for: {', '.join(sorted(missing))}\n")
    if a.account:
        findings = [dataclasses.replace(f, account_id=a.account) for f in findings]

    put_findings(findings)
    print(f"Wrote {len(findings)} finding(s) to {os.environ['FINDINGS_TABLE']}:")
    for f in findings:
        print(f"  {f.severity:8} {f.finding_id}")


if __name__ == "__main__":
    main()
