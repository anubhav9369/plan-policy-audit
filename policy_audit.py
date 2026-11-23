#!/usr/bin/env python3
"""plan-policy-audit: audit an InspectablePlan against a policy pack and
write the report a human files after the decision.

Part of the trustworthy-agentic-AI prototype series for project BRJP26100123
(BITS-RMIT). Companion repos: plan-policy-pack (packs + conformance),
plan-policy-check (the checker this audit wraps), plan-policy-override
(scoped, expiring exceptions) and plan-policy-diff (pack version diffs).

A check answers "does this plan pass?". An audit answers "what exactly was
checked, what failed, what was waived, and what must be fixed before this
plan may run?" — in a dated report a reviewer can file and a later
investigator can re-read without re-running anything.

Usage:
    python3 policy_audit.py examples/pack.json examples/plan.json
    python3 policy_audit.py examples/pack.json examples/plan.json --json
    python3 policy_audit.py examples/pack.json examples/plan.json \\
        --overrides examples/overrides.json --today 2026-11-23 --out audit.md

Exit codes:
    0  PASS — no findings remain.
    1  BLOCKED — at least one HIGH finding remains.
    2  NEEDS REVIEW — only MEDIUM/LOW findings remain.
    3  Input error (unreadable file, bad JSON, invalid pack/plan/override).

Standard library only, no network.
"""
import argparse
import json
import sys
from datetime import date

MATCHERS = {
    "forbid_action", "forbid_target", "require_gate", "require_reason",
    "require_estimate", "require_field", "max_total_cost",
}
SEVERITIES = {"low", "medium", "high"}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
CATEGORIES = {"security", "privacy", "org", "ethics"}


class InputError(Exception):
    """Bad pack, plan or override file: plain-English, exit 3."""


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise InputError(f"{what} file not found: {path}")
    except json.JSONDecodeError as e:
        raise InputError(f"{what} file is not valid JSON: {path} ({e})")
    except OSError as e:
        raise InputError(f"cannot read {what} file {path}: {e}")


def validate_pack(pack):
    if not isinstance(pack, dict):
        raise InputError("pack must be a JSON object")
    for field in ("id", "version", "rules"):
        if field not in pack:
            raise InputError(f"pack is missing '{field}'")
    if not isinstance(pack["rules"], list) or not pack["rules"]:
        raise InputError("pack 'rules' must be a non-empty list")
    seen = set()
    for i, rule in enumerate(pack["rules"]):
        where = f"rule {i} ({rule.get('id', '?')})"
        if not isinstance(rule, dict):
            raise InputError(f"{where} is not an object")
        for field in ("id", "category", "matcher", "params", "severity"):
            if field not in rule:
                raise InputError(f"{where} is missing '{field}'")
        if rule["id"] in seen:
            raise InputError(f"duplicate rule id: {rule['id']}")
        seen.add(rule["id"])
        if rule["category"] not in CATEGORIES:
            raise InputError(f"{where} has unknown category {rule['category']!r}")
        if rule["matcher"] not in MATCHERS:
            raise InputError(f"{where} has unknown matcher {rule['matcher']!r}")
        if str(rule["severity"]).lower() not in SEVERITIES:
            raise InputError(f"{where} has unknown severity {rule['severity']!r}")
        if not isinstance(rule["params"], dict):
            raise InputError(f"{where} 'params' must be an object")
    return pack


def validate_plan(plan):
    if not isinstance(plan, dict):
        raise InputError("plan must be a JSON object")
    for field in ("id", "version", "steps"):
        if field not in plan:
            raise InputError(f"plan is missing '{field}'")
    if not isinstance(plan["steps"], list) or not plan["steps"]:
        raise InputError("plan 'steps' must be a non-empty list")
    for i, step in enumerate(plan["steps"]):
        if not isinstance(step, dict) or "id" not in step or "action" not in step:
            raise InputError(f"step {i} needs 'id' and 'action'")
    return plan


def plan_total_cost(plan):
    if isinstance(plan.get("total_cost_usd"), (int, float)):
        return float(plan["total_cost_usd"])
    total = 0.0
    for step in plan["steps"]:
        est = step.get("estimate_usd")
        if isinstance(est, (int, float)):
            total += float(est)
    return total


def _contains(haystack, needles):
    text = str(haystack or "").lower()
    return [n for n in needles if str(n).lower() in text]


def evaluate_rule(rule, plan):
    """Return a list of evidence strings for the steps this rule fires on."""
    matcher, params = rule["matcher"], rule["params"]
    evidence = []
    if matcher == "forbid_action":
        for step in plan["steps"]:
            hits = _contains(step.get("action"), params.get("actions", []))
            if hits:
                evidence.append(f"step {step['id']}: action {step['action']!r} "
                                f"contains forbidden {hits}")
    elif matcher == "forbid_target":
        for step in plan["steps"]:
            hits = _contains(step.get("target"), params.get("targets", []))
            if hits:
                evidence.append(f"step {step['id']}: target {step.get('target')!r} "
                                f"contains forbidden {hits}")
    elif matcher == "require_gate":
        for step in plan["steps"]:
            if step.get("reversible") is False and not step.get("gate"):
                evidence.append(f"step {step['id']}: irreversible, no human gate")
    elif matcher == "require_reason":
        for step in plan["steps"]:
            if not str(step.get("reason") or "").strip():
                evidence.append(f"step {step['id']}: no reason given")
    elif matcher == "require_estimate":
        for step in plan["steps"]:
            if step.get("estimate_usd") is None and not step.get("estimate"):
                evidence.append(f"step {step['id']}: no cost/time estimate")
    elif matcher == "require_field":
        field = params.get("field")
        for step in plan["steps"]:
            if field not in step or step.get(field) in (None, ""):
                evidence.append(f"step {step['id']}: missing field {field!r}")
    elif matcher == "max_total_cost":
        limit = params.get("limit_usd")
        total = plan_total_cost(plan)
        if isinstance(limit, (int, float)) and total > float(limit):
            evidence.append(f"total cost ${total:.2f} exceeds limit ${float(limit):.2f}")
    return evidence


def load_overrides(path, today):
    """Overrides: JSON list of {id, rule_id, step_id?, expires}.
    Returns the list of overrides still in force on `today`."""
    raw = load_json(path, "overrides")
    if not isinstance(raw, list):
        raise InputError("overrides file must be a JSON list")
    live = []
    for i, ovr in enumerate(raw):
        if not isinstance(ovr, dict):
            raise InputError(f"override {i} is not an object")
        for field in ("id", "rule_id", "expires"):
            if field not in ovr:
                raise InputError(f"override {i} is missing '{field}'")
        try:
            expiry = date.fromisoformat(str(ovr["expires"]))
        except ValueError:
            raise InputError(f"override {ovr['id']} has bad expiry date "
                             f"{ovr['expires']!r}")
        if expiry >= today:
            live.append(ovr)
    return live


def audit(pack, plan, overrides=(), today=None):
    """Run every rule; return the audit dict (JSON-serialisable)."""
    today = today or date.today()
    findings, waived, passed = [], [], []
    for rule in pack["rules"]:
        evidence = evaluate_rule(rule, plan)
        if not evidence:
            passed.append({"rule_id": rule["id"], "severity": rule["severity"],
                           "description": rule.get("description", "")})
            continue
        finding = {"rule_id": rule["id"], "severity": rule["severity"],
                   "category": rule["category"],
                   "description": rule.get("description", ""),
                   "evidence": evidence, "waived_by": None}
        for ovr in overrides:
            if ovr["rule_id"] != rule["id"]:
                continue
            step_id = ovr.get("step_id")
            if step_id is None or any(step_id in e for e in evidence):
                finding["waived_by"] = ovr["id"]
                break
        (waived if finding["waived_by"] else findings).append(finding)
    remaining = sorted(findings, key=lambda f: -SEVERITY_RANK[f["severity"].lower()])
    if any(f["severity"].lower() == "high" for f in remaining):
        verdict, exit_code = "BLOCKED", 1
    elif remaining:
        verdict, exit_code = "NEEDS REVIEW", 2
    else:
        verdict, exit_code = "PASS", 0
    counts = {sev: sum(1 for f in findings if f["severity"].lower() == sev)
              for sev in ("high", "medium", "low")}
    return {
        "plan_id": plan["id"], "plan_version": plan["version"],
        "pack_id": pack["id"], "pack_version": pack["version"],
        "audit_date": today.isoformat(), "verdict": verdict,
        "exit_code": exit_code,
        "summary": {"rules_checked": len(pack["rules"]),
                    "rules_passed": len(passed),
                    "findings": len(findings), "waived": len(waived),
                    "by_severity": counts},
        "findings": remaining, "waived": waived, "passed": passed,
    }


def render_markdown(result):
    s = result["summary"]
    lines = [
        f"# Policy audit — plan {result['plan_id']} v{result['plan_version']}",
        "",
        f"**Verdict: {result['verdict']}** — pack `{result['pack_id']}` "
        f"v{result['pack_version']}, audited {result['audit_date']}.",
        "",
        f"Rules checked: {s['rules_checked']} · passed: {s['rules_passed']} · "
        f"findings: {s['findings']} (HIGH {s['by_severity']['high']}, "
        f"MEDIUM {s['by_severity']['medium']}, LOW {s['by_severity']['low']}) · "
        f"waived: {s['waived']}",
        "",
    ]
    if result["findings"]:
        lines += ["## Must fix before execution", ""]
        for f in result["findings"]:
            lines.append(f"- **{f['rule_id']}** [{f['severity'].upper()}] — "
                         f"{f['description']}")
            for e in f["evidence"]:
                lines.append(f"  - {e}")
        lines.append("")
    if result["waived"]:
        lines += ["## Waived findings", ""]
        for f in result["waived"]:
            lines.append(f"- **{f['rule_id']}** [{f['severity'].upper()}] — "
                         f"waived by {f['waived_by']}: {f['description']}")
        lines.append("")
    if result["passed"]:
        lines += ["## Passed rules", ""]
        for p in result["passed"]:
            lines.append(f"- {p['rule_id']} [{p['severity'].upper()}] — "
                         f"{p['description']}")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pack", help="policy pack JSON")
    parser.add_argument("plan", help="plan JSON")
    parser.add_argument("--overrides", help="overrides JSON list")
    parser.add_argument("--today", default=date.today().isoformat(),
                        help="audit date, YYYY-MM-DD (default: today)")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--out", help="write the report to this file")
    args = parser.parse_args(argv)
    try:
        try:
            today = date.fromisoformat(args.today)
        except ValueError:
            raise InputError(f"--today must be YYYY-MM-DD, got {args.today!r}")
        pack = validate_pack(load_json(args.pack, "pack"))
        plan = validate_plan(load_json(args.plan, "plan"))
        overrides = load_overrides(args.overrides, today) if args.overrides else []
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    result = audit(pack, plan, overrides, today)
    report = (json.dumps(result, indent=2) if args.json
              else render_markdown(result))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report if report.endswith("\n") else report + "\n")
        print(f"Audit written to {args.out}: {result['verdict']}")
    else:
        print(report)
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
