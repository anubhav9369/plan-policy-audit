# plan-policy-audit

Audit an InspectablePlan against a policy pack and write the report a
human files after the decision.

Part of the trustworthy-agentic-AI prototype series for project
**BRJP26100123** (Building Trustworthy AI Systems through Explainability and
Human-in-the-Loop Control). Companion repos: `plan-policy-pack` (versioned
policy packs, validation, conformance runner), `plan-policy-check` (the
checker this audit wraps), `plan-policy-override` (scoped, expiring
exceptions to findings) and `plan-policy-diff` (pack version diffs).

## The problem

A check answers "does this plan pass?". An audit answers the questions a
reviewer is actually asked afterwards:

1. What exactly was checked, and what failed?
2. What was waived, by whom, and until when?
3. What must be fixed before this plan may run?

`plan-policy-audit` answers all three in one dated, fileable report —
Markdown for humans, JSON for tooling — so a later investigator can
re-read the decision without re-running anything.

## Policy pack format

A pack is JSON, the same shape `plan-policy-pack` validates:

```json
{
  "id": "default",
  "version": "1.2.0",
  "rules": [
    {
      "id": "ORG-01",
      "category": "org",
      "matcher": "max_total_cost",
      "params": {"limit_usd": 5.0},
      "severity": "medium",
      "description": "Total plan cost must stay under the budget."
    }
  ]
}
```

Known matchers: `forbid_action`, `forbid_target`, `require_gate`,
`require_reason`, `require_estimate`, `require_field`, `max_total_cost`.
Categories: `security`, `privacy`, `org`, `ethics`. Severities:
`low`, `medium`, `high`.

## Usage

```bash
python3 policy_audit.py examples/pack.json examples/plan-good.json
python3 policy_audit.py examples/pack.json examples/plan-bad.json --json
python3 policy_audit.py examples/pack.json examples/plan-bad.json \
    --overrides examples/overrides.json --today 2026-11-23 --out audit.md
```

Exit codes:

- `0` — **PASS**, no findings remain.
- `1` — **BLOCKED**, at least one HIGH finding remains.
- `2` — **NEEDS REVIEW**, only MEDIUM/LOW findings remain.
- `3` — input error (unreadable file, bad JSON, invalid pack/plan/override).

## Overrides

An overrides file is a JSON list of `{id, rule_id, step_id?, expires}`.
A live override (expiry on or after `--today`) waives the finding for its
rule — for one step if `step_id` is given, for every step of that rule
otherwise. Expired overrides waive nothing. An override never waives a
finding it does not name, and a waived finding is still listed in the
report, marked with the override that waived it.

## Example

`examples/plan-bad.json` against `examples/pack.json` (see
`examples/audit-bad.md`):

- `SEC-01` [HIGH] — step s3 publishes to the team blog
- `SEC-02` [HIGH] — step s3 is irreversible with no human gate
- `ORG-01` [MEDIUM] — total cost $5.30 exceeds the $5.00 limit
- `ETH-01` [MEDIUM] — steps s2 and s3 give no reason
- `ORG-02` [LOW] — step s3 has no estimate

Verdict: **BLOCKED** (exit 1). With `examples/overrides.json`, the
`ORG-01` cost finding is waived until 2026-12-31
(`examples/audit-bad-overridden.md`), but the verdict stays **BLOCKED**
because the two HIGH findings remain.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

11 tests, standard library only, no network.
