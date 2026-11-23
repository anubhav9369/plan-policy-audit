"""Tests for plan-policy-audit. Standard library only, no network."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from policy_audit import (InputError, audit, load_overrides, render_markdown,
                          validate_pack, validate_plan)  # noqa: E402
from datetime import date  # noqa: E402

PACK = {
    "id": "default", "version": "1.0.0",
    "rules": [
        {"id": "SEC-01", "category": "security", "matcher": "forbid_action",
         "params": {"actions": ["publish"]}, "severity": "high",
         "description": "Never publish as a routine step."},
        {"id": "SEC-02", "category": "security", "matcher": "require_gate",
         "params": {}, "severity": "high",
         "description": "Irreversible steps need a gate."},
        {"id": "ORG-01", "category": "org", "matcher": "max_total_cost",
         "params": {"limit_usd": 5.0}, "severity": "medium",
         "description": "Stay under budget."},
        {"id": "ETH-01", "category": "ethics", "matcher": "require_reason",
         "params": {}, "severity": "medium",
         "description": "Every step needs a reason."},
        {"id": "ORG-02", "category": "org", "matcher": "require_estimate",
         "params": {}, "severity": "low",
         "description": "Every step needs an estimate."},
    ],
}
GOOD_PLAN = {
    "id": "p1", "version": 1,
    "steps": [{"id": "s1", "action": "search", "reason": "gather",
               "estimate_usd": 1.0, "reversible": True}],
}
TODAY = date(2026, 11, 23)


def run_cli(*args):
    proc = subprocess.run([sys.executable, os.path.join(HERE, "policy_audit.py"),
                           *args], capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


class TestAuditVerdicts(unittest.TestCase):
    def test_good_plan_passes(self):
        result = audit(validate_pack(PACK), validate_plan(GOOD_PLAN), today=TODAY)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["summary"]["rules_passed"], 5)

    def test_high_finding_blocks(self):
        plan = dict(GOOD_PLAN, steps=[{"id": "s1", "action": "publish the draft",
                                        "reason": "share it", "estimate_usd": 1.0,
                                        "reversible": False, "gate": "human"}])
        result = audit(validate_pack(PACK), validate_plan(plan), today=TODAY)
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["findings"][0]["rule_id"], "SEC-01")

    def test_only_medium_or_low_needs_review(self):
        plan = dict(GOOD_PLAN, steps=[{"id": "s1", "action": "search",
                                        "estimate_usd": 9.0, "reversible": True}])
        result = audit(validate_pack(PACK), validate_plan(plan), today=TODAY)
        self.assertEqual(result["verdict"], "NEEDS REVIEW")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["summary"]["by_severity"]["medium"], 2)  # cost + reason

    def test_cost_at_limit_passes(self):
        plan = dict(GOOD_PLAN, steps=[{"id": "s1", "action": "search",
                                        "reason": "gather", "estimate_usd": 5.0,
                                        "reversible": True}])
        result = audit(validate_pack(PACK), validate_plan(plan), today=TODAY)
        self.assertEqual(result["verdict"], "PASS")

    def test_markdown_lists_must_fix(self):
        plan = dict(GOOD_PLAN, steps=[{"id": "s1", "action": "publish",
                                        "reason": "share", "estimate_usd": 1.0,
                                        "reversible": True}])
        result = audit(validate_pack(PACK), validate_plan(plan), today=TODAY)
        md = render_markdown(result)
        self.assertIn("Verdict: BLOCKED", md)
        self.assertIn("Must fix before execution", md)
        self.assertIn("SEC-01", md)


class TestOverrides(unittest.TestCase):
    def test_live_override_waives_medium_finding(self):
        plan = dict(GOOD_PLAN, steps=[{"id": "s1", "action": "search",
                                        "reason": "gather", "estimate_usd": 9.0,
                                        "reversible": True}])
        ovr = [{"id": "OVR-1", "rule_id": "ORG-01", "expires": "2026-12-31"}]
        result = audit(validate_pack(PACK), validate_plan(plan), ovr, TODAY)
        self.assertEqual(result["summary"]["waived"], 1)
        self.assertEqual(result["waived"][0]["waived_by"], "OVR-1")
        self.assertEqual(result["verdict"], "PASS")  # cost waived, nothing else open

    def test_expired_override_waives_nothing(self):
        plan = dict(GOOD_PLAN, steps=[{"id": "s1", "action": "search",
                                        "reason": "gather", "estimate_usd": 9.0,
                                        "reversible": True}])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([{"id": "OVR-9", "rule_id": "ORG-01",
                        "expires": "2026-11-01"}], f)
            path = f.name
        try:
            live = load_overrides(path, TODAY)
        finally:
            os.unlink(path)
        self.assertEqual(live, [])
        result = audit(validate_pack(PACK), validate_plan(plan), live, TODAY)
        self.assertEqual(result["summary"]["waived"], 0)


class TestInputErrors(unittest.TestCase):
    def test_duplicate_rule_ids_rejected(self):
        bad = json.loads(json.dumps(PACK))
        bad["rules"].append(dict(bad["rules"][0]))
        with self.assertRaises(InputError):
            validate_pack(bad)

    def test_unknown_matcher_rejected(self):
        bad = json.loads(json.dumps(PACK))
        bad["rules"][0]["matcher"] = "forbid_vibes"
        with self.assertRaises(InputError):
            validate_pack(bad)

    def test_cli_bad_json_exits_3(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not json")
            bad = f.name
        try:
            code, _, err = run_cli(bad, os.path.join(HERE, "examples",
                                                     "plan-good.json"))
        finally:
            os.unlink(bad)
        self.assertEqual(code, 3)
        self.assertIn("error:", err)

    def test_cli_examples_exit_codes(self):
        ex = os.path.join(HERE, "examples")
        code, _, _ = run_cli(os.path.join(ex, "pack.json"),
                             os.path.join(ex, "plan-good.json"))
        self.assertEqual(code, 0)
        code, _, _ = run_cli(os.path.join(ex, "pack.json"),
                             os.path.join(ex, "plan-bad.json"))
        self.assertEqual(code, 1)
        code, _, _ = run_cli(os.path.join(ex, "pack.json"),
                             os.path.join(ex, "plan-bad.json"),
                             "--overrides", os.path.join(ex, "overrides.json"),
                             "--today", "2026-11-23")
        self.assertEqual(code, 1)  # ORG-01 waived, but HIGH findings remain


if __name__ == "__main__":
    unittest.main()
