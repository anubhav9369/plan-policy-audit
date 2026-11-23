# Policy audit — plan research-summary v4

**Verdict: BLOCKED** — pack `default` v1.2.0, audited 2026-11-23.

Rules checked: 5 · passed: 0 · findings: 5 (HIGH 2, MEDIUM 2, LOW 1) · waived: 0

## Must fix before execution

- **SEC-01** [HIGH] — Publishing, deleting or transferring is never a routine step.
  - step s3: action 'publish summary to the team blog' contains forbidden ['publish']
- **SEC-02** [HIGH] — Every irreversible step needs a human gate before it runs.
  - step s3: irreversible, no human gate
- **ORG-01** [MEDIUM] — Total plan cost must stay under the $5 budget.
  - total cost $5.30 exceeds limit $5.00
- **ETH-01** [MEDIUM] — Every step must say why it exists.
  - step s2: no reason given
  - step s3: no reason given
- **ORG-02** [LOW] — Every step must carry a cost or time estimate.
  - step s3: no cost/time estimate
