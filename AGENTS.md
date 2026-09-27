# DevGuard project context

## Goal

DevGuard reduces the time required to resolve a software incident. Given a bug report and logs, it gathers evidence from logs, source code, and dependency manifests, identifies the root cause, proposes the smallest safe fix, adds a regression test, and validates the result.

## Required debugging workflow

1. Preserve the failing behavior before changing code.
2. Investigate logs, code paths, and dependencies as separate focused tasks. Run independent investigations in parallel when Bob supports it.
3. Cite repository-relative files and line numbers for every root-cause claim.
4. Rank hypotheses and state uncertainty. Do not invent evidence.
5. Make the smallest fix that addresses the demonstrated cause.
6. Add or update a regression test that fails before the fix and passes after it.
7. Run the relevant tests and report the exact commands and results.
8. Never include secrets, credentials, or personal data in prompts, reports, or screenshots.

## Project commands

- Debugging-agent tests: `python -m unittest discover -s tests -v`
- Sample-app tests: `python -m unittest discover -s demo_repo/tests -v`
- Reproduce incident: `python demo_repo/app.py`
- Collect a read-only report: `.\debug-agent.cmd --repo demo_repo --logs demo.log --issue "Order summary crashes when an order has no priced items" --output demo-report.md --skip-model`

## Acceptance criteria

- The root cause is backed by source evidence.
- A regression test covers the empty-order incident.
- All test suites pass after the proposed fix.
- The target repository is not changed by the evidence-collection CLI.
