# DevGuard

**IBM Bob-powered incident resolution for faster, evidence-backed debugging.**

DevGuard addresses a common developer workflow problem: logs, source code, dependencies, fixes, and regression tests are often investigated one after another. DevGuard uses IBM Bob IDE to coordinate the full workflow—from a production-style failure to a validated fix—while the included Python CLI gathers a deterministic, read-only evidence report.

## Problem

Developers lose time moving between logs, repository searches, dependency files, and tests before they can safely fix a bug. The handoffs are manual, evidence gets lost, and a plausible diagnosis may reach review without a regression test.

## Solution

```text
Bug report + log
        |
        v
     IBM Bob
        |
   +----+-------------+
   |         |        |
 Log task  Code task  Dependency/test task
   |         |        |
   +---------+--------+
             |
             v
   Cited root cause and ranked hypotheses
             |
             v
   Minimal fix + regression test + validation
```

IBM Bob IDE is the core reasoning and implementation environment. Agent mode, focused tasks or subagents, repository context, and test execution connect the stages into one developer workflow. `debug_agent.py` supports Bob with bounded evidence collection and a reviewable report; it never edits the target repository.

## Quick start

Requirements: Python 3.10+ and IBM Bob IDE signed into the hackathon-provisioned account. No hosted API key or local model is needed for the hackathon workflow.

```powershell
# Confirm the incident has been fixed
python demo_repo/app.py

# Both regression tests should pass
python -m unittest discover -s demo_repo/tests -v

# Verify the evidence collector
python -m unittest discover -s tests -v

# Generate a read-only report outside the sample repository
.\debug-agent.cmd --repo demo_repo --logs demo.log `
  --issue "Order summary crashes when an order has no priced items" `
  --output demo-report.md --skip-model `
  --test-command "python -m unittest discover -s tests -v"
```

The sample repository now contains the completed fix: `average_price` defines empty input as `0.0`, and the former expected failure is a normal regression test. The original `demo.log` remains as historical incident evidence for demonstrating DevGuard's investigation workflow.

## Regression monitoring

Run a single health check:

```powershell
.\monitor-regression.cmd
```

Keep monitoring locally every five minutes:

```powershell
.\monitor-regression.cmd --watch --interval 300
```

Results are recorded in `monitoring/latest.json` and `monitoring/history.jsonl`. The GitHub Actions workflow in `.github/workflows/regression-monitor.yml` also runs on relevant changes, pull requests, manual dispatch, and once per day. It uses only local tests and requires no API key.

## Dashboard

The web folder includes a sanitized demo report for the public dashboard. To generate a fresh local `demo-report.md.json`, then start the local interface:

```powershell
.\serve-dashboard.cmd
```

Open `http://localhost:8080/web/`. The dashboard loads the sanitized demo report automatically. **Analyze file** and the drop zone accept any file up to 5 MB. DevGuard JSON reports load fully; source, log, and configuration files receive a local browser scan; binary files receive metadata-only analysis. Selected files remain in the browser and are never executed.

## Measuring impact

Record a manual baseline and a Bob-assisted run using the same start and stop conditions in [docs/METRICS.md](docs/METRICS.md). Publish the observed time reduction only after both runs.

## Repository guide

- `AGENTS.md` — persistent project context and acceptance criteria for Bob.
- `docs/BOB_WORKFLOW.md` — prompt and recording sequence.
- `docs/METRICS.md` — before/after measurement template.
- `docs/SCAN_PARAMETERS.md` — coverage, limits, finding categories, and confidence rules.
- `docs/SUBMISSION_CHECKLIST.md` — account, evidence, demo, and delivery checks.
- `bob_sessions/` — required Bob task-session screenshots.
- `demo_repo/` and `demo.log` — reproducible sample incident.
- `debug_agent.py` — standard-library, read-only evidence collector.
- `tests/` — evidence collector verification.

## Safety and limitations

The collector excludes common generated, environment, credential, and secret paths; redacts common secret assignments; limits file and log sizes; verifies cited locations; and validates proposed diffs against current source. AI output can still be wrong. Review every fix and require a passing regression test.

Do not use client data, personal information, confidential code, social-media data, or any dataset without permission. This repository uses only synthetic sample data.

## IBM Bob evidence

Bob task-session screenshots have not yet been added to this repository. The documented workflow should be run and the resulting screenshots captured before treating it as recorded Bob evidence.

For every relevant Bob task, open **Tasks**, select the task, select its header, and capture the task-session consumption summary. Save the PNG using [the naming convention](bob_sessions/README.md) and include every relevant screenshot in the public repository.


