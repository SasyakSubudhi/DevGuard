# Investigation parameters

DevGuard uses bounded scans so results remain fast and reviewable.

| Parameter | Default | Purpose |
|---|---:|---|
| Maximum repository files | 1,500 | Prevent unbounded scans in very large repositories |
| Maximum individual file size | 256 KB | Skip generated bundles and unusually large files |
| Log tail | 1 MB | Focus on recent failures while bounding memory use |
| Maximum source excerpts | 18 | Keep model and human review context focused |
| Maximum normalized findings | 80 | Keep prioritization useful rather than noisy |
| Test timeout | 120 seconds | Prevent a stuck test suite from blocking the workflow |

Generated folders such as `.git`, `node_modules`, `dist`, `build`, `.next`, coverage output, virtual environments, and caches are excluded. Common environment, credential, private-key, and secret file names are excluded. Common secret assignments in included evidence are redacted.

## Finding model

Each finding records:

- **Category:** correctness, reliability, security, API, database, configuration, performance, or testing.
- **Severity:** critical, high, medium, or low.
- **Confidence:** high, medium, or low.
- **Status:** confirmed, highly likely, possible, or unresolved.
- **Evidence:** repository-relative path, line number, and bounded source text.
- **Recommendation:** the next verification or remediation action.

Heuristic findings are candidates, not proof. A finding becomes highly likely when it correlates with a runtime stack frame. Test output can confirm a failure. IBM Bob performs the final repository-aware reasoning, fix, regression-test creation, and validation.
