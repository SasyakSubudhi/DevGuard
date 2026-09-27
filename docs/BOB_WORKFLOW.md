# Bob workflow for the recorded demo

## One task to run in Bob IDE

Open this repository in IBM Bob IDE, use Agent mode, and paste the following prompt:

> Investigate the incident in `demo.log`: "Order summary crashes when an order has no priced items." First reproduce the failure without editing source. Then use focused parallel tasks or subagents where available: one must analyze the log and stack trace, one must trace the source call path and data flow, and one must inspect dependencies and existing tests. Merge their evidence into ranked root-cause hypotheses with repository-relative file and line citations. Implement the smallest safe fix, add a regression test that fails on the original code, run both test suites listed in `AGENTS.md`, and report the before/after results. Do not expose secrets or use external data. At the end, summarize the files changed and why.

## Expected diagnosis

The empty order reaches `average_price([])`. The function divides by `len(prices)`, which is zero. The intended behavior for an order with no priced items is a stable summary with an average of `0.0`.

Do not give the expected diagnosis to Bob in the task prompt. It is recorded here so the team can verify whether the workflow found the known cause.

## Demo sequence

1. Start screen recording and show the failing sample-app test.
2. Show the prompt and Bob's focused investigations.
3. Show Bob's cited diagnosis and proposed change.
4. Show the regression test and passing validation.
5. Run the evidence CLI and show its read-only report.
6. Show the measured before/after table in `docs/METRICS.md`.
7. Open the Bob task header and capture its session summary for `bob_sessions/`.

