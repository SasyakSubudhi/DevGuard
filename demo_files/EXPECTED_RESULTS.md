# Rigged performance fixture

Upload `rigged_performance_test.py` to the DevGuard dashboard.

Expected result: DevGuard should report 10 heuristic findings covering correctness, security, database, API, reliability, performance, and configuration. The file also contains one explicit `RuntimeError` line for log-style error extraction.

The file is approximately 2 MB so the dashboard's **Total analysis** value can be used as a browser-side performance measurement. Run the upload three times and use the median value. The file is intentionally invalid and unsafe-looking source code, so it must not be executed.

Run `node tests/web_scanner_benchmark.cjs` from the DevGuard folder to verify coverage and measure the scanner without browser rendering. The benchmark fails unless all 10 seeded findings and both error-related log events are collected.
