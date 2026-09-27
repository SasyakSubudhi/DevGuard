"""Run DevGuard's regression checks and record the latest health result."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LATEST = ROOT / "monitoring" / "latest.json"
HISTORY = ROOT / "monitoring" / "history.jsonl"

CHECKS = [
    ("empty-order regression", [sys.executable, "-m", "unittest", "discover", "-s", "demo_repo/tests", "-v"]),
    ("DevGuard regression suite", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]),
]


def run_check(name: str, command: list[str]) -> dict:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    return {
        "name": name,
        "status": "passed" if completed.returncode == 0 else "failed",
        "return_code": completed.returncode,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "output": output[-5000:],
    }


def monitor_once() -> dict:
    checks = [run_check(name, command) for name, command in CHECKS]
    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": "healthy" if all(check["status"] == "passed" for check in checks) else "regression_detected",
        "checks": checks,
    }
    LATEST.parent.mkdir(parents=True, exist_ok=True)
    LATEST.write_text(json.dumps(result, indent=2), encoding="utf-8")
    with HISTORY.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "checked_at": result["checked_at"],
            "status": result["status"],
            "checks": [{"name": check["name"], "status": check["status"], "duration_ms": check["duration_ms"]}
                       for check in checks],
        }) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor DevGuard's fixed empty-order regression.")
    parser.add_argument("--watch", action="store_true", help="Repeat until stopped.")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between watch checks (default: 300).")
    args = parser.parse_args()

    while True:
        result = monitor_once()
        print(f"[{result['checked_at']}] {result['status']}")
        for check in result["checks"]:
            print(f"  {check['status']:>6}  {check['name']}  {check['duration_ms']} ms")
        if not args.watch or result["status"] != "healthy":
            return 0 if result["status"] == "healthy" else 1
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
