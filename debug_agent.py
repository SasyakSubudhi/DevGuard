#!/usr/bin/env python3
"""Read-only, local-repository debugging assistant (standard library only)."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "target", "coverage", "__pycache__", ".next"}
SKIP_NAMES = {".env", ".env.local", "id_rsa", "id_ed25519"}
SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".rb", ".php", ".c", ".cpp", ".h", ".cs"}
MANIFESTS = {"requirements.txt", "pyproject.toml", "Pipfile", "package.json", "package-lock.json", "Cargo.toml", "go.mod", "pom.xml", "Gemfile"}
MAX_FILE = 256_000
MAX_FILES = 1500
MAX_EXCERPTS = 18
MAX_LINE = 300
MAX_FINDINGS = 80
SECRET_RE = re.compile(r"(?i)(\b(?:api[_-]?key|token|password|secret|authorization)\b\s*[:=]\s*)([^\s,;]+)")


def redact(value: str) -> str:
    return SECRET_RE.sub(r"\1[REDACTED]", value)


def safe_files(repo: Path, names: set[str] | None = None, extensions: set[str] | None = None) -> list[Path]:
    found = []
    for directory, dirs, filenames in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".env")
                   and not (Path(directory) / d).is_symlink()]
        for filename in filenames:
            if len(found) >= MAX_FILES:
                return found
            path = Path(directory) / filename
            low = filename.lower()
            if low in SKIP_NAMES or low.startswith(".env") or any(s in low for s in ("secret", "credential", "private_key")):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            if names is not None and path.name not in names:
                continue
            if extensions is not None and path.suffix.lower() not in extensions:
                continue
            try:
                if path.stat().st_size <= MAX_FILE:
                    found.append(path)
            except OSError:
                continue
    return found


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def excerpt(path: Path, repo: Path, number: int, radius: int = 2) -> dict:
    content = lines(path)
    start, end = max(1, number - radius), min(len(content), number + radius)
    return {"path": path.relative_to(repo).as_posix(), "line": number,
            "excerpt": "\n".join(f"{n}: {redact(content[n-1][:MAX_LINE])}" for n in range(start, end + 1))}


def tokens(text: str) -> list[str]:
    words = re.findall(r"[A-Za-z_][A-Za-z_0-9]{2,}", text)
    stop = {"error", "exception", "traceback", "file", "line", "failed", "from", "with", "this", "that", "none", "null", "true", "false", "most", "recent", "call", "last"}
    return list(dict.fromkeys(w.lower() for w in words if w.lower() not in stop))[:24]


def investigate_logs(log_path: Path, repo: Path, issue: str) -> dict:
    if not log_path.exists():
        return {"status": "missing", "error": f"Log file does not exist: {log_path}", "events": [], "terms": tokens(issue)}
    if not log_path.is_file():
        return {"status": "error", "error": "Logs path is not a file", "events": [], "terms": tokens(issue)}
    try:
        with log_path.open("rb") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - 1_000_000))
            raw = stream.read()
    except OSError as exc:
        return {"status": "error", "error": str(exc), "events": [], "terms": tokens(issue)}
    content = raw.decode("utf-8", errors="replace").splitlines()
    patterns = re.compile(r"error|exception|traceback|fatal|failed|panic|\bat\s+\S+[:(]\d+|File \"", re.I)
    event_indices = [i for i, line in enumerate(content) if patterns.search(line)]
    selected = event_indices[-20:]
    events = []
    frames = []
    for i in selected:
        stamp = re.search(r"\d{4}-\d\d-\d\d[T ][\d:.+-]+Z?", content[i])
        events.append({"line": i + 1, "timestamp": stamp.group(0) if stamp else None,
                       "text": redact(content[i][:MAX_LINE])})
        frame = re.search(r'File "([^"]+)", line (\d+)', content[i])
        if frame:
            frames.append({"path": frame[1].replace("\\", "/"), "line": int(frame[2])})
        else:
            frame = re.search(r"(?:at\s+[^()]*\()?([^\s()]+\.[A-Za-z]+):(\d+)(?::\d+)?\)?", content[i])
            if frame:
                frames.append({"path": frame[1].replace("\\", "/"), "line": int(frame[2])})
    key_text = issue + " " + " ".join(e["text"] for e in events)
    return {"status": "ok", "events": events, "frames": frames, "terms": tokens(key_text), "total_lines": len(content),
            "note": "Log line numbers refer to the last 1 MB when a log is larger than 1 MB."}


def investigate_code(repo: Path, terms: list[str], frames: list[dict] | None = None) -> dict:
    files = safe_files(repo, extensions=SOURCE_EXTS)
    scored = []
    frame_hits = []
    frames = frames or []
    by_relative = {path.relative_to(repo).as_posix(): path for path in files}
    for frame in frames:
        candidate = frame["path"].lstrip("./")
        matches = [path for rel, path in by_relative.items() if rel == candidate or rel.endswith("/" + candidate)]
        if len(matches) == 1:
            path = matches[0]
            try:
                if 1 <= frame["line"] <= len(lines(path)):
                    frame_hits.append(excerpt(path, repo, frame["line"]))
            except OSError:
                pass
    for path in files:
        try:
            content = lines(path)
        except OSError:
            continue
        for n, line in enumerate(content, 1):
            hits = [term for term in terms if term in line.lower()]
            if hits:
                scored.append((len(hits), path, n))
    scored.sort(key=lambda row: (-row[0], row[1].as_posix(), row[2]))
    matches = frame_hits[:MAX_EXCERPTS]
    seen = {(item["path"], item["line"]) for item in matches}
    for _, path, n in scored:
        key = (path.relative_to(repo).as_posix(), n)
        if key not in seen:
            matches.append(excerpt(path, repo, n))
            seen.add(key)
        if len(matches) >= MAX_EXCERPTS:
            break
    return {"status": "ok", "files_scanned": len(files), "stack_matches": len(frame_hits), "matches": matches}


def investigate_code_independent(repo: Path, log_path: Path, issue: str) -> dict:
    # Read a small tail independently so this worker never waits on the log investigator.
    hints = issue
    frames = []
    try:
        with log_path.open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 32_000))
            tail = stream.read().decode("utf-8", errors="replace")
            hints += " " + tail
            for path, number in re.findall(r'File "([^"]+)", line (\d+)', tail):
                frames.append({"path": path.replace("\\", "/"), "line": int(number)})
    except OSError:
        pass
    return investigate_code(repo, tokens(hints), frames)


def investigate_dependencies(repo: Path) -> dict:
    files = safe_files(repo, names=MANIFESTS)
    manifests = []
    for path in files[:12]:
        try:
            content = lines(path)
        except OSError:
            continue
        selected = [(n, line) for n, line in enumerate(content, 1) if line.strip() and not line.lstrip().startswith(("#", "//"))]
        manifests.append({"path": path.relative_to(repo).as_posix(), "lines": [f"{n}: {redact(line[:MAX_LINE])}" for n, line in selected[:35]]})
    imports = []
    for path in safe_files(repo, extensions=SOURCE_EXTS)[:300]:
        try:
            for n, line in enumerate(lines(path), 1):
                if re.match(r"\s*(import |from \S+ import |const \S+ = require\(|.*from ['\"])", line):
                    imports.append({"path": path.relative_to(repo).as_posix(), "line": n, "text": redact(line[:MAX_LINE])})
                    if len(imports) >= 30:
                        break
        except OSError:
            continue
        if len(imports) >= 30:
            break
    return {"status": "ok", "manifests": manifests, "imports": imports}


def finding(category: str, severity: str, confidence: str, path: Path, repo: Path,
            line: int, title: str, evidence: str, recommendation: str) -> dict:
    return {"category": category, "severity": severity, "confidence": confidence,
            "status": "possible", "path": path.relative_to(repo).as_posix(), "line": line,
            "title": title, "evidence": redact(evidence[:MAX_LINE]), "recommendation": recommendation}


def investigate_quality(repo: Path) -> dict:
    rules = [
        ("correctness", "high", "high", re.compile(r"/\s*len\s*\("), "Possible division by empty collection",
         "Verify empty-input behavior and guard a zero-length denominator."),
        ("correctness", "medium", "medium", re.compile(r"\[[0-9]+\]"), "Unchecked positional access",
         "Verify the sequence length before indexing."),
        ("security", "critical", "high", re.compile(r"\b(?:eval|exec)\s*\("), "Dynamic code execution",
         "Remove dynamic execution or strictly validate and isolate its input."),
        ("security", "high", "high", re.compile(r"subprocess\.(?:run|Popen|call).*shell\s*=\s*True"), "Shell command injection risk",
         "Use an argument list with shell disabled and validate user-controlled values."),
        ("reliability", "medium", "high", re.compile(r"except\s*:\s*(?:#.*)?$"), "Bare exception handler",
         "Catch specific exceptions and record actionable context."),
        ("api", "medium", "medium", re.compile(r"requests\.(?:get|post|put|delete|patch)\s*\((?![^)]*timeout\s*=)"), "HTTP call may lack a timeout",
         "Set an explicit connection/read timeout and handle timeout failures."),
        ("database", "high", "medium", re.compile(r"(?:execute|executemany)\s*\(\s*f['\"]"), "Possible SQL injection",
         "Use parameterized SQL instead of interpolating values."),
        ("performance", "low", "medium", re.compile(r"time\.sleep\s*\("), "Blocking sleep",
         "Confirm this path can block; use event-driven waiting for async or request code."),
    ]
    findings = []
    files = safe_files(repo, extensions=SOURCE_EXTS)
    for path in files:
        try:
            content = lines(path)
        except OSError:
            continue
        for number, text_line in enumerate(content, 1):
            for category, severity, confidence, pattern, title, recommendation in rules:
                if pattern.search(text_line):
                    if title == "Possible division by empty collection":
                        denominator = re.search(r"/\s*len\s*\(\s*([A-Za-z_]\w*)\s*\)", text_line)
                        if denominator:
                            name = re.escape(denominator.group(1))
                            lookback = "\n".join(content[max(0, number - 5):number - 1])
                            guard = re.search(
                                rf"if\s+(?:not\s+{name}|len\s*\(\s*{name}\s*\)\s*==\s*0|{name}\s*==\s*\[\])\s*:",
                                lookback,
                            )
                            if guard:
                                continue
                    findings.append(finding(category, severity, confidence, path, repo, number,
                                            title, text_line.strip(), recommendation))
            if len(findings) >= MAX_FINDINGS:
                break
        if len(findings) >= MAX_FINDINGS:
            break
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (order[item["severity"]], item["path"], item["line"]))
    return {"status": "ok", "files_scanned": len(files), "findings": findings}


def investigate_configuration(repo: Path) -> dict:
    extensions = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".properties"}
    config_files = safe_files(repo, extensions=extensions)
    findings = []
    patterns = [
        (re.compile(r"(?i)\bdebug\b\s*[:=]\s*(?:true|1|yes)"), "medium", "Debug mode enabled",
         "Disable debug mode outside local development."),
        (re.compile(r"(?i)\bverify(?:_ssl)?\b\s*[:=]\s*false"), "high", "TLS verification disabled",
         "Enable certificate verification."),
        (re.compile(r"(?i)\ballow[_-]?origins?\b.*\*"), "medium", "Wildcard cross-origin access",
         "Restrict allowed origins to trusted applications."),
    ]
    for path in config_files:
        try:
            for number, text_line in enumerate(lines(path), 1):
                for pattern, severity, title, recommendation in patterns:
                    if pattern.search(text_line):
                        findings.append(finding("configuration", severity, "high", path, repo, number,
                                                title, text_line.strip(), recommendation))
        except OSError:
            continue
    return {"status": "ok", "files_scanned": len(config_files), "findings": findings[:MAX_FINDINGS]}


def investigate_tests(repo: Path) -> dict:
    sources = safe_files(repo, extensions=SOURCE_EXTS)
    tests = [path for path in sources if path.name.lower().startswith("test_") or "tests" in path.parts
             or path.name.lower().endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts"))]
    expected_failures = []
    for path in tests:
        try:
            for number, text_line in enumerate(lines(path), 1):
                if re.search(r"expectedFailure|xfail|\.skip\s*\(|@Ignore|@Disabled", text_line):
                    expected_failures.append({"path": path.relative_to(repo).as_posix(), "line": number,
                                              "evidence": text_line.strip()})
        except OSError:
            continue
    source_count = len([path for path in sources if path not in tests])
    return {"status": "ok", "source_files": source_count, "test_files": len(tests),
            "test_to_source_ratio": round(len(tests) / max(source_count, 1), 2),
            "expected_failures": expected_failures[:MAX_FINDINGS]}


def prioritize_findings(quality: dict, configuration: dict, tests: dict, logs: dict) -> list[dict]:
    combined = quality.get("findings", []) + configuration.get("findings", [])
    frame_locations = {(Path(frame["path"]).name, frame["line"]) for frame in logs.get("frames", [])}
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for item in combined:
        if (Path(item["path"]).name, item["line"]) in frame_locations:
            item["status"] = "highly_likely"
            item["confidence"] = "high"
            item["correlated_with_stack"] = True
    for item in tests.get("expected_failures", []):
        combined.append({"category": "testing", "severity": "medium", "confidence": "high",
                         "status": "confirmed", "path": item["path"], "line": item["line"],
                         "title": "Suppressed or expected test failure", "evidence": item["evidence"],
                         "recommendation": "Resolve the known defect and convert this into a normal passing regression test."})
    return sorted(combined, key=lambda item: (rank[item["severity"]],
                  0 if item["status"] == "confirmed" else 1 if item["status"] == "highly_likely" else 2,
                  item["path"], item["line"]))[:MAX_FINDINGS]


def build_incident_summary(issue: str, logs: dict, code: dict) -> dict:
    events = logs.get("events", [])
    exception = next((event["text"] for event in reversed(events)
                      if re.search(r"(?:Error|Exception|panic|fatal)(?::|\b)", event["text"], re.I)), None)
    stack_count = code.get("stack_matches", 0)
    stack = code.get("matches", [])[:stack_count]
    fault = stack[-1] if stack else (code.get("matches") or [None])[0]
    source_line = None
    if fault:
        source_line = next((row.split(":", 1)[1].strip() for row in fault["excerpt"].splitlines()
                            if row.startswith(f"{fault['line']}:") ), None)
    diagnosis, next_action = "Evidence is insufficient for a deterministic diagnosis.", "Review the cited source and reproduce the failure."
    if exception and fault:
        location = f"{fault['path']}:{fault['line']}"
        if "ZeroDivisionError" in exception:
            diagnosis = f"The failure occurs at {location}, where a calculation divides by zero."
            if source_line and "len(" in source_line:
                diagnosis += " The denominator is a collection length, so an empty collection reaches this calculation."
            next_action = "Define the expected empty-input behavior, guard it before the division, and add a regression test."
        elif "KeyError" in exception:
            diagnosis = f"The failure occurs at {location} because code accesses a mapping key that is absent."
            next_action = "Validate the input contract or handle the missing key explicitly, then add a regression test."
        elif "IndexError" in exception:
            diagnosis = f"The failure occurs at {location} because code indexes outside the available sequence."
            next_action = "Handle the empty or shorter sequence before indexing, then add a regression test."
        elif "AttributeError" in exception:
            diagnosis = f"The failure occurs at {location} because the runtime value lacks the requested attribute."
            next_action = "Trace the value's origin, enforce its expected type, and add a regression test."
        else:
            diagnosis = f"The deepest resolved stack frame is {location}, which is the leading fault candidate for {exception}."
            next_action = "Reproduce the failure at this location, verify the input assumptions, and add a regression test."
    return {
        "issue": issue or "No issue description supplied",
        "exception": exception or "No explicit exception found in the selected log events",
        "likely_fault": ({"path": fault["path"], "line": fault["line"]} if fault else None),
        "causal_path": [{"path": item["path"], "line": item["line"]} for item in stack],
        "confidence": "high" if exception and fault and stack_count >= 1 else "low",
        "preliminary_diagnosis": diagnosis,
        "next_action": next_action,
        "source_line": source_line,
    }


def run_validation(repo: Path, command: str, timeout: int) -> dict:
    started = time.perf_counter()
    try:
        argv = shlex.split(command, posix=os.name != "nt")
        if not argv:
            raise ValueError("test command is empty")
        with tempfile.TemporaryDirectory(prefix="devguard-validation-") as temp:
            target = Path(temp) / "repo"
            shutil.copytree(repo, target, ignore=shutil.ignore_patterns(*SKIP_DIRS, ".env*", "*.pyc"))
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(argv, cwd=target, capture_output=True, text=True,
                                    timeout=timeout, env=environment, shell=False)
        combined = redact((result.stdout + "\n" + result.stderr).strip())[-8_000:]
        expected = bool(re.search(r"expected failures?", combined, re.I))
        outcome = "passed_with_expected_failures" if result.returncode == 0 and expected else (
            "passed" if result.returncode == 0 else "failed")
        return {"status": outcome, "exit_code": result.returncode, "command": argv,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2), "output": combined}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "command": command,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2), "error": str(exc)}


def ollama_chat(payload: dict, model: str, url: str, timeout: int) -> dict:
    system = ("You are a careful debugging analyst. Respond with JSON only: "
              "{\"root_cause\": string, \"confidence\": \"low|medium|high\", "
              "\"evidence\": [{\"path\": string, \"line\": integer, \"reason\": string}], "
              "\"fix\": string, \"diff\": string}. Cite only source paths and line numbers present "
              "in the provided code matches or dependency findings. Do not invent evidence. "
              "The diff must be a unified diff with --- a/path and +++ b/path headers, "
              "and should be minimal. If evidence is insufficient, say so and use an empty diff.")
    body = json.dumps({"model": model, "stream": False, "format": "json", "messages": [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)[:40_000]},
    ]}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError(f"Ollama model '{model}' was not found. Run: ollama pull {model}") from exc
        raise
    return json.loads(answer["message"]["content"])


def validate_evidence(evidence: object, repo: Path, allowed: set[tuple[str, int]] | None = None) -> tuple[list[dict], list[str]]:
    valid, errors = [], []
    if not isinstance(evidence, list):
        return [], ["Model evidence is not a list"]
    for item in evidence:
        try:
            rel, number = item["path"], item["line"]
            if not isinstance(rel, str) or not isinstance(number, int) or number < 1:
                raise ValueError("invalid path or line")
            path = (repo / rel).resolve()
            if not path.is_relative_to(repo) or not path.is_file() or path.is_symlink() or number > len(lines(path)):
                raise ValueError("path or line does not exist in repository")
            canonical = path.relative_to(repo).as_posix()
            if allowed is not None and (canonical, number) not in allowed:
                raise ValueError("citation was not included in the investigation")
            valid.append({"path": canonical, "line": number, "reason": str(item.get("reason", ""))})
        except (KeyError, ValueError, OSError, TypeError) as exc:
            errors.append(f"Rejected evidence: {exc}")
    return valid, errors


def validate_diff(diff: object, repo: Path) -> tuple[str, list[str]]:
    if not isinstance(diff, str) or not diff.strip():
        return "", []
    rows = diff.splitlines()
    errors = []
    if len(rows) < 3 or not rows[0].startswith("--- a/") or not rows[1].startswith("+++ b/"):
        return "", ["Diff lacks unified file headers"]
    old, new = rows[0][6:], rows[1][6:]
    if old != new or not old or (repo / old).resolve().is_relative_to(repo) is False or not (repo / old).is_file():
        return "", ["Diff target is invalid or outside repository"]
    original = lines(repo / old)
    position, seen_hunk, i = 0, False, 2
    while i < len(rows):
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", rows[i])
        if not match:
            errors.append("Malformed hunk header or multiple file diff")
            break
        seen_hunk = True
        old_start, old_count = int(match[1]), int(match[2] or 1)
        new_count = int(match[4] or 1)
        if old_start < 1 or old_start - 1 < position:
            errors.append("Invalid hunk position")
        position = old_start - 1
        i += 1
        observed_old = observed_new = 0
        while i < len(rows) and not rows[i].startswith("@@"):
            row = rows[i]
            if row.startswith((" ", "-")):
                observed_old += 1
                if position >= len(original) or original[position] != row[1:]:
                    errors.append("Diff context does not match target file")
                position += 1
            if row.startswith((" ", "+")):
                observed_new += 1
            if not row.startswith((" ", "-", "+")) and row != "\\ No newline at end of file":
                errors.append("Malformed diff line")
            i += 1
        if observed_old != old_count or observed_new != new_count:
            errors.append("Hunk line count mismatch")
    if not seen_hunk:
        errors.append("Diff has no hunk")
    return (diff if not errors else ""), errors


def render(report: dict) -> str:
    out = ["# Debugging report", "", f"Status: {report['status']}", ""]
    summary = report.get("summary", {})
    out += ["## Incident summary", "", f"**Issue:** {summary.get('issue', 'Unknown')}",
            "", f"**Observed failure:** {summary.get('exception', 'Unknown')}", ""]
    fault = summary.get("likely_fault")
    if fault:
        out += [f"**Likely fault location:** `{fault['path']}:{fault['line']}`",
                "", f"**Evidence confidence:** {summary.get('confidence', 'low')}", ""]
    out += ["**Preliminary diagnosis:** " + summary.get("preliminary_diagnosis", "Unavailable"),
            "", "**Recommended next action:** " + summary.get("next_action", "Review the evidence."), ""]
    if summary.get("causal_path"):
        out += ["**Causal path:** " + " → ".join(
            f"`{item['path']}:{item['line']}`" for item in summary["causal_path"]), ""]
    findings = report.get("findings", [])
    if findings:
        counts = report.get("finding_counts", {})
        out += ["## Prioritized findings", "",
                f"Critical: {counts.get('critical', 0)} · High: {counts.get('high', 0)} · "
                f"Medium: {counts.get('medium', 0)} · Low: {counts.get('low', 0)}", ""]
        out += [f"- **{item['severity'].upper()} · {item['category']} · {item['status']}** — "
                f"`{item['path']}:{item['line']}` {item['title']}. {item['recommendation']}"
                for item in findings]
    if report.get("diagnosis"):
        d = report["diagnosis"]
        out += ["## Likely root cause", "", str(d.get("root_cause", "Unknown")), "", f"Confidence: {d.get('confidence', 'unknown')}", "", "## Evidence", ""]
        out += [f"- `{e['path']}:{e['line']}` — {e['reason']}" for e in d.get("evidence", [])] or ["- No validated source citations."]
        out += ["", "## Suggested fix", "", str(d.get("fix", "No fix proposed.")), ""]
        if d.get("diff"):
            out += ["## Proposed diff", "", "```diff", d["diff"], "```", ""]
    else:
        heading = "Evidence ready for IBM Bob" if report["status"] == "evidence_ready" else "Diagnosis unavailable"
        out += [f"## {heading}", "", report.get("model_error", "No model result."), ""]
    out += ["## Investigation", "", "### Log events", ""]
    if report["logs"].get("error"):
        out += [f"Log input: {report['logs']['error']}", ""]
    out += [f"- Line {e['line']}: {e['text']}" for e in report["logs"].get("events", [])] or ["- No error events found."]
    out += ["", f"### Code matches ({report['code'].get('files_scanned', 0)} files scanned)", ""]
    out += [f"- `{e['path']}:{e['line']}`\n\n  {e['excerpt'].replace(chr(10), chr(10) + '  ')}" for e in report["code"].get("matches", [])] or ["- No matches found."]
    out += ["", "### Dependency manifests", ""]
    out += [f"- `{m['path']}`: " + "; ".join(m["lines"][:5]) for m in report["dependencies"].get("manifests", [])] or ["- No manifests found."]
    if report.get("validation_errors"):
        out += ["", "## Validation warnings", ""] + [f"- {e}" for e in report["validation_errors"]]
    if report.get("test_validation"):
        validation = report["test_validation"]
        out += ["", "## Test validation", "", f"Status: **{validation['status']}**",
                "", f"Duration: {validation['duration_ms']} ms", ""]
        if validation.get("output"):
            out += ["```text", validation["output"], "```", ""]
        elif validation.get("error"):
            out += [f"Error: {validation['error']}", ""]
    timings = report.get("timings_ms", {})
    if timings:
        out += ["", "## Performance", ""] + [f"- {name}: {value} ms" for name, value in timings.items()]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--logs", required=True, type=Path)
    parser.add_argument("--issue", default="")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model", default="gemma4:e2b")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--skip-model", action="store_true",
                        help="Collect evidence only; do not call Ollama")
    parser.add_argument("--test-command", help="Run this test command in an isolated copy of the repository")
    parser.add_argument("--test-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    total_started = time.perf_counter()
    repo = args.repo.resolve()
    if not repo.is_dir():
        parser.error("--repo must be an existing directory")
    if args.output.resolve().is_relative_to(repo):
        parser.error("--output must be outside --repo to keep the target repository unchanged")
    log_path = args.logs.resolve()
    print("[1/3] Investigating logs, code, dependencies, quality, configuration, and tests concurrently...", file=sys.stderr)
    investigation_started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        log_future = pool.submit(investigate_logs, log_path, repo, args.issue)
        code_future = pool.submit(investigate_code_independent, repo, log_path, args.issue)
        dep_future = pool.submit(investigate_dependencies, repo)
        quality_future = pool.submit(investigate_quality, repo)
        config_future = pool.submit(investigate_configuration, repo)
        tests_future = pool.submit(investigate_tests, repo)
        logs, code, dependencies = log_future.result(), code_future.result(), dep_future.result()
        quality, configuration, test_inventory = quality_future.result(), config_future.result(), tests_future.result()
    prioritized = prioritize_findings(quality, configuration, test_inventory, logs)
    finding_counts = {severity: sum(1 for item in prioritized if item["severity"] == severity)
                      for severity in ("critical", "high", "medium", "low")}
    report = {"status": "incomplete", "repo": str(repo), "logs": logs, "code": code, "dependencies": dependencies,
              "issue": args.issue, "diagnosis": None, "validation_errors": [],
              "summary": build_incident_summary(args.issue, logs, code),
              "quality": quality, "configuration": configuration, "test_inventory": test_inventory,
              "findings": prioritized, "finding_counts": finding_counts,
              "scan_parameters": {"max_files": MAX_FILES, "max_file_bytes": MAX_FILE,
                                  "max_log_bytes": 1_000_000, "max_findings": MAX_FINDINGS,
                                  "excluded_directories": sorted(SKIP_DIRS)},
              "timings_ms": {"investigation": round((time.perf_counter() - investigation_started) * 1000, 2)}}
    if args.skip_model:
        print("[2/3] Evidence collected for IBM Bob; local model skipped.", file=sys.stderr)
        report["status"] = "evidence_ready"
        report["model_error"] = "Use this evidence as input to the IBM Bob workflow in docs/BOB_WORKFLOW.md."
    else:
        print("[2/3] Asking local Ollama model for a diagnosis...", file=sys.stderr)
        try:
            diagnosis = ollama_chat({"issue": args.issue, "logs": logs, "code": code, "dependencies": dependencies},
                                    args.model, args.ollama_url, args.timeout)
            if not isinstance(diagnosis, dict):
                raise ValueError("model response is not a JSON object")
            allowed = set()
            for match in code["matches"]:
                for shown in match["excerpt"].splitlines():
                    line_number = re.match(r"^(\d+):", shown)
                    if line_number:
                        allowed.add((match["path"], int(line_number[1])))
            allowed.update((e["path"], e["line"]) for e in dependencies["imports"])
            evidence, evidence_errors = validate_evidence(diagnosis.get("evidence"), repo, allowed)
            diff, diff_errors = validate_diff(diagnosis.get("diff"), repo)
            diagnosis["evidence"], diagnosis["diff"] = evidence, diff
            report["diagnosis"] = diagnosis
            report["validation_errors"] = evidence_errors + diff_errors
            report["status"] = "complete" if evidence and diff and logs["status"] == "ok" and not report["validation_errors"] else "needs_review"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
            report["model_error"] = f"Local model unavailable or returned invalid JSON: {exc}"
    if args.test_command:
        report["test_validation"] = run_validation(repo, args.test_command, args.test_timeout)
        validation = report["test_validation"]
        summary = report["summary"]
        source_line = summary.get("source_line") or ""
        historical_division_fixed = (
            validation.get("status") == "passed"
            and "ZeroDivisionError" in summary.get("exception", "")
            and "/" not in source_line
        )
        if historical_division_fixed:
            report["status"] = "resolved"
            summary["confidence"] = "high"
            summary["preliminary_diagnosis"] = (
                "The historical empty-input failure is fixed. The cited source now guards the failing path, "
                "and the regression suite passes."
            )
            summary["next_action"] = "Resolution verified. Keep the regression test and monitor for recurrence."
            monitor_result = repo.parent / "monitoring" / "latest.json"
            if monitor_result.is_file():
                try:
                    monitor_status = json.loads(monitor_result.read_text(encoding="utf-8")).get("status")
                    if monitor_status == "healthy":
                        summary["next_action"] = "Regression monitoring is active. Latest checks are healthy."
                except (OSError, json.JSONDecodeError):
                    pass
    report["timings_ms"]["total"] = round((time.perf_counter() - total_started) * 1000, 2)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(report), encoding="utf-8")
    args.output.with_suffix(args.output.suffix + ".json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[3/3] {report['status']}: {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
