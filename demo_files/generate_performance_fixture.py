"""Generate a safe, deliberately faulty text fixture for DevGuard.

The generated file resembles Python source but is intended only for upload and
static analysis. DevGuard's browser interface reads it as text and never runs it.
"""

from pathlib import Path


OUTPUT = Path(__file__).with_name("rigged_performance_test.py")
TARGET_BYTES = 2 * 1024 * 1024

KNOWN_FINDINGS = [
    "average = sum(values) / len(values)  # expected: division by empty collection\n",
    "result = eval(user_expression)  # expected: dynamic code execution\n",
    "subprocess.run(command, shell=True)  # expected: shell injection risk\n",
    'api_key = "DEMO_FAKE_KEY_DO_NOT_USE"  # expected: embedded secret\n',
    'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # expected: SQL injection\n',
    'response = requests.get(url)  # expected: missing HTTP timeout\n',
    "except:  # expected: bare exception handler\n",
    "    pass\n",
    "time.sleep(1)  # expected: blocking sleep\n",
    "verify_ssl = false  # expected: TLS verification disabled\n",
    "debug = true  # expected: debug mode enabled\n",
    "raise RuntimeError('PERFORMANCE_FIXTURE_ERROR')\n",
]


def main() -> None:
    header = (
        "# DEVGUARD STATIC-ANALYSIS PERFORMANCE FIXTURE\n"
        "# Deliberately contains insecure and incorrect patterns. DO NOT RUN.\n"
        "# Safe purpose: upload this file to the local DevGuard dashboard.\n\n"
    )
    chunks = [header, *KNOWN_FINDINGS, "\n"]
    index = 0
    current_size = sum(len(chunk.encode("utf-8")) for chunk in chunks)
    while current_size < TARGET_BYTES:
        line = f"fixture_record_{index:06d} = 'benign performance padding {index:06d}'\n"
        chunks.append(line)
        current_size += len(line.encode("utf-8"))
        index += 1
    OUTPUT.write_text("".join(chunks), encoding="utf-8")
    print(f"Created {OUTPUT} ({OUTPUT.stat().st_size:,} bytes, {index:,} padding lines)")


if __name__ == "__main__":
    main()
