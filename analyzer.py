#!/usr/bin/env python3
"""
Brute-Force Log Analyzer
------------------------
Parses SSH auth logs and detects possible brute-force login attempts by
counting failed password attempts per IP address.

Usage:
    python analyzer.py                  # uses bundled sample_auth.log
    python analyzer.py /var/log/auth.log
    python analyzer.py sample_auth.log --threshold 3
"""

import os
import re
import sys
from collections import Counter, defaultdict

DEFAULT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_auth.log")
DEFAULT_THRESHOLD = 5

# Matches typical sshd lines like:
# Nov 15 10:23:41 server sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2
FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def analyse(path: str) -> tuple[Counter, dict, int]:
    """Return (failures per IP, first/last timestamps per IP, total lines read)."""
    failures: Counter = Counter()
    timestamps: dict[str, list[str]] = defaultdict(list)
    total = 0
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                total += 1
                match = FAILED_RE.search(line)
                if match:
                    ip = match.group("ip")
                    failures[ip] += 1
                    timestamps[ip].append(match.group("timestamp"))
    except FileNotFoundError:
        print(f"Error: log file not found: {path}")
        sys.exit(1)
    return failures, timestamps, total


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--threshold")]
    threshold = DEFAULT_THRESHOLD
    for a in sys.argv[1:]:
        if a.startswith("--threshold"):
            try:
                threshold = int(a.split("=", 1)[1])
            except (IndexError, ValueError):
                print("Error: use --threshold=N, e.g. --threshold=3")
                sys.exit(1)

    path = args[0] if args else DEFAULT_LOG
    display_path = args[0] if args else "sample_auth.log"
    failures, timestamps, total = analyse(path)

    print(f"Log file: {display_path}")
    print(f"Lines read: {total}")
    print(f"Total failed logins: {sum(failures.values())}")
    print(f"Unique attacking IPs: {len(failures)}")
    print(f"Brute-force threshold: >= {threshold} failures")
    print()

    if not failures:
        print("No failed password attempts found.")
        return

    print("Failed attempts per IP (most first):")
    for ip, count in failures.most_common():
        first = timestamps[ip][0]
        last = timestamps[ip][-1]
        flag = "  <-- BRUTE FORCE SUSPECTED" if count >= threshold else ""
        print(f"  {ip}: {count} failures (first {first}, last {last}){flag}")

    suspects = [ip for ip, count in failures.items() if count >= threshold]
    print()
    if suspects:
        print(f"Flagged IPs (>= {threshold} failures): {', '.join(suspects)}")
    else:
        print(f"No IP reached the brute-force threshold of {threshold}.")


if __name__ == "__main__":
    main()
