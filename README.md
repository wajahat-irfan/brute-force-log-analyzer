# Brute-Force Log Analyzer

Parses SSH auth logs and flags IP addresses that look like brute-force login attempts.

**Author:** Wajahat Irfan — BS Computer Science student (7th semester), GPGC No. 1 Abbottabad

## What it does

- Reads `sshd` "Failed password" lines from an auth log (bundled `sample_auth.log` by default, or any log file you pass in)
- Counts failed attempts per IP address
- Flags any IP with **5 or more failures** (threshold adjustable with `--threshold=N`)
- Prints a report: total failures, unique IPs, per-IP counts with first/last timestamps, and the flagged IPs

## How to run

```bash
python analyzer.py                        # uses sample_auth.log
python analyzer.py /var/log/auth.log      # analyse a real log file
python analyzer.py sample_auth.log --threshold=3
```

No extra packages needed — Python 3 standard library only.

## Example output

```
$ python analyzer.py
Log file: sample_auth.log
Lines read: 18
Total failed logins: 16
Unique attacking IPs: 3
Brute-force threshold: >= 5 failures

Failed attempts per IP (most first):
  203.0.113.45: 8 failures (first Nov 15 10:21:03, last Nov 15 10:27:12)  <-- BRUTE FORCE SUSPECTED
  198.51.100.23: 6 failures (first Nov 15 10:23:44, last Nov 15 10:24:15)  <-- BRUTE FORCE SUSPECTED
  192.0.2.77: 2 failures (first Nov 15 10:25:30, last Nov 15 10:25:35)

Flagged IPs (>= 5 failures): 203.0.113.45, 198.51.100.23
```

(The sample log uses the documentation IP ranges 203.0.113.x / 198.51.100.x / 192.0.2.x, so no real addresses are involved.)

## Skills shown

- Log parsing with regular expressions
- Counting and ranking with `collections.Counter`
- CLI arguments and configurable thresholds
- Turning raw logs into a readable security report
