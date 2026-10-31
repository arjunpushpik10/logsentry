# LogSentry

**An open-source SOC Tier-1 triage assistant for Linux SSH logs.** Feed it an `auth.log`, get back a prioritized list of attacks, the MITRE ATT&CK technique for each, and the exact next steps an analyst should take. Optionally, Claude turns the findings into a plain-English incident summary.

Zero dependencies (Python standard library only), explainable rules instead of a black box, and a privacy-minimizing AI layer.

## Why this exists

A Tier-1 analyst's day is a flood of alerts. The hard part is not seeing the noise, it is knowing **which 1 in 50 matters and what to do next**. The most dangerous SSH pattern is easy to miss in raw logs: *many failures followed by one success*. LogSentry surfaces that first.

## Quick start

```bash
git clone https://github.com/arjunpushpik10/logsentry.git
cd logsentry
python3 make_sample_log.py                      # creates a synthetic sample_auth.log
python3 logsentry.py sample_auth.log --year 2026
python3 -m unittest -v                          # run the tests
```

Use it on a real host (read access to the log required):

```bash
python3 logsentry.py /var/log/auth.log --year 2026 --markdown report.md --json report.json
```

See [`sample_report.md`](sample_report.md) for real output.

## Detections

| Rule | Severity | Triggers when | ATT&CK (approximate) |
|---|---|---|---|
| `success_after_failures` | Critical | A login succeeds from an IP with 3+ failures in the previous hour | T1078 Valid Accounts |
| `brute_force` | Medium / High | 5+ failures from one IP inside 5 minutes (20+ = High) | T1110.001 |
| `password_spraying` | High | One IP fails against 5+ different accounts | T1110.003 |
| `root_targeted` | Medium | 3+ failed logins as `root` | T1110.001 |
| `user_enumeration` | Low / Medium | One IP probes 3+ non-existent usernames | T1595 |

All thresholds are tunable (`--threshold`, `--window`). ATT&CK mappings are approximate; verify before citing them in a formal report.

## Optional AI summary

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 logsentry.py sample_auth.log --year 2026 --ai
```

The model (default `claude-sonnet-5-5`, override with `--model` or `LOGSENTRY_MODEL`) receives a situation summary request over the **findings only**:

- Raw log lines and hostnames are never sent.
- Non-generic usernames are pseudonymized (`user_1`, `user_2`, ...).
- Source IPs and timestamps **are** sent, so do not use `--ai` if that is not acceptable for your environment.
- The model is told the data is untrusted and must not follow instructions inside it.

Without `--ai`, nothing leaves your machine.

## How it works

```
auth.log -> parse (regex) -> events -> detect (5 rules) -> findings -> report (+ optional AI summary)
```

Everything lives in one readable file, `logsentry.py`: a parser, a rule engine with a sliding-window counter, a response playbook per rule, and a reporter.

## Limitations (honest ones)

- Parses classic syslog timestamps only (no year in the line, so pass `--year`). journald/ISO formats are not yet supported.
- SSH only. No sudo, web, or Windows logs yet.
- Rules are heuristic. A NAT gateway with many users behind one IP can look like a spray; always verify before blocking.

## Roadmap

- ISO-8601 and journald input
- GeoIP and threat-intel enrichment (AbuseIPDB)
- Sigma rule export
- Detection for sudo abuse and new SSH keys

## Tests

12 unit tests cover the parser, every rule (including the sliding window boundary), and the AI payload privacy guarantee.

## License

MIT, see [LICENSE](LICENSE). Sample data is fully synthetic and uses RFC 5737 documentation IP ranges.
