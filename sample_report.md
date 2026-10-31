# LogSentry triage report

- Log lines read: 98
- SSH auth events parsed: 98
- Unique source IPs: 17
- Findings: 6

## Findings (highest severity first)

### 1. [CRITICAL] Successful login after 48 failures
- Source IP: `203.0.113.45`
- Window: 2026-10-30 02:14:00 to 2026-10-30 02:17:20
- ATT&CK: T1078 Valid Accounts
- Accounts: admin
- Why it matters: Account 'admin' logged in from an IP that failed 48 times in the previous hour. Possible successful brute force.
- Next steps:
  - Treat as a possible account compromise and escalate to Tier 2.
  - Disable or reset the affected account's credentials.
  - Review the session: commands run, new users, cron jobs, SSH keys.
  - Block the source IP and hunt for other logins from it.

### 2. [HIGH] 48 failed SSH logins within 5 min
- Source IP: `203.0.113.45`
- Window: 2026-10-30 02:14:00 to 2026-10-30 02:17:08
- ATT&CK: T1110.001 Password Guessing
- Accounts: admin, root, ubuntu
- Why it matters: 48 failed logins from one IP inside a 5-minute window (threshold 5). Typical of automated password guessing.
- Next steps:
  - Check the source IP against threat intel (AbuseIPDB, VirusTotal).
  - Block or rate-limit the IP (firewall rule or fail2ban).
  - Confirm there was no successful login from this IP.
  - Prefer key-based auth and disable SSH password login if possible.

### 3. [HIGH] Failed logins against 12 different accounts
- Source IP: `198.51.100.7`
- Window: 2026-10-30 13:00:01 to 2026-10-30 13:33:01
- ATT&CK: T1110.003 Password Spraying
- Accounts: akhan, dev1, dev2, dpatel, finance, guest, hr, jsmith
- Why it matters: One IP tried 12 distinct accounts. Spraying often stays under lockout thresholds, so per-account counts look harmless.
- Next steps:
  - Treat as targeted: one IP tried many accounts with few attempts each.
  - Check whether any of the tried accounts logged in successfully.
  - Block the IP and force a password review for the accounts involved.

### 4. [MEDIUM] 20 failed logins as root
- Source IP: `203.0.113.45`
- Window: 2026-10-30 02:14:12 to 2026-10-30 02:17:08
- ATT&CK: T1110.001 Password Guessing
- Accounts: root
- Why it matters: Direct root login attempts. Root SSH login should be disabled.
- Next steps:
  - Verify PermitRootLogin is set to no in sshd_config.
  - Block the source IP and review other attempts from it.

### 5. [MEDIUM] 12 non-existent usernames probed
- Source IP: `198.51.100.7`
- Window: 2026-10-30 13:00:00 to 2026-10-30 13:33:00
- ATT&CK: T1595 Active Scanning (approximate)
- Accounts: akhan, dev1, dev2, dpatel, finance, guest, hr, jsmith
- Why it matters: Attempts used usernames that do not exist on the host: reconnaissance for valid accounts.
- Next steps:
  - Low risk alone, but it is reconnaissance: expect guessing to follow.
  - Watch this IP for later failed or successful logins.
  - Consider blocking the IP if it keeps returning.

### 6. [LOW] 6 non-existent usernames probed
- Source IP: `192.0.2.99`
- Window: 2026-10-30 18:30:00 to 2026-10-30 18:31:40
- ATT&CK: T1595 Active Scanning (approximate)
- Accounts: ftp, git, oracle, pi, postgres, test
- Why it matters: Attempts used usernames that do not exist on the host: reconnaissance for valid accounts.
- Next steps:
  - Low risk alone, but it is reconnaissance: expect guessing to follow.
  - Watch this IP for later failed or successful logins.
  - Consider blocking the IP if it keeps returning.
