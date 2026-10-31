"""Generate a fully synthetic SSH auth log for demos (uses RFC 5737 documentation IPs)."""
import random
from datetime import datetime, timedelta

random.seed(7)
HOST = "web01"
rows = []


def add(t, msg):
    stamp = f"{t:%b} {t.day:>2} {t:%H:%M:%S}"
    rows.append((t, f"{stamp} {HOST} sshd[{random.randint(1000, 60000)}]: {msg}"))


def port():
    return random.randint(20000, 65000)


# 1) Normal activity (should NOT be flagged)
day = datetime(2026, 10, 30, 8, 0, 0)
for _ in range(18):
    t = day + timedelta(minutes=random.randint(0, 600))
    add(t, f"Accepted publickey for {random.choice(['alice', 'bob', 'carol'])} "
           f"from 10.0.0.{random.randint(10, 40)} port {port()} ssh2")
add(day + timedelta(hours=3), f"Failed password for alice from 10.0.0.12 port {port()} ssh2")  # one typo

# 2) Brute force that ends in a successful login (the scary one)
base = datetime(2026, 10, 30, 2, 14, 0)
attacker = "203.0.113.45"
for i in range(48):
    t = base + timedelta(seconds=i * 4)
    user = random.choice(["root", "root", "admin", "ubuntu"])
    if user in ("root", "admin"):
        add(t, f"Failed password for {user} from {attacker} port {port()} ssh2")
    else:
        add(t, f"Failed password for invalid user {user} from {attacker} port {port()} ssh2")
add(base + timedelta(seconds=200), f"Accepted password for admin from {attacker} port {port()} ssh2")

# 3) Slow password spraying (stays under per-account lockouts)
sprayer = "198.51.100.7"
names = ["jsmith", "mjones", "akhan", "lee", "dpatel", "svc_backup", "hr", "finance", "dev1", "dev2", "test", "guest"]
t0 = datetime(2026, 10, 30, 13, 0, 0)
for k, name in enumerate(names):
    t = t0 + timedelta(minutes=3 * k)
    add(t, f"Invalid user {name} from {sprayer} port {port()}")
    add(t + timedelta(seconds=1), f"Failed password for invalid user {name} from {sprayer} port {port()} ssh2")

# 4) Username enumeration only
for k, name in enumerate(["oracle", "postgres", "ftp", "git", "pi", "test"]):
    add(datetime(2026, 10, 30, 18, 30, 0) + timedelta(seconds=20 * k),
        f"Invalid user {name} from 192.0.2.99 port {port()}")

rows.sort(key=lambda r: r[0])
with open("sample_auth.log", "w", encoding="utf-8") as fh:
    fh.write("\n".join(r[1] for r in rows) + "\n")
print(f"wrote sample_auth.log ({len(rows)} lines)")
