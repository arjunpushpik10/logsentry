import json
import unittest

import logsentry as ls


def line(minute, sec, msg, host="web01"):
    return f"Oct 30 02:{minute:02d}:{sec:02d} {host} sshd[1234]: {msg}"


def events_from(lines):
    evs = [ls.parse_line(l, 2026) for l in lines]
    return [e for e in evs if e]


def fails(n, ip="203.0.113.5", user="root", minute=14, gap=1, step_minutes=0):
    out = []
    for i in range(n):
        m = minute + i * step_minutes
        out.append(line(m, (i * gap) % 60, f"Failed password for {user} from {ip} port 4000 ssh2"))
    return out


class ParserTests(unittest.TestCase):
    def test_failed_invalid_user(self):
        e = ls.parse_line(line(14, 1, "Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2"), 2026)
        self.assertEqual((e.kind, e.user, e.ip), ("failed", "admin", "203.0.113.5"))

    def test_accepted(self):
        e = ls.parse_line(line(14, 1, "Accepted publickey for alice from 10.0.0.5 port 22 ssh2"), 2026)
        self.assertEqual((e.kind, e.user), ("accepted", "alice"))

    def test_invalid_user_line(self):
        e = ls.parse_line(line(14, 1, "Invalid user oracle from 192.0.2.9 port 5555"), 2026)
        self.assertEqual((e.kind, e.user), ("invalid_user", "oracle"))

    def test_ignores_other_processes_and_garbage(self):
        self.assertIsNone(ls.parse_line("Oct 30 02:14:01 web01 CRON[99]: session opened", 2026))
        self.assertIsNone(ls.parse_line("complete nonsense", 2026))
        self.assertIsNone(ls.parse_line("", 2026))


class DetectTests(unittest.TestCase):
    def rules(self, lines, **kw):
        return [f.rule for f in ls.detect(events_from(lines), **kw)]

    def test_brute_force_triggers(self):
        self.assertIn("brute_force", self.rules(fails(6, user="bob")))

    def test_below_threshold_is_quiet(self):
        self.assertNotIn("brute_force", self.rules(fails(4, user="bob")))

    def test_window_is_respected(self):
        # 6 failures, 3 minutes apart: never 5 inside one 5-minute window
        self.assertNotIn("brute_force", self.rules(fails(6, user="bob", step_minutes=3)))

    def test_password_spraying(self):
        lines = []
        for i, u in enumerate(["a1", "b2", "c3", "d4", "e5", "f6"]):
            lines += fails(1, user=u, minute=10 + i * 8)
        rules = self.rules(lines)
        self.assertIn("password_spraying", rules)
        self.assertNotIn("brute_force", rules)

    def test_success_after_failures_is_critical_and_first(self):
        lines = fails(5, user="admin") + [
            line(15, 0, "Accepted password for admin from 203.0.113.5 port 4001 ssh2")
        ]
        findings = ls.detect(events_from(lines))
        self.assertEqual(findings[0].rule, "success_after_failures")
        self.assertEqual(findings[0].severity, "critical")

    def test_normal_login_is_not_flagged(self):
        lines = [line(14, 0, "Accepted publickey for alice from 10.0.0.5 port 22 ssh2")]
        self.assertEqual(ls.detect(events_from(lines)), [])

    def test_root_targeted(self):
        self.assertIn("root_targeted", self.rules(fails(3, user="root", step_minutes=10)))


class PrivacyTests(unittest.TestCase):
    def test_ai_payload_pseudonymizes_real_usernames(self):
        lines = fails(5, user="jsmith") + [
            line(15, 0, "Accepted password for jsmith from 203.0.113.5 port 4001 ssh2")
        ]
        payload = json.dumps(ls.build_ai_payload(ls.detect(events_from(lines))))
        self.assertNotIn("jsmith", payload)
        self.assertIn("user_1", payload)


if __name__ == "__main__":
    unittest.main()
