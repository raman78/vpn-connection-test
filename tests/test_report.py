import csv
import tempfile
import unittest
from pathlib import Path

from vpnct.report import format_report, summarise
from vpnct.session import FILES


def write_session(d: Path, rows: dict[str, list[dict]]) -> None:
    d.mkdir()
    for name, fields in FILES.items():
        with open(d / name, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for r in rows.get(name, []):
                w.writerow(r)
    (d / "events.log").write_text("2026-01-01T10:00:30 mark            it stutters now\n")


def sample(t, local, rtt, data=10):
    return {"time": t, "program": "GAME.exe", "local": local, "remote": "203.0.113.10:13328",
            "path": "direct:eth0", "rtt_ms": rtt, "rttvar_ms": 1, "minrtt_ms": 1,
            "d_bytes_in": 100, "d_data_segs_in": data, "d_retrans": 0, "d_ooopack": 0}


def loss(minute, local, covered, data, retrans):
    return {"minute": minute, "interface": "eth0", "path": "direct:eth0", "program": "GAME.exe",
            "local": local, "remote": "203.0.113.10:13328", "covered_s": covered,
            "data_pkts": data, "lost_gaps": 1 if retrans else 0, "retrans": retrans}


class ReportTests(unittest.TestCase):
    def test_parallel_connections_count_wall_time_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s1"
            write_session(d, {
                "samples.csv": [sample("t1", "192.0.2.20:1", 20), sample("t1", "192.0.2.20:2", 30),
                                sample("t2", "192.0.2.20:1", 22), sample("t2", "192.0.2.20:2", 0, data=0)],
                "losses.csv": [loss("m1", "192.0.2.20:1", 60, 100, 5),
                               loss("m1", "192.0.2.20:2", 60, 100, 5)],
            })
            s = summarise([d])
        (g,) = s["groups"].values()
        self.assertEqual(g.seconds, 2)                 # not 4
        self.assertEqual(g.covered_s, 60)              # not 120
        self.assertEqual(sorted(g.rtts), [20, 22, 30]) # the second without data is left out
        self.assertEqual((g.data_pkts, g.retrans), (200, 10))
        self.assertEqual(s["marks"], ["2026-01-01T10:00:30 mark            it stutters now"])

    def test_target_that_never_answers_is_not_shown_as_loss(self):
        probe = {"time": "t", "target": "198.51.100.7", "role": "connection", "bound": "no",
                 "interface": "eth0", "path": "direct:eth0", "sent": 20, "received": 0,
                 "loss_pct": 100.0, "rtt_min": "", "rtt_avg": "", "rtt_max": "", "error": ""}
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s1"
            write_session(d, {"probes.csv": [probe, probe]})
            text = format_report(summarise([d]))
        line = next(x for x in text.splitlines() if x.startswith("198.51.100.7"))
        self.assertIn("does not answer ping", line)
        self.assertNotIn("100.0", line)


if __name__ == "__main__":
    unittest.main()


def minute_samples(minute, rtts, path="direct:eth0", local="192.0.2.20:1", remote="203.0.113.10:13328"):
    """One sample per second of minute `minute` (0-59) with the given RTTs."""
    return [{"time": f"2026-01-01T10:{minute:02d}:{i:02d}.000+01:00", "program": "GAME.exe",
             "local": local, "remote": remote, "path": path, "rtt_ms": r, "rttvar_ms": 1,
             "minrtt_ms": 1, "d_bytes_in": 100, "d_data_segs_in": 10, "d_retrans": 0, "d_ooopack": 0}
            for i, r in enumerate(rtts)]


class JumpyMinuteTests(unittest.TestCase):
    def test_spiky_rules(self):
        from vpnct.report import spiky
        self.assertIsNone(spiky([35.0] * 29))                     # too few seconds
        self.assertFalse(spiky([35.0] * 60))
        self.assertTrue(spiky([35.0] * 54 + [50.0] * 6))          # p95 15 ms over the median
        self.assertTrue(spiky([35.0] * 59 + [70.0]))              # one second 35 ms over
        self.assertFalse(spiky([35.0] * 59 + [60.0]))             # 25 ms once: not yet
        # a steady level far above the minimum is not a jump (delayed ACKs)
        self.assertFalse(spiky([48.0] * 60))

    def summary(self, samples):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s"
            write_session(d, {"samples.csv": samples})
            return summarise([d])

    def test_counted_per_connection(self):
        # two calm connections at different levels in one minute (two game
        # servers): not a jump, though pooled they would spread 45 ms
        rows = minute_samples(0, [35.0] * 60) + minute_samples(0, [80.0] * 60, local="192.0.2.20:2")
        rows += minute_samples(1, [35.0] * 59 + [80.0])
        rows += minute_samples(2, [35.0] * 10)                    # too short to judge
        g = self.summary(rows)["groups"][("GAME.exe", "13328", "direct:eth0")]
        self.assertEqual(g.ping_minutes, 2)
        self.assertEqual(g.spiky_minutes, 1)


class FamilyTests(unittest.TestCase):
    def test_path_family(self):
        from vpnct.report import path_family
        self.assertEqual(path_family("vpn:proton0 [ProtonVPN NL-FREE#244]"), "vpn:proton0 [ProtonVPN NL-FREE]")
        self.assertEqual(path_family("vpn:wg0 [Office]"), "vpn:wg0 [Office]")
        self.assertEqual(path_family("vpn:wg0"), "vpn:wg0")
        self.assertEqual(path_family("direct:eth0 [Wired #2]"), "direct:eth0 [Wired #2]")
        self.assertEqual(path_family("gone(10.2.0.2)"), "gone(10.2.0.2)")

    def test_by_family_merges_minutes(self):
        from vpnct.report import by_family, by_service
        a, b = "vpn:wg0 [VPN NL#1]", "vpn:wg0 [VPN NL#2]"
        losses = [{"minute": "m0", "interface": "wg0", "path": a, "program": "GAME.exe",
                   "local": "192.0.2.20:1", "remote": "203.0.113.10:13328", "covered_s": 30,
                   "data_pkts": 100, "lost_gaps": 0, "retrans": 1},
                  {"minute": "m0", "interface": "wg0", "path": b, "program": "GAME.exe",
                   "local": "192.0.2.20:2", "remote": "203.0.113.10:13328", "covered_s": 30,
                   "data_pkts": 100, "lost_gaps": 0, "retrans": 0}]
        samples = minute_samples(0, [35.0] * 59 + [80.0], path=a) + minute_samples(1, [35.0] * 60, path=b)
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s"
            write_session(d, {"losses.csv": losses, "samples.csv": samples})
            s = summarise([d])
        fam = by_family(by_service(s["groups"])[("GAME.exe", "13328")])
        self.assertEqual(set(fam), {"vpn:wg0 [VPN NL]"})
        g = fam["vpn:wg0 [VPN NL]"]
        self.assertEqual(g.members, {a, b})
        self.assertEqual((g.data_pkts, g.retrans), (200, 1))
        self.assertEqual(len(g.minute_tcp), 1)                     # one minute, both servers in it
        self.assertEqual(g.minute_tcp[("s", "m0")].data, 200)      # merged, not one overwriting the other
        self.assertEqual((g.ping_minutes, g.spiky_minutes), (2, 1))
        # the per-server groups are left as they were
        self.assertEqual(s["groups"][("GAME.exe", "13328", a)].data_pkts, 100)


class ProbeJumpTests(unittest.TestCase):
    def test_jumpy_rounds_counted(self):
        def probe(lo, hi):
            return {"time": "t", "target": "10.2.0.1", "role": "vpn-gateway(wg0)", "bound": "yes",
                    "interface": "wg0", "path": "vpn:wg0 [X]", "sent": 20, "received": 20,
                    "loss_pct": 0, "rtt_min": lo, "rtt_max": hi, "rtt_avg": lo, "error": ""}
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s"
            write_session(d, {"probes.csv": [probe(34, 36), probe(34, 91), probe(34, 53.9)]})
            pg = summarise([d])["probes"][("10.2.0.1", "vpn-gateway(wg0)", "vpn:wg0 [X]", "yes")]
        self.assertEqual((pg.timed, pg.jumpy), (3, 1))
