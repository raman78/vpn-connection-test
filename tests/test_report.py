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
