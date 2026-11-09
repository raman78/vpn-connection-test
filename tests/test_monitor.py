import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from vpnct.monitor import Monitor, ping_command
from vpnct.report import CAL_MIN_BAD, summarise
from tests.test_report import write_session


def reply(t, seq, rtt):
    return f"[{t:.6f}] 64 bytes from 192.0.2.1: icmp_seq={seq} ttl=60 time={rtt} ms\n"


def miss(t, seq):
    return f"[{t:.6f}] no answer yet for icmp_seq={seq}\n"


class MonitorTests(unittest.TestCase):
    def test_minute_counts(self):
        m = Monitor("192.0.2.1", "eth0", started=1200.0)
        m.feed(reply(1201.02, 1, 20.0))
        m.feed(miss(1203.0, 2))                  # sent 1202
        m.feed(reply(1203.02, 3, 22.0))
        (row,) = m.take_rows(now=1270.0)
        self.assertEqual((row.minute, row.sent, row.received, row.loss_pct, row.rtt_p50),
                         (1200, 3, 2, 33.3, 21.0))

    def test_late_reply_turns_miss_back(self):
        m = Monitor("192.0.2.1", "eth0", started=1200.0)
        m.feed(miss(1202.0, 1))
        m.feed(reply(1202.3, 1, 1300.0))         # arrived after ping gave up on it
        (row,) = m.take_rows(now=1270.0)
        self.assertEqual((row.sent, row.received), (1, 1))

    def test_ping_belongs_to_the_minute_it_was_sent_in(self):
        m = Monitor("192.0.2.1", "eth0", started=1190.0)
        m.feed(miss(1200.5, 7))                  # sent 1199.5
        m.feed(reply(1200.01, 8, 30.0))          # sent 1199.98
        rows = m.take_rows(now=1270.0)
        self.assertEqual([(r.minute, r.sent) for r in rows], [(1140, 2), (1200, 0)])

    def test_silent_minute_is_a_row_with_nothing_sent(self):
        m = Monitor("192.0.2.1", "eth0", started=1200.0)
        (row,) = m.take_rows(now=1270.0)
        self.assertEqual((row.sent, row.loss_pct, row.covered_s), (0, None, 60.0))


@unittest.skipUnless(shutil.which("ping"), "ping not installed")
class RealPingTests(unittest.TestCase):
    def test_parser_matches_real_ping_output(self):
        proc = subprocess.Popen(ping_command("127.0.0.1", "lo"), stdout=subprocess.PIPE, text=True)
        m = Monitor("127.0.0.1", "lo", started=time.time())
        start = time.time()
        for line in proc.stdout:
            m.feed(line)
            if time.time() - start > 2.5:
                break
        proc.terminate()
        proc.wait()
        proc.stdout.close()
        sent = sum(b["sent"] for b in m.buckets.values())
        got = sum(len(b["rtts"]) for b in m.buckets.values())
        self.assertGreaterEqual(sent, 3)
        self.assertEqual(sent, got)


def monitor_row(minute, loss_pct, sent=60):
    received = round(sent * (1 - loss_pct / 100))
    return {"minute": minute, "target": "203.0.113.10", "interface": "eth0", "path": "direct:eth0",
            "covered_s": 60, "sent": sent, "received": received, "loss_pct": loss_pct,
            "rtt_p50": 20, "rtt_max": 30}


def loss_row(minute, retrans, path="direct:eth0", interface="eth0", data=1000):
    return {"minute": minute, "interface": interface, "path": path, "program": "GAME.exe",
            "local": "192.0.2.20:1", "remote": "203.0.113.10:13328", "covered_s": 60,
            "data_pkts": data, "lost_gaps": 0, "retrans": retrans}


class CalibrationTests(unittest.TestCase):
    def run_summary(self, monitor, losses):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s"
            write_session(d, {"monitor.csv": monitor, "losses.csv": losses})
            return summarise([d])

    def test_unconfirmed_until_enough_bad_minutes(self):
        s = self.run_summary([monitor_row(f"m{i}", 0) for i in range(30)],
                             [loss_row(f"m{i}", 0) for i in range(30)])
        c = s["calibration"]
        self.assertEqual((c.pairs, c.tcp_bad, c.status), (30, 0, "unconfirmed"))

    def test_confirmed_when_ping_follows_tcp(self):
        n = CAL_MIN_BAD + 1
        s = self.run_summary([monitor_row(f"b{i}", 15) for i in range(n)] + [monitor_row("g", 0)],
                             [loss_row(f"b{i}", 130) for i in range(n)] + [loss_row("g", 0)])
        self.assertEqual(s["calibration"].status, "confirmed")

    def test_refuted_when_ping_misses_tcp_loss(self):
        n = CAL_MIN_BAD + 1
        s = self.run_summary([monitor_row(f"b{i}", 0) for i in range(n)],
                             [loss_row(f"b{i}", 130) for i in range(n)])
        self.assertEqual(s["calibration"].status, "refuted")

    def test_vpn_minutes_are_not_paired_but_counted_for_the_monitor(self):
        s = self.run_summary([monitor_row("v", 10)],
                             [loss_row("v", 0, path="vpn:wg0 [X]", interface="wg0")])
        self.assertEqual(s["calibration"].pairs, 0)
        (mg,) = s["monitor"].values()
        self.assertEqual((mg.minutes, mg.bad, mg.minutes_on_vpn, mg.bad_on_vpn), (1, 1, 1, 1))

    def test_minute_with_too_few_pings_is_counted_as_short(self):
        s = self.run_summary([monitor_row("x", 0, sent=10)], [])
        (mg,) = s["monitor"].values()
        self.assertEqual((mg.minutes, mg.short), (0, 1))


if __name__ == "__main__":
    unittest.main()
