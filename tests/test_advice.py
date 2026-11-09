import tempfile
import unittest
from pathlib import Path

from vpnct import advice
from vpnct.engine import MinutePoint
from vpnct.monitor import MonitorMinute
from vpnct.report import summarise
from tests.test_report import write_session

HOST = "203.0.113.10"


def mp(minute, retrans, vpn=False, data=1000, cover=60.0, local_port=1):
    path = "vpn:wg0 [X]" if vpn else "direct:eth0"
    return MinutePoint(minute, "GAME.exe", 13328, HOST, local_port, path, vpn, cover, data, 0, retrans)


def mon(minute, lost, sent=60):
    return MonitorMinute(minute, HOST, "eth0", 60.0, sent, sent - lost, 20.0, 30.0)


class LiveHintTests(unittest.TestCase):
    def test_direct_losing_says_switch(self):
        h = advice.live_hint([mp(0, 0), mp(60, 20), mp(120, 30)], [], False, "unconfirmed")
        self.assertEqual(h.level, "switch")

    def test_one_bad_minute_is_not_losing(self):
        h = advice.live_hint([mp(0, 0), mp(60, 20), mp(120, 0)], [], False, "unconfirmed")
        self.assertEqual(h.level, "ok")

    def test_too_few_minutes_is_unknown(self):
        h = advice.live_hint([mp(0, 0)], [], False, "unconfirmed")
        self.assertEqual(h.level, "unknown")

    def test_split_capture_rows_add_up_to_a_full_minute(self):
        # one connection's capture restarted mid-minute: 30 s + 30 s
        rows = [mp(m, 0, cover=30) for m in (0, 60, 120)] + [mp(m, 20, cover=30) for m in (0, 60, 120)]
        h = advice.live_hint(rows, [], False, "unconfirmed")
        self.assertEqual(h.level, "switch")

    def test_on_vpn_direct_losing_says_stay(self):
        h = advice.live_hint([mp(m, 0, vpn=True) for m in (0, 60, 120)],
                             [mon(0, 0), mon(60, 10), mon(120, 12)], True, "unconfirmed")
        self.assertEqual(h.level, "stay")

    def test_on_vpn_direct_clean_long_enough_says_return_with_caveat(self):
        watch = [mon(60 * i, 0) for i in range(advice.CLEAN_MINUTES)]
        h = advice.live_hint([mp(m, 0, vpn=True) for m in (0, 60, 120)], watch, True, "unconfirmed")
        self.assertEqual(h.level, "return")
        self.assertIn("not yet confirmed", h.text)

    def test_on_vpn_not_clean_long_enough_is_ok(self):
        watch = [mon(0, 10)] + [mon(60 * i, 0) for i in range(1, advice.CLEAN_MINUTES)]
        h = advice.live_hint([mp(m, 0, vpn=True) for m in (0, 60, 120)], watch, True, "confirmed")
        self.assertEqual(h.level, "ok")

    def test_vpn_server_losing_while_direct_clean_says_return(self):
        h = advice.live_hint([mp(m, 30, vpn=True) for m in (0, 60, 120)],
                             [mon(m, 0) for m in (0, 60, 120)], True, "confirmed")
        self.assertEqual(h.level, "return")
        self.assertNotIn("not yet confirmed", h.text)


def loss(minute, retrans, session_path="direct:eth0", interface="eth0", local="192.0.2.20:1"):
    return {"minute": minute, "interface": interface, "path": session_path, "program": "GAME.exe",
            "local": local, "remote": f"{HOST}:13328", "covered_s": 60, "data_pkts": 1000,
            "lost_gaps": 0, "retrans": retrans}


class RecommendTests(unittest.TestCase):
    def summary(self, sessions: list[list[dict]]):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = []
            for i, rows in enumerate(sessions):
                d = Path(tmp) / f"s{i}"
                write_session(d, {"losses.csv": rows})
                dirs.append(d)
            return summarise(dirs)

    def direct_sessions(self, bad_every: int | None, n_sessions=3, minutes=50, vpn_bad=0):
        out = []
        for s in range(n_sessions):
            rows = [loss(f"d{m}", 20 if bad_every and m % bad_every == 0 else 0) for m in range(minutes)]
            rows += [loss(f"v{m}", 20 if m < vpn_bad else 0, "vpn:wg0 [X]", "wg0") for m in range(20)]
            out.append(rows)
        return out

    def verdict(self, sessions):
        return advice.recommend(self.summary(sessions), ("GAME.exe", "13328")).verdict

    def test_not_enough_data(self):
        self.assertEqual(self.verdict(self.direct_sessions(None, n_sessions=1)), "not-enough-data")

    def test_stay_direct_when_bad_minutes_are_rare(self):
        self.assertEqual(self.verdict(self.direct_sessions(None)), "stay-direct")

    def test_vpn_always_when_direct_often_bad(self):
        self.assertEqual(self.verdict(self.direct_sessions(5)), "vpn-always")

    def test_vpn_when_losing_in_between(self):
        self.assertEqual(self.verdict(self.direct_sessions(20)), "vpn-when-losing")

    def test_vpn_no_help_when_vpn_as_bad(self):
        self.assertEqual(self.verdict(self.direct_sessions(5, vpn_bad=10)), "vpn-no-help")

    def test_one_long_session_is_not_enough(self):
        self.assertEqual(self.verdict(self.direct_sessions(None, n_sessions=1, minutes=200)),
                         "not-enough-data")

    def test_unconfirmed_watch_does_not_move_the_verdict(self):
        # clean direct traffic, but the ping watch says the direct path was bad
        # in every VPN minute; ping is unconfirmed, so that must not count
        with tempfile.TemporaryDirectory() as tmp:
            dirs = []
            for i, rows in enumerate(self.direct_sessions(None)):
                d = Path(tmp) / f"s{i}"
                monitor = [{"minute": f"v{m}", "target": HOST, "interface": "eth0",
                            "path": "direct:eth0", "covered_s": 60, "sent": 60, "received": 50,
                            "loss_pct": 16.7, "rtt_p50": 20, "rtt_max": 30} for m in range(20)]
                write_session(d, {"losses.csv": rows, "monitor.csv": monitor})
                dirs.append(d)
            s = summarise(dirs)
        self.assertEqual(s["calibration"].status, "unconfirmed")
        rec = advice.recommend(s, ("GAME.exe", "13328"))
        self.assertEqual(rec.verdict, "stay-direct")
        self.assertTrue(any("not counted" in d for d in rec.details))

    def test_side_services_are_listed_not_judged(self):
        s = self.summary(self.direct_sessions(None))
        main, rest = advice.main_services(s)
        self.assertEqual(main, [("GAME.exe", "13328")])
        self.assertEqual(rest, [])


if __name__ == "__main__":
    unittest.main()
