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

    def watch_summary(self, route_verdict=None, refute=False, route_delay_min=1.5):
        """Three sessions: 50 clean direct minutes each, then 20 VPN minutes in
        which the direct-path ping lost 17 % every minute."""
        from datetime import datetime, timezone
        iso = lambda m: datetime.fromtimestamp(1_800_000_000 + 60 * m, timezone.utc).isoformat()
        with tempfile.TemporaryDirectory() as tmp:
            dirs = []
            for i in range(3):
                d = Path(tmp) / f"s{i}"
                rows = [loss(iso(m), 0) for m in range(50)]
                rows += [loss(iso(100 + m), 0, "vpn:wg0 [X]", "wg0") for m in range(20)]
                monitor = [{"minute": iso(100 + m), "target": HOST, "interface": "eth0",
                            "path": "direct:eth0", "covered_s": 60, "sent": 60, "received": 50,
                            "loss_pct": 16.7, "rtt_p50": 20, "rtt_max": 30} for m in range(20)]
                if refute:      # direct minutes where TCP lost but ping did not: ping misses loss
                    rows += [loss(iso(200 + m), 20) for m in range(6)]
                    monitor += [{"minute": iso(200 + m), "target": HOST, "interface": "eth0",
                                 "path": "direct:eth0", "covered_s": 60, "sent": 60, "received": 60,
                                 "loss_pct": 0.0, "rtt_p50": 20, "rtt_max": 30} for m in range(6)]
                routes = ([{"time": iso(100 + m + route_delay_min), "target": HOST, "interface": "eth0",
                            "path": "direct:eth0", "trigger": "watch-loss", "verdict": route_verdict,
                            "start_hop": "", "start_address": "", "target_loss_pct": 0, "hops": 5,
                            "text": ""} for m in range(20)] if route_verdict else [])
                write_session(d, {"losses.csv": rows, "monitor.csv": monitor, "routes.csv": routes})
                dirs.append(d)
            return summarise(dirs)

    def test_unconfirmed_watch_counts_provisionally(self):
        s = self.watch_summary()
        self.assertEqual(s["calibration"].status, "unconfirmed")
        rec = advice.recommend(s, ("GAME.exe", "13328"))
        self.assertEqual(rec.verdict, "vpn-always")
        self.assertTrue(rec.provisional)
        self.assertTrue(rec.headline.startswith(advice.PROVISIONAL_PREFIX))

    def test_minutes_a_trace_dismissed_do_not_count(self):
        rec = advice.recommend(self.watch_summary("hop-limit"), ("GAME.exe", "13328"))
        self.assertEqual(rec.verdict, "stay-direct")
        self.assertTrue(any("60 dismissed" in d for d in rec.details))

    def test_a_trace_long_after_does_not_judge_the_minute(self):
        rec = advice.recommend(self.watch_summary("hop-limit", route_delay_min=30), ("GAME.exe", "13328"))
        self.assertEqual(rec.verdict, "vpn-always")
        self.assertTrue(any("0 dismissed" in d for d in rec.details))

    def test_minutes_a_trace_confirmed_count(self):
        rec = advice.recommend(self.watch_summary("real"), ("GAME.exe", "13328"))
        self.assertEqual(rec.verdict, "vpn-always")
        self.assertTrue(any("60 confirmed" in d for d in rec.details))

    def test_refuted_ping_is_not_counted(self):
        s = self.watch_summary(refute=True)
        self.assertEqual(s["calibration"].status, "refuted")
        rec = advice.recommend(s, ("GAME.exe", "13328"))
        self.assertFalse(rec.provisional)
        self.assertTrue(any("not counted" in d for d in rec.details))

    def test_side_services_are_listed_not_judged(self):
        s = self.summary(self.direct_sessions(None))
        main, rest = advice.main_services(s)
        self.assertEqual(main, [("GAME.exe", "13328")])
        self.assertEqual(rest, [])


if __name__ == "__main__":
    unittest.main()


class PathCardTests(unittest.TestCase):
    def cards(self, sessions):
        s = RecommendTests().summary(sessions)
        return {c.title: c for c in advice.path_cards(
            __import__("vpnct.report", fromlist=["by_service"]).by_service(s["groups"])[("GAME.exe", "13328")])}

    def test_titles_and_stability(self):
        rows = [loss(f"d{m}", 20 if m < 5 else 0) for m in range(50)]
        rows += [loss(f"v{m}", 0, "vpn:wg0 [VPN NL#1]", "wg0") for m in range(20)]
        c = self.cards([rows])
        self.assertEqual(set(c), {"Direct", "VPN · VPN NL"})      # server family, number dropped
        self.assertAlmostEqual(c["Direct"].stability_pct, 90.0)
        self.assertEqual(c["Direct"].stability_level, "poor")
        self.assertEqual(c["VPN · VPN NL"].stability_pct, 100.0)
        self.assertTrue(c["VPN · VPN NL"].best)
        self.assertEqual(c["VPN · VPN NL"].best_reason, "most stable")
        self.assertFalse(c["Direct"].best)

    def test_no_best_with_only_one_comparable_path(self):
        rows = [loss(f"d{m}", 0) for m in range(50)]
        rows += [loss(f"v{m}", 0, "vpn:wg0 [X]", "wg0") for m in range(5)]   # too short
        c = self.cards([rows])
        self.assertFalse(any(x.best for x in c.values()))
        self.assertFalse(c["VPN · X"].enough)

    def test_gone_paths_get_no_card(self):
        rows = [loss(f"d{m}", 0) for m in range(20)]
        rows += [loss("g", 0, "gone(10.99.0.2)", "?")]
        from vpnct.report import by_service
        s = RecommendTests().summary([rows])
        cards = advice.path_cards(by_service(s["groups"])[("GAME.exe", "13328")])
        self.assertEqual([c.path for c in cards], ["direct:eth0"])



def sample_row(t, path, rtt, local="192.0.2.20:1"):
    return {"time": t, "program": "GAME.exe", "local": local, "remote": f"{HOST}:13328",
            "path": path, "rtt_ms": rtt, "rttvar_ms": 1, "minrtt_ms": 1, "d_bytes_in": 100,
            "d_data_segs_in": 10, "d_retrans": 0, "d_ooopack": 0}


class BestPathTests(unittest.TestCase):
    def cards(self, losses, samples):
        from vpnct.report import by_service
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s"
            write_session(d, {"losses.csv": losses, "samples.csv": samples})
            s = summarise([d])
        return {c.title: c for c in advice.path_cards(by_service(s["groups"])[("GAME.exe", "13328")])}

    def test_equal_stability_lower_ping_wins_over_tiny_loss(self):
        vpn = "vpn:wg0 [X]"
        losses = [loss(f"d{m}", 1) for m in range(20)]                    # 0.1 %: no bad minute
        losses += [loss(f"v{m}", 0, vpn, "wg0") for m in range(20)]
        samples = [sample_row(f"d{i}", "direct:eth0", 32) for i in range(30)]
        samples += [sample_row(f"v{i}", vpn, 43) for i in range(30)]
        c = self.cards(losses, samples)
        self.assertTrue(c["Direct"].best)
        self.assertEqual(c["Direct"].best_reason, "as stable, lowest ping")
        self.assertFalse(c["VPN · X"].best)

    def test_more_stable_beats_lower_ping(self):
        vpn = "vpn:wg0 [X]"
        losses = [loss(f"d{m}", 20 if m < 3 else 0) for m in range(20)]  # 3 bad minutes
        losses += [loss(f"v{m}", 0, vpn, "wg0") for m in range(20)]
        samples = [sample_row(f"d{i}", "direct:eth0", 32) for i in range(30)]
        samples += [sample_row(f"v{i}", vpn, 43) for i in range(30)]
        c = self.cards(losses, samples)
        self.assertTrue(c["VPN · X"].best)
        self.assertEqual(c["VPN · X"].best_reason, "most stable")


class RecentViewTests(unittest.TestCase):
    NOW = 100_000.0

    def route(self, kind, ago=30):
        from vpnct.engine import RouteResult
        from vpnct.probes import RouteVerdict
        text = {"real": "loss starts at hop 9 198.51.100.9 and continues to the server (15 %)",
                "hop-limit": "route clean to the server; hop 4 198.51.100.4 only limit ping replies",
                "clean": "route clean to the server (0 % ping loss)"}[kind]
        return RouteResult(self.NOW - ago, HOST, "eth0", "direct:eth0", "watch-loss", RouteVerdict(kind, text))

    def view(self, minutes=(), monitor=(), routes=(), on_vpn=True, window=3600, **kw):
        return advice.recent_view(list(minutes), [], list(monitor), list(routes), on_vpn, window, self.NOW, **kw)

    def vpn_minutes(self, n, bad=0):
        return [mp(self.NOW - 60 * (i + 1), 20 if i < bad else 0, vpn=True) for i in range(n)]

    def watch(self, n, bad=0, start_ago=1):
        return [mon(self.NOW - 60 * (i + start_ago), 10 if i < bad else 0) for i in range(n)]

    def test_direct_losing_on_the_route_while_on_vpn(self):
        v = self.view(self.vpn_minutes(20), self.watch(20, bad=3), [self.route("real")])
        self.assertEqual(v.conclusion.level, "stay")
        self.assertIn("starts at hop 9", v.conclusion.text)

    def test_ping_loss_dismissed_by_the_route(self):
        v = self.view(self.vpn_minutes(20), self.watch(20, bad=3), [self.route("hop-limit")])
        self.assertEqual(v.conclusion.level, "ok")
        self.assertIn("limiting ping", v.conclusion.text)

    def test_unverified_ping_loss_says_so(self):
        v = self.view(self.vpn_minutes(20), self.watch(20, bad=3))
        self.assertEqual(v.conclusion.level, "stay")
        self.assertIn("not yet confirmed", v.conclusion.text)

    def test_direct_clean_on_vpn_says_not_needed(self):
        v = self.view(self.vpn_minutes(20), self.watch(12), rtt_cost_ms=11)
        self.assertEqual(v.conclusion.level, "return")
        self.assertIn("+11 ms", v.conclusion.text)

    def test_vpn_server_itself_losing(self):
        v = self.view(self.vpn_minutes(20, bad=3), self.watch(20))
        self.assertEqual(v.conclusion.level, "return")
        self.assertIn("This VPN server lost", v.conclusion.text)

    def test_direct_traffic_losing_names_best_vpn(self):
        minutes = [mp(self.NOW - 60 * (i + 1), 20 if i < 3 else 0) for i in range(15)]
        v = self.view(minutes, on_vpn=False, best_vpn="VPN · X")
        self.assertEqual(v.conclusion.level, "switch")
        self.assertIn("VPN · X", v.conclusion.text)

    def test_window_leaves_older_minutes_out(self):
        old_bad = [mp(self.NOW - 3000 - 60 * i, 20) for i in range(3)]
        recent = [mp(self.NOW - 60 * (i + 1), 0) for i in range(10)]
        v = self.view(old_bad + recent, on_vpn=False, window=900)
        self.assertEqual(v.conclusion.level, "ok")
        v = self.view(old_bad + recent, on_vpn=False, window=3600)
        self.assertEqual(v.conclusion.level, "switch")


    def test_few_clean_watched_minutes_are_not_enough(self):
        v = self.view(self.vpn_minutes(20), self.watch(advice.RECENT_MIN_CLEAN - 1))
        self.assertEqual(v.conclusion.level, "unknown")


def sp(t, rtt, vpn=True, path=None, local_port=1):
    from vpnct.engine import SecondPoint
    path = path or ("vpn:wg0 [VPN NL#7]" if vpn else "direct:eth0")
    return SecondPoint(t, "GAME.exe", 13328, path, vpn, rtt, 10, HOST, local_port)


def seconds_of(start, jumpy, n=60, vpn=True):
    """One minute of SecondPoints from `start`; jumpy: one second 50 ms up."""
    return [sp(start + i, 85.0 if jumpy and i == 30 else 35.0, vpn) for i in range(n)]


def probe_point(t, role, jumpy):
    from vpnct.engine import ProbePoint
    return ProbePoint(t, "198.51.100.1", role, "eth0", "x", 20, 20, 34.0, 80.0 if jumpy else 36.0, "")


class JumpyAdviceTests(unittest.TestCase):
    NOW = 100_020.0      # minutes at 99_960, 99_900, ... are whole minutes

    def minute_starts(self, n):
        return [int(self.NOW // 60) * 60 - 60 * (i + 1) for i in range(n)]

    def test_hint_says_when_the_vpn_ping_jumps(self):
        starts = self.minute_starts(3)
        secs = [s for t in sorted(starts) for s in seconds_of(t, jumpy=True)]
        minutes = [mp(t, 0, vpn=True) for t in sorted(starts)]
        h = advice.live_hint(minutes, [mon(t, 0) for t in sorted(starts)], True, "unconfirmed", seconds=secs)
        self.assertIn("jumped in 3 of the last 3 minutes", h.text)
        self.assertEqual(h.level, "ok")                  # jumps alone never ask for a switch
        calm = [s for t in sorted(starts) for s in seconds_of(t, jumpy=False)]
        h = advice.live_hint(minutes, [mon(t, 0) for t in sorted(starts)], True, "unconfirmed", seconds=calm)
        self.assertNotIn("jumped", h.text)

    def test_recent_view_counts_jumps_per_family(self):
        starts = sorted(self.minute_starts(12))
        secs = []
        for i, t in enumerate(starts):              # two servers of one family, 6 jumpy minutes
            path = "vpn:wg0 [VPN NL#7]" if i < 6 else "vpn:wg0 [VPN NL#9]"
            secs += [sp(t + k, 85.0 if i % 2 == 0 and k == 30 else 35.0, path=path) for k in range(60)]
        minutes = [mp(t, 0, vpn=True) for t in starts]
        for m, i in zip(minutes, range(12)):
            m.path = "vpn:wg0 [VPN NL#7]" if i < 6 else "vpn:wg0 [VPN NL#9]"
        watch = [mon(t, 0) for t in starts]
        v = advice.recent_view(minutes, secs, watch, [], True, 3600, self.NOW)
        own = [l for l in v.lines if l.title.startswith("VPN")]
        self.assertEqual([l.title for l in own], ["VPN · VPN NL"])
        self.assertIn("ping jumped in 6 of 12", own[0].text)
        self.assertEqual(own[0].level, "fair")
        self.assertEqual(v.conclusion.level, "return")
        self.assertIn("Its ping jumped in 6 of 12 minutes", v.conclusion.text)

    def test_tunnel_line_tells_where_jumps_start(self):
        t = self.NOW - 100
        def view(inside, outside):
            pr = [probe_point(t, "vpn-gateway(wg0)", i < inside) for i in range(10)]
            pr += [probe_point(t, "vpn-endpoint(wg0)", i < outside) for i in range(10)]
            v = advice.recent_view([], [], [], [], True, 3600, self.NOW, probes=pr)
            return next(l.text for l in v.lines if l.title == "Tunnel")
        self.assertIn("only inside the tunnel", view(5, 0))
        self.assertIn("on the route to the VPN server", view(5, 4))
        self.assertIn("steady up to the VPN server", view(1, 0))
        pr = [probe_point(t, "vpn-gateway(wg0)", True) for _ in range(3)]
        v = advice.recent_view([], [], [], [], True, 3600, self.NOW, probes=pr)
        self.assertIn("not pinged outside the tunnel", next(l.text for l in v.lines if l.title == "Tunnel"))


class JumpyRankingTests(unittest.TestCase):
    def summary(self, losses, samples):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "s"
            write_session(d, {"losses.csv": losses, "samples.csv": samples})
            return summarise([d])

    @staticmethod
    def samples(path, minutes, jumpy_every, rtt, local="192.0.2.20:1"):
        from tests.test_report import minute_samples
        out = []
        for m in range(minutes):
            rtts = [rtt] * 60
            if jumpy_every and m % jumpy_every == 0:
                rtts[30] = rtt + 50
            for r in minute_samples(m, rtts, path=path, local=local):
                r["remote"] = f"{HOST}:13328"
                out.append(r)
        return out

    def test_steadier_ping_wins_among_equally_stable(self):
        from vpnct.report import by_service
        a, b = "vpn:wg0 [A]", "vpn:wg1 [B]"
        losses = [loss(f"a{m}", 0, a, "wg0") for m in range(20)] + [loss(f"b{m}", 0, b, "wg1") for m in range(20)]
        samples = self.samples(a, 20, 2, 40.0) + self.samples(b, 20, 0, 45.0)    # A cheaper but jumpy
        s = self.summary(losses, samples)
        c = {x.title: x for x in advice.path_cards(by_service(s["groups"])[("GAME.exe", "13328")])}
        self.assertEqual(c["VPN · A"].jumpy_pct, 50.0)
        self.assertEqual(c["VPN · A"].steady_pct, 50.0)
        self.assertEqual(c["VPN · A"].jumpy_level, "poor")
        self.assertTrue(c["VPN · B"].best)
        self.assertEqual(c["VPN · B"].best_reason, "as stable, steadier ping")

    def test_recommendation_ranks_families_and_names_jumps(self):
        a1, a2, b = "vpn:wg0 [A#1]", "vpn:wg0 [A#2]", "vpn:wg1 [B]"
        losses = [loss(f"d{m}", 0) for m in range(130)]
        losses += [loss(f"a{m}", 0, a1 if m < 6 else a2, "wg0") for m in range(12)]
        losses += [loss(f"b{m}", 0, b, "wg1") for m in range(12)]
        samples = self.samples(a1, 12, 2, 40.0) + self.samples(b, 12, 0, 45.0, local="192.0.2.20:9")
        sessions = []
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                d = Path(tmp) / f"s{i}"
                write_session(d, {"losses.csv": losses, "samples.csv": samples if i == 0 else []})
                sessions.append(d)
            s = summarise(sessions)
        rec = advice.recommend(s, ("GAME.exe", "13328"))
        self.assertEqual(rec.verdict, "stay-direct")
        self.assertEqual([r.path for r in rec.ranking], ["vpn:wg1 [B]", "vpn:wg0 [A]"])
        self.assertEqual(rec.ranking[1].members, (a1, a2))
        self.assertIn("ping steady in 100 % of minutes", rec.headline)
