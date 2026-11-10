import unittest

from vpnct.probes import Hop, PingResult, classify_route, parse_ttl_ping


def hop(n, loss, addr=None, received=None):
    sent = 20
    rec = received if received is not None else round(sent * (1 - loss / 100))
    return Hop(n, addr or f"198.51.100.{n}", PingResult(addr or "x", "eth0", sent, rec, 1, 1, 1))


class TtlParseTests(unittest.TestCase):
    def test_exceeded(self):
        out = "PING 203.0.113.10 (203.0.113.10) from 192.0.2.20 eth0: 56(84) bytes of data.\n" \
              "From 198.51.100.1 icmp_seq=1 Time to live exceeded\n"
        self.assertEqual(parse_ttl_ping(out), ("198.51.100.1", False))

    def test_reached(self):
        out = "64 bytes from 203.0.113.10: icmp_seq=1 ttl=54 time=17.4 ms\n"
        self.assertEqual(parse_ttl_ping(out), ("203.0.113.10", True))

    def test_silence(self):
        self.assertEqual(parse_ttl_ping("PING x\n\n--- x ping statistics ---\n"), (None, False))


class VerdictTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(classify_route([hop(1, 0), hop(2, 0), hop(3, 0)], None).kind, "clean")

    def test_loss_starting_mid_route_is_real(self):
        v = classify_route([hop(1, 0), hop(2, 0), hop(3, 20), hop(4, 15), hop(5, 18)], None)
        self.assertEqual((v.kind, v.start_hop), ("real", 3))

    def test_silent_hops_do_not_break_the_run(self):
        v = classify_route([hop(1, 0), hop(2, 25), hop(3, 100, received=0), hop(4, 20)], None)
        self.assertEqual((v.kind, v.start_hop), ("real", 2))

    def test_single_lossy_hop_with_clean_target_is_ping_limiting(self):
        v = classify_route([hop(1, 0), hop(2, 40), hop(3, 0)], None)
        self.assertEqual(v.kind, "hop-limit")
        self.assertIn("hop 2", v.text)

    def test_loss_only_at_target(self):
        v = classify_route([hop(1, 0), hop(2, 0), hop(3, 30)], None)
        self.assertEqual((v.kind, v.start_hop), ("target-only", 3))

    def test_a_clean_hop_after_lossy_ones_ends_the_run(self):
        v = classify_route([hop(1, 30), hop(2, 0), hop(3, 20), hop(4, 25)], None)
        self.assertEqual(v.start_hop, 3)

    def test_server_not_answering_ping(self):
        self.assertEqual(classify_route([hop(1, 0), hop(2, 100, received=0)], None).kind, "no-answer")

    def test_one_lost_ping_is_not_loss(self):
        self.assertEqual(classify_route([hop(1, 0), hop(2, 5)], None).kind, "clean")

    def test_error_without_hops(self):
        self.assertEqual(classify_route([], "SO_BINDTODEVICE eth9: No such device").kind, "error")

    def test_name_is_shown(self):
        v = classify_route([hop(1, 0), hop(2, 20), hop(3, 20)], None, lambda a: "r1.example.net")
        self.assertIn("r1.example.net", v.text)


if __name__ == "__main__":
    unittest.main()


class StopTests(unittest.TestCase):
    """Quit must not wait for a trace, and a trace cut short is not a result."""

    def test_run_stoppable_kills_a_running_process(self):
        import threading, time
        from vpnct.probes import run_stoppable
        stop = threading.Event()
        threading.Timer(0.3, stop.set).start()
        t0 = time.monotonic()
        self.assertIsNone(run_stoppable(["sleep", "30"], stop, timeout=60))
        self.assertLess(time.monotonic() - t0, 2.0)

    def test_run_stoppable_returns_output_and_times_out(self):
        import subprocess
        from vpnct.probes import run_stoppable
        r = run_stoppable(["echo", "hop"], None, timeout=10)
        self.assertEqual((r.returncode, r.stdout), (0, "hop\n"))
        with self.assertRaises(subprocess.TimeoutExpired):
            run_stoppable(["sleep", "30"], None, timeout=0.5)

    def test_trace_via_stopped_during_hop_pings(self):
        import subprocess, threading
        from unittest import mock
        from vpnct import probes
        stop = threading.Event()
        replies = {"1": "From 198.51.100.1 icmp_seq=1 Time to live exceeded\n",
                   "2": "64 bytes from 203.0.113.10: icmp_seq=1 ttl=54 time=17.4 ms\n"}

        def fake_run(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, replies[cmd[cmd.index("-t") + 1]], "")

        def fake_ping(*a, **kw):
            stop.set()                     # Quit pressed while the first hop is pinged
            return PingResult("x", "eth0", 20, 20, 1.0, 1.0, 1.0, None)

        with mock.patch.object(probes.subprocess, "run", fake_run), mock.patch.object(probes, "ping", fake_ping):
            hops, error = probes.trace_via("203.0.113.10", "eth0", stop=stop)
        self.assertEqual(error, probes.STOPPED)
        self.assertIsNone(hops[1].ping)    # the server was never pinged: no verdict may be drawn

    def test_trace_route_stopped_during_hop_pings(self):
        import subprocess, threading
        from unittest import mock
        from vpnct import probes
        from tests.test_parsers import TRACEPATH
        stop = threading.Event()

        def fake_ping(*a, **kw):
            stop.set()
            return PingResult("x", None, 20, 20, 1.0, 1.0, 1.0, None)

        done = subprocess.CompletedProcess([], 0, TRACEPATH, "")
        with mock.patch.object(probes, "run_stoppable", lambda *a, **kw: done), \
                mock.patch.object(probes, "ping", fake_ping):
            _hops, error = probes.trace_route("203.0.113.10", stop=stop)
        self.assertEqual(error, probes.STOPPED)
        with mock.patch.object(probes, "run_stoppable", lambda *a, **kw: None):
            self.assertEqual(probes.trace_route("203.0.113.10", stop=stop), ([], probes.STOPPED))

    def test_no_tunnel_trace_after_stop(self):
        import threading
        from types import SimpleNamespace
        from vpnct.engine import Engine
        stop = threading.Event()
        calls = []
        fake = SimpleNamespace(
            _stop=stop,
            paths=SimpleNamespace(direct_interfaces=lambda devs: [SimpleNamespace(name="eth0")],
                                  vpn_interfaces=lambda: ["wg0"]),
            _trace_direct=lambda target, itf, trigger: (calls.append("direct"), stop.set()),
            _trace=lambda target: calls.append("tunnel"))
        from unittest import mock
        with mock.patch("vpnct.engine.interfaces.read_default_route_devices", lambda: {"eth0"}):
            Engine._trace_paths(fake, "203.0.113.10", "schedule")
        self.assertEqual(calls, ["direct"])

    def test_stopped_traces_write_nothing(self):
        import threading
        from types import SimpleNamespace
        from unittest import mock
        from vpnct import probes
        from vpnct.engine import Engine
        written = []
        fake = SimpleNamespace(
            _stop=threading.Event(),
            paths=SimpleNamespace(path_for_interface=lambda itf: SimpleNamespace(label="direct:eth0")),
            session=SimpleNamespace(write=lambda name, row: written.append(name)),
            _event=lambda *a: written.append("event"))
        with mock.patch.object(probes, "trace_via", lambda *a, **kw: ([probes.Hop(1, "198.51.100.1")], probes.STOPPED)), \
                mock.patch.object(probes, "trace_route", lambda *a, **kw: ([], probes.STOPPED)), \
                mock.patch("vpnct.engine.interfaces.route_interface", lambda t: "wg0"):
            Engine._trace_direct(fake, "203.0.113.10", "eth0", "schedule")
            Engine._trace(fake, "203.0.113.10")
        self.assertEqual(written, [])
