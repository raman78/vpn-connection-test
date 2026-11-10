import json
import unittest

from vpnct.interfaces import (PathMap, parse_ip_addr, parse_nm_active,
                              parse_nm_device_targets, parse_wireguard_endpoint)
from vpnct.probes import parse_ping, parse_tracepath
from vpnct.procs import program_from_cmdline
from vpnct.ss import parse_ss, split_endpoint

SS_OUTPUT = """\
0      11     192.0.2.20:40000 203.0.113.10:13328 users:(("GameThread",pid=4242,fd=165),("wineserver",pid=4100,fd=3229))
\t cubic wscale:13,2 rto:232 rtt:31.654/11.273 ato:40 mss:1400 cwnd:10 bytes_sent:217358 bytes_acked:217348 bytes_received:2569528 segs_out:26541 segs_in:26876 data_segs_out:19231 data_segs_in:21170 send 3538257bps lastsnd:18 minrtt:16.233 snd_wnd:139264 rcv_wnd:163240
0      0      192.0.2.20:40002 198.51.100.7:443 users:(("vivaldi-bin",pid=77,fd=9))
\t cubic rtt:40.1/2 minrtt:38.5 bytes_received:900 segs_in:12 data_segs_in:6 retrans:0/3 rcv_ooopack:4 lost:1
0      0      [::1]:631 [::1]:50000
"""

IP_JSON = json.dumps([
    {"ifindex": 1, "ifname": "lo", "link_type": "loopback",
     "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
    {"ifindex": 2, "ifname": "eth0", "link_type": "ether",
     "addr_info": [{"family": "inet", "local": "192.0.2.20"}]},
    {"ifindex": 9, "ifname": "wg0", "link_type": "none", "linkinfo": {"info_kind": "wireguard"},
     "addr_info": [{"family": "inet", "local": "10.99.0.2"}]},
    {"ifindex": 12, "ifname": "leak0", "link_type": "ether", "linkinfo": {"info_kind": "dummy"},
     "addr_info": [{"family": "inet6", "local": "fd00::1"}]},
])


class SsTests(unittest.TestCase):
    def test_parse(self):
        a, b, c = parse_ss(SS_OUTPUT)
        self.assertEqual(a.key, ("192.0.2.20", 40000, "203.0.113.10", 13328))
        self.assertEqual((a.pid, a.comm), (4242, "GameThread"))
        self.assertEqual((a.rtt_ms, a.rttvar_ms, a.minrtt_ms), (31.654, 11.273, 16.233))
        self.assertEqual(a.data_segs_in, 21170)

    def test_missing_counters_are_zero(self):
        a = parse_ss(SS_OUTPUT)[0]
        self.assertEqual((a.retrans_total, a.rcv_ooopack), (0, 0))

    def test_retrans_total_and_ooo(self):
        b = parse_ss(SS_OUTPUT)[1]
        self.assertEqual((b.retrans_total, b.rcv_ooopack), (3, 4))

    def test_socket_without_stats_line(self):
        c = parse_ss(SS_OUTPUT)[2]
        self.assertEqual((c.local_ip, c.remote_port, c.pid, c.rtt_ms), ("::1", 50000, None, None))

    def test_endpoints(self):
        self.assertEqual(split_endpoint("192.0.2.20%eth0:68"), ("192.0.2.20", 68))
        self.assertEqual(split_endpoint("[::ffff:192.0.2.1]:80"), ("192.0.2.1", 80))
        self.assertEqual(split_endpoint("[2001:db8::1]:443"), ("2001:db8::1", 443))


class ProcTests(unittest.TestCase):
    def test_wine_windows_path(self):
        raw = b"Z:\\home\\u\\Games\\GAME\\Binaries\\Win64\\GAME.exe\0-steam\0"
        self.assertEqual(program_from_cmdline(raw), "GAME.exe")

    def test_electron_rewritten_command_line(self):
        raw = b"/tmp/.mount_RamboxX/rambox --no-sandbox\0"
        self.assertEqual(program_from_cmdline(raw), "rambox")
        self.assertEqual(program_from_cmdline(b"discord --type=renderer --x=1"), "discord")

    def test_windows_path_with_dash_in_real_argv_is_kept(self):
        raw = b"C:\\Games\\Foo - Bar\\foo.exe\0-steam\0"
        self.assertEqual(program_from_cmdline(raw), "foo.exe")

    def test_unix_path_and_empty(self):
        self.assertEqual(program_from_cmdline(b"/usr/lib/vivaldi/vivaldi-bin\0--type=x"), "vivaldi-bin")
        self.assertIsNone(program_from_cmdline(b""))


class InterfaceTests(unittest.TestCase):
    def test_kinds(self):
        itfs = {i.name: i for i in parse_ip_addr(IP_JSON)}
        self.assertFalse(itfs["eth0"].is_vpn)
        self.assertTrue(itfs["wg0"].is_vpn)
        self.assertEqual(itfs["wg0"].kind, "wireguard")

    def test_paths(self):
        pm = PathMap(parse_ip_addr(IP_JSON), {"wg0": "VPN NL#1", "eth0": "Wired"})
        self.assertEqual(pm.path_for("10.99.0.2").label, "vpn:wg0 [VPN NL#1]")
        self.assertEqual(pm.path_for("192.0.2.20").label, "direct:eth0 [Wired]")
        self.assertEqual(pm.path_for("10.99.0.3").label, "gone(10.99.0.3)")
        # a VPN client's dummy device has addresses but no default route
        self.assertEqual([i.name for i in pm.direct_interfaces({"eth0"})], ["eth0"])
        self.assertEqual(pm.direct_interfaces(set()), [])
        self.assertEqual([i.name for i in pm.vpn_interfaces()], ["wg0"])

    def test_signature_changes_when_device_is_recreated(self):
        a = PathMap(parse_ip_addr(IP_JSON), {})
        data = json.loads(IP_JSON)
        data[2]["ifindex"] = 10
        b = PathMap(parse_ip_addr(json.dumps(data)), {})
        self.assertNotEqual(a.signature(), b.signature())

    def test_nm_terse_escape(self):
        out = "VPN NL#1:wg0\nWired connection 1:eth0\nA\\:B:eth1\nlo:lo\n"
        self.assertEqual(parse_nm_active(out),
                         {"wg0": "VPN NL#1", "eth0": "Wired connection 1",
                          "eth1": "A:B", "lo": "lo"})

    def test_nm_device_targets(self):
        self.assertEqual(parse_nm_device_targets("192.0.2.1\n198.51.100.53 | 198.51.100.54\n"),
                         ["192.0.2.1", "198.51.100.53", "198.51.100.54"])
        self.assertEqual(parse_nm_device_targets("\n10.99.0.1\n"), ["10.99.0.1"])

    def test_wireguard_endpoint(self):
        # nmcli -g escapes ':' (shape recorded from a Proton VPN connection, 2026-11-10)
        self.assertEqual(parse_wireguard_endpoint(
            "5jCMG3U4pgJLotvxcXNGiRUuQ2RiVXhAAGVPo4JG5Tg= allowed-ips=0.0.0.0/0 "
            "endpoint=198.51.100.139\\:443\n"), "198.51.100.139")
        self.assertEqual(parse_wireguard_endpoint("K= allowed-ips=::/0 endpoint=[2001\\:db8\\:\\:1]\\:51820"),
                         "2001:db8::1")
        self.assertIsNone(parse_wireguard_endpoint("K= allowed-ips=0.0.0.0/0\n"))
        self.assertIsNone(parse_wireguard_endpoint(""))


PING_OK = """PING 198.51.100.1 (198.51.100.1) 56(84) bytes of data.

--- 198.51.100.1 ping statistics ---
20 packets transmitted, 17 received, 15% packet loss, time 3803ms
rtt min/avg/max/mdev = 10.261/10.705/10.917/0.231 ms
"""
PING_NONE = """--- 192.0.2.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 409ms
"""
TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.0.2.1                                              0.306ms
 1:  192.0.2.1                                              0.205ms
 2:  no reply
 2:  198.51.100.9                                           7.4ms
 3:  no reply
 4:  203.0.113.10                                          17.8ms reached
     Resume: pmtu 1500 hops 4 back 4
"""


class ProbeParseTests(unittest.TestCase):
    def test_loss(self):
        r = parse_ping("198.51.100.1", None, 1, PING_OK, "")
        self.assertEqual((r.sent, r.received, r.loss_pct, r.rtt_avg), (20, 17, 15.0, 10.705))

    def test_nothing_back_is_loss_with_no_rtt(self):
        r = parse_ping("192.0.2.1", None, 1, PING_NONE, "")
        self.assertEqual((r.loss_pct, r.rtt_avg, r.error), (100.0, None, None))

    def test_could_not_send_is_an_error_not_loss(self):
        r = parse_ping("192.0.2.1", "eth9", 2, "", "ping: SO_BINDTODEVICE eth9: No such device\n")
        self.assertIsNone(r.loss_pct)
        self.assertIn("No such device", r.error)

    def test_interrupted_is_named(self):
        r = parse_ping("192.0.2.1", None, -2, "", "")
        self.assertEqual(r.error, "interrupted by SIGINT")

    def test_tracepath(self):
        hops = parse_tracepath(TRACEPATH)
        self.assertEqual([(h.number, h.address) for h in hops],
                         [(1, "192.0.2.1"), (2, "198.51.100.9"), (3, None), (4, "203.0.113.10")])


if __name__ == "__main__":
    unittest.main()


class SerialPerPathTests(unittest.TestCase):
    def test_same_path_never_overlaps_other_paths_do(self):
        import threading
        import time
        from vpnct.probes import run_serial_per_path
        running: dict[str, int] = {}
        peak: dict[str, int] = {}
        lock = threading.Lock()
        overall = {"now": 0, "peak": 0}

        def run(job):
            path, n = job
            with lock:
                running[path] = running.get(path, 0) + 1
                peak[path] = max(peak.get(path, 0), running[path])
                overall["now"] += 1
                overall["peak"] = max(overall["peak"], overall["now"])
            time.sleep(0.05)
            with lock:
                running[path] -= 1
                overall["now"] -= 1
            return (path, n)

        jobs = [("vpn", 1), ("direct", 1), ("vpn", 2), ("direct", 2), ("vpn", 3)]
        results = run_serial_per_path(jobs, lambda j: j[0], run)
        self.assertEqual(results, jobs)
        self.assertEqual(peak, {"vpn": 1, "direct": 1})
        self.assertEqual(overall["peak"], 2)


class SerialStopTests(unittest.TestCase):
    def test_stop_leaves_unstarted_jobs_out(self):
        import threading
        from vpnct.probes import run_serial_per_path
        stop = threading.Event()
        done = []

        def run(job):
            done.append(job)
            stop.set()                       # stop requested during the first job
            return job

        results = run_serial_per_path([1, 2, 3], lambda j: "vpn", run, stop=stop)
        self.assertEqual(done, [1])
        self.assertEqual(results, [1, None, None])
