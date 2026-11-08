import json
import unittest
from dataclasses import replace

from vpnct.interfaces import PathMap, parse_ip_addr
from vpnct.ss import SocketStats
from vpnct.tracker import (AUTO_MIN_SEGMENTS, CAPTURE_MIN_AGE_S, CAPTURE_MIN_SEGMENTS,
                           Selection, Tracker)

IFS = json.dumps([
    {"ifindex": 2, "ifname": "eth0", "link_type": "ether",
     "addr_info": [{"local": "192.0.2.20"}]},
    {"ifindex": 9, "ifname": "wg0", "link_type": "none", "linkinfo": {"info_kind": "wireguard"},
     "addr_info": [{"local": "10.99.0.2"}]},
])
PATHS = PathMap(parse_ip_addr(IFS), {})


class Names:
    def name(self, pid, comm):
        return {1: "GAME.exe", 2: "browser"}.get(pid, comm or "?")

    def forget_except(self, pids):
        pass


# Remote addresses must be global to be watched; documentation ranges
# (192.0.2.0/24 etc.) are not, so the remote here is a public resolver.
def sock(remote="9.9.9.9", rport=13328, lport=40000, local="192.0.2.20", pid=1,
         data=0, bytes_in=0, retrans=0, ooo=0, rtt=20.0):
    return SocketStats(local, lport, remote, rport, pid, "GameThread", rtt, 1.0, 15.0,
                       retrans, ooo, bytes_in, 0, data, data)


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.t = Tracker(Selection(programs=["game.exe"]), Names())

    def test_pinned_connection_gives_deltas(self):
        self.t.update([sock(data=100, bytes_in=1000)], PATHS, now=0)
        deltas, events = self.t.update([sock(data=130, bytes_in=1500, retrans=2, ooo=3)], PATHS, now=1)
        self.assertEqual([e.kind for e in events], [])
        (d,) = deltas
        self.assertEqual((d.d_data_segs_in, d.d_bytes_in, d.d_retrans, d.d_ooopack), (30, 500, 2, 3))
        self.assertEqual(d.path.label, "direct:eth0")

    def test_first_update_announces_watch(self):
        _, events = self.t.update([sock()], PATHS, now=0)
        self.assertEqual([e.kind for e in events], ["watch"])

    def test_counter_going_down_is_reported_never_negative(self):
        self.t.update([sock(data=500, bytes_in=9000)], PATHS, now=0)
        self.t.update([sock(data=510, bytes_in=9100)], PATHS, now=1)
        deltas, events = self.t.update([sock(data=5, bytes_in=50)], PATHS, now=2)
        self.assertEqual(deltas, [])
        self.assertEqual([e.kind for e in events], ["counters-reset"])
        deltas, _ = self.t.update([sock(data=8, bytes_in=80)], PATHS, now=3)
        self.assertEqual(deltas[0].d_data_segs_in, 3)

    def test_local_and_lan_are_skipped_and_counted(self):
        self.t.update([sock(remote="127.0.0.1"), sock(remote="10.0.0.5"), sock()], PATHS, now=0)
        self.assertEqual(self.t.skipped_local, 2)
        self.assertEqual(len(self.t.conns), 1)

    def test_vanished_address_gets_gone_path(self):
        s = sock(local="10.99.0.2")
        self.t.update([s], PATHS, now=0)
        self.assertEqual(self.t.watched()[0].path.label, "vpn:wg0")
        no_vpn = PathMap([i for i in PATHS.interfaces if i.name != "wg0"], {})
        _, events = self.t.update([s], no_vpn, now=1)
        self.assertEqual([e.kind for e in events], ["path-change"])
        self.assertIn("gone(10.99.0.2)", events[0].text)

    def test_closed_watched_connection_is_reported(self):
        self.t.update([sock()], PATHS, now=0)
        _, events = self.t.update([], PATHS, now=5)
        self.assertEqual([e.kind for e in events], ["closed"])

    def test_unpinned_program_not_watched(self):
        self.t.update([sock(pid=2, rport=443)], PATHS, now=0)
        self.assertEqual(self.t.watched(), [])
        self.assertEqual(self.t.unwatched_count(), 1)


class AutoSelectionTests(unittest.TestCase):
    def test_busy_connection_is_picked_quiet_one_is_not(self):
        t = Tracker(Selection(), Names())
        busy, quiet = sock(lport=1), sock(lport=2, rport=443)
        t.update([busy, quiet], PATHS, now=0)
        _, events = t.update([replace(busy, data_segs_in=AUTO_MIN_SEGMENTS),
                              replace(quiet, data_segs_in=3)], PATHS, now=1)
        self.assertEqual([w.last.local_port for w in t.watched()], [1])
        self.assertEqual([e.kind for e in events], ["watch"])


class CaptureSelectionTests(unittest.TestCase):
    def setUp(self):
        self.t = Tracker(Selection(programs=["game.exe"]), Names())

    def test_short_request_is_watched_not_captured(self):
        s = sock(rport=443)
        self.t.update([s], PATHS, now=0)
        self.t.update([replace(s, data_segs_in=50)], PATHS, now=2)
        self.assertEqual(self.t.select_captured(2), [])
        self.assertEqual(len(self.t.watched()), 1)

    def test_lasting_busy_connection_is_captured(self):
        s = sock()
        self.t.update([s], PATHS, now=0)
        later = CAPTURE_MIN_AGE_S + 1
        self.t.update([replace(s, data_segs_in=CAPTURE_MIN_SEGMENTS)], PATHS, now=later)
        self.assertEqual([c.last.key for c in self.t.select_captured(later)], [s.key])

    def test_lasting_idle_connection_is_not_captured(self):
        s = sock()
        self.t.update([s], PATHS, now=0)
        later = CAPTURE_MIN_AGE_S + 1
        self.t.update([s], PATHS, now=later)
        self.assertEqual(self.t.select_captured(later), [])

    def test_vanished_path_stops_capture(self):
        s = sock(local="10.99.0.2")
        self.t.update([s], PATHS, now=0)
        later = CAPTURE_MIN_AGE_S + 1
        self.t.update([replace(s, data_segs_in=100)], PATHS, now=later)
        self.assertEqual(len(self.t.select_captured(later)), 1)
        no_vpn = PathMap([i for i in PATHS.interfaces if i.name != "wg0"], {})
        self.t.update([replace(s, data_segs_in=200)], no_vpn, now=later + 1)
        self.assertEqual(self.t.select_captured(later + 1), [])


if __name__ == "__main__":
    unittest.main()
