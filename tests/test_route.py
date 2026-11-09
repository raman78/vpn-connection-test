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
