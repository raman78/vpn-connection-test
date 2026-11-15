import struct
import unittest

from vpnct.games import aion2
from vpnct.games.aion2 import (OP_BUNDLE, OP_ENTER_MAP, OP_MAP_FRAME, OP_PING_RS,
                               StreamDecoder, frame_length, lz4_block)

# Frames are built here from the format in vpnct/games/aion2.py's docstring.
# Bodies are made up: no captured game content is used in tests.


def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def frame(op, body):
    for size in (1, 2, 3, 4):
        total = size + 2 + len(body)
        head = leb(total + 4 - size)
        if len(head) == size:
            return head + struct.pack("<H", op) + body
    raise ValueError("frame too long")


def map_frame(t):
    return frame(OP_MAP_FRAME, struct.pack("<q", t))


def ping(sent, result=0):
    return frame(OP_PING_RS, struct.pack("<Hqq", result, sent, 777))


def enter_map(map_id):
    return frame(OP_ENTER_MAP, struct.pack("<ii", 42, map_id) + bytes(30))


def other(n=20):
    return frame(0x1234, bytes(i % 256 for i in range(n)))


def lz4_literals(raw):
    """A valid LZ4 block holding raw as literals only."""
    n = len(raw)
    if n < 15:
        return bytes([n << 4]) + raw
    rest, ext = n - 15, bytearray()
    while rest >= 255:
        ext.append(255)
        rest -= 255
    ext.append(rest)
    return bytes([0xF0]) + bytes(ext) + raw


def bundle(raw, block=None):
    block = lz4_literals(raw) if block is None else block
    return frame(OP_BUNDLE, struct.pack("<I", len(raw)) + block)


START = map_frame(1) + map_frame(2) + map_frame(3)     # recognises the stream


def kinds(msgs):
    return [(m.kind, m.value) for m in msgs]


class FramingTests(unittest.TestCase):
    def test_length_counts_as_if_the_header_were_four_bytes(self):
        f = ping(5)
        self.assertEqual(len(f), 21)            # the size seen on the wire in AION 2
        self.assertEqual(f[0], 24)
        self.assertEqual(frame_length(f, 0, len(f)), 21)

    def test_incomplete_and_impossible_headers(self):
        self.assertIsNone(frame_length(b"\x18\x03", 0, 2))
        self.assertEqual(frame_length(b"\x01\x00\x00", 0, 3), -1)

    def test_lz4_with_overlapping_match(self):
        # literal "ab", then a match at offset 2 of length 6 -> "abababab"
        # (a block ends with literals, here "c")
        block = bytes([0x22]) + b"ab" + struct.pack("<H", 2) + bytes([0x10]) + b"c"
        self.assertEqual(lz4_block(block, 9), b"ababababc")

    def test_lz4_rejects_wrong_size_and_bad_offset(self):
        self.assertIsNone(lz4_block(lz4_literals(b"abc"), 4))
        self.assertIsNone(lz4_block(bytes([0x10]) + b"a" + struct.pack("<H", 5) + bytes([0x10]) + b"b", 6))


class DecoderTests(unittest.TestCase):
    def test_three_messages_read_everything_else_stepped_over(self):
        d = StreamDecoder()
        msgs = d.push(START + other() + ping(123) + enter_map(9) + other(300), 1.0)
        self.assertTrue(d.recognised)
        self.assertEqual(kinds(msgs), [("frame", 1), ("frame", 2), ("frame", 3),
                                       ("ping", 123), ("map", 9)])

    def test_failed_ping_is_not_a_ping(self):
        msgs = StreamDecoder().push(START + ping(5, result=1), 1.0)
        self.assertNotIn("ping", [m.kind for m in msgs])

    def test_frame_split_across_packets_gets_the_completing_packets_time(self):
        d = StreamDecoder()
        d.push(START, 1.0)
        p = ping(55)
        self.assertEqual(d.push(p[:7], 2.0), [])
        (m,) = d.push(p[7:], 3.0)
        self.assertEqual((m.kind, m.value, m.at), ("ping", 55, 3.0))

    def test_ping_inside_a_bundle_is_found(self):
        # Observed 2026-11-14: 2 of 59 replies came packed with other messages.
        d = StreamDecoder()
        msgs = d.push(START + bundle(other(40) + ping(77) + map_frame(4)), 1.0)
        self.assertEqual(kinds(msgs)[3:], [("ping", 77), ("frame", 4)])

    def test_nothing_reported_until_recognised(self):
        d = StreamDecoder()
        self.assertEqual(d.push(map_frame(1) + ping(9), 1.0), [])
        self.assertFalse(d.recognised)
        msgs = d.push(map_frame(2), 2.0)            # third known message in a row
        self.assertTrue(d.recognised)
        self.assertEqual(kinds(msgs), [("frame", 1), ("ping", 9), ("frame", 2)])

    def test_unknown_messages_do_not_recognise_a_stream(self):
        d = StreamDecoder()
        d.push(other() * 50 + enter_map(3) * 5, 1.0)
        self.assertFalse(d.recognised)

    def test_starting_mid_stream_finds_the_frames(self):
        d = StreamDecoder()
        msgs = d.push(ping(1)[5:] + START + ping(8), 1.0)
        self.assertTrue(d.recognised)
        self.assertEqual(kinds(msgs)[-1], ("ping", 8))

    def test_gap_resyncs_and_is_counted(self):
        d = StreamDecoder()
        d.push(START, 1.0)
        d.gap()
        msgs = d.push(ping(3)[4:] + map_frame(5) + map_frame(6) + ping(7), 2.0)
        self.assertEqual(kinds(msgs), [("frame", 5), ("frame", 6), ("ping", 7)])
        self.assertEqual(d.resyncs, 1)

    def test_a_broken_bundle_loses_sync_and_the_stream_recovers(self):
        # A bundle whose size does not match is not unpacked. (Frames stored
        # as plain literals inside it would be found by the resync, as in
        # Questlog; they are the server's own messages, so that is right.)
        d = StreamDecoder()
        d.push(START, 1.0)
        raw = other(40)
        bad = frame(OP_BUNDLE, struct.pack("<I", len(raw) + 5) + lz4_literals(raw))
        msgs = d.push(bad + map_frame(7) + map_frame(8) + ping(10), 2.0)
        self.assertEqual(kinds(msgs), [("frame", 7), ("frame", 8), ("ping", 10)])
        self.assertEqual(d.resyncs, 1)

    def test_noise_is_given_up(self):
        d = StreamDecoder()
        for i in range(aion2.GIVE_UP_BYTES // 1000 + 2):
            d.push(bytes((i * 7 + k * 13) % 251 for k in range(1000)), float(i))
        self.assertTrue(d.given_up)
        self.assertFalse(d.recognised)
        self.assertLessEqual(len(d.buf), aion2.MAX_FRAME)


if __name__ == "__main__":
    unittest.main()


class GameConnectionTests(unittest.TestCase):
    """The game clock is OFFSET ms behind ours; each reply comes RTT later."""
    OFFSET, RTT = 5000, 0.030

    def _session(self, rounds, reply_in_bundle=(), skip_request=()):
        g, seq, t0 = aion2.GameConnection(), 0, 1_800_000_000.0

        def server(t, data):
            nonlocal seq
            g.add(t, True, len(data), seq, data)
            seq += len(data)
        server(t0, START)
        for i in range(rounds):
            t = t0 + 1 + 10 * i
            if i not in skip_request:
                g.add(t, False, aion2.REQUEST_LEN, None, None)
            reply = ping(round(t * 1000) - self.OFFSET)
            server(t + self.RTT, bundle(other(30) + reply) if i in reply_in_bundle else reply)
        return g

    def test_no_ping_until_the_clock_offset_is_known_then_all_of_them(self):
        g = self._session(aion2.OFFSET_MIN - 1)
        self.assertEqual(g.take()[0], [])
        g = self._session(aion2.OFFSET_MIN)
        self.assertEqual([ms for _, ms in g.take()[0]], [30.0] * aion2.OFFSET_MIN)

    def test_reply_in_a_bundle_gets_its_ping(self):
        g = self._session(6, reply_in_bundle={4})
        self.assertEqual([ms for _, ms in g.take()[0]], [30.0] * 6)

    def test_a_wrong_pair_does_not_move_the_offset(self):
        # Another 12-byte packet of ours 1 ms before a reply pairs with it
        # wrongly (an offset 29 ms off); the median of the pairs ignores it.
        g, seq, t0 = aion2.GameConnection(), 0, 1_800_000_000.0
        g.add(t0, True, len(START), seq, START)
        seq += len(START)
        for i in range(8):
            t = t0 + 1 + 10 * i
            g.add(t, False, aion2.REQUEST_LEN, None, None)
            if i in (5, 6):
                g.add(t + self.RTT - 0.001, False, aion2.REQUEST_LEN, None, None)   # stray
            reply = ping(round(t * 1000) - self.OFFSET)
            g.add(t + self.RTT, True, len(reply), seq, reply)
            seq += len(reply)
        self.assertEqual([ms for _, ms in g.take()[0]], [30.0] * 8)

    def test_out_of_order_and_retransmitted_segments(self):
        g = aion2.GameConnection()
        data = START + ping(1)
        g.add(1.0, True, 10, 0, data[:10])
        g.add(1.2, True, len(data) - 20, 20, data[20:])      # arrives before 10..20
        g.add(1.3, True, 10, 0, data[:10])                     # retransmission
        g.add(1.4, True, 10, 10, data[10:20])
        self.assertTrue(g.decoder.recognised)
        self.assertEqual(g.next_seq, len(data))
        self.assertEqual(g.decoder.resyncs, 0)

    def test_many_retransmissions_are_not_a_gap(self):
        g = aion2.GameConnection()
        data = START + ping(1)
        g.add(1.0, True, len(data), 0, data)
        for i in range(aion2.MAX_PENDING_SEGMENTS + 5):
            g.add(2.0 + i, True, 10, 0, data[:10])
        self.assertEqual((g.gaps, g.decoder.resyncs, len(g.pending)), (0, 0, 0))

    def test_maps_are_taken_once(self):
        g = aion2.GameConnection()
        data = START + enter_map(1010)
        g.add(1.0, True, len(data), 0, data)
        self.assertEqual(g.take()[1], [(1.0, 1010)])
        self.assertEqual(g.take()[1], [])
