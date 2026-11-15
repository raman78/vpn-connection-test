import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from vpnct.capture import (DECODE_FIELDS, LOADING_AFTER_S, Pipeline, bpf_filter, decoded,
                           dumpcap_command, parse_tshark_line, tshark_command, TSHARK_FIELDS)
from vpnct.games import aion2
from tests.test_aion2 import START, enter_map, map_frame, ping

SERVER = ("203.0.113.10", 13328)
CLIENT = ("192.0.2.20", 40000)
KEY = (CLIENT[0], CLIENT[1], SERVER[0], SERVER[1])


def _ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def _packet(src, dst, seq, ack, payload_len, flags=0x18, payload=b"") -> tuple[bytes, int]:
    """IPv4 + TCP headers; the payload is declared in the IP total length but
    not included, exactly like a capture cut at the snap length — unless
    `payload` is given (a whole packet, as for a decoded connection)."""
    if payload:
        payload_len = len(payload)
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
    total = 20 + len(tcp) + payload_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, _ip(src[0]), _ip(dst[0]))
    return ip + tcp + payload, total


def write_pcap(path: Path, packets: list[tuple[float, bytes, int]], snaplen: int = 96) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 101))  # LINKTYPE_RAW
        for t, data, orig in packets:
            sec = int(t)
            fh.write(struct.pack("<IIII", sec, int((t - sec) * 1e6), len(data), orig))
            fh.write(data)


def stream_with_gap_and_retransmission() -> list[tuple[float, bytes, int]]:
    """Server sends 20 segments of 100 bytes, 10 ms apart; segment 5 is
    missing at first and retransmitted 300 ms later. The client ACKs."""
    pkts = []
    t0 = 1_800_000_000.0
    for i in range(20):
        if i == 5:
            continue
        data, orig = _packet(SERVER, CLIENT, 1000 + i * 100, 1, 100)
        pkts.append((t0 + i * 0.01, data, orig))
        ack = 1000 + (5 if i > 5 else i + 1) * 100
        data, orig = _packet(CLIENT, SERVER, 1, ack, 0, flags=0x10)
        pkts.append((t0 + i * 0.01 + 0.001, data, orig))
    data, orig = _packet(SERVER, CLIENT, 1500, 1, 100)
    pkts.append((t0 + 0.5, data, orig))
    return pkts


def stream_with_stall() -> list[tuple[float, bytes, int]]:
    """Server sends data every 0.3 s, then pauses 2.4 s (1.2 s to 3.6 s) while the client keeps
    sending data every 0.1 s and the server acknowledges each with a bare ACK
    — the 2026-11-14 AION 2 pattern — then resumes."""
    t0, pkts, sseq, cseq = 1_800_000_000.0, [], 1000, 1

    def server_data(t):
        nonlocal sseq
        pkts.append((t, *_packet(SERVER, CLIENT, sseq, cseq, 100)))
        sseq += 100

    for i in range(5):
        server_data(t0 + 0.3 * i)
    t = t0 + 1.25
    while t < t0 + 3.6:
        pkts.append((t, *_packet(CLIENT, SERVER, cseq, sseq, 20)))
        cseq += 20
        pkts.append((t + 0.017, *_packet(SERVER, CLIENT, sseq, cseq, 0, flags=0x10)))
        t += 0.1
    server_data(t0 + 3.6)
    return sorted(pkts)


class ParseTests(unittest.TestCase):
    def test_line(self):
        line = "1800000000.25|203.0.113.10||13328|192.0.2.20||40000|100|1|\n"
        p = parse_tshark_line(line)
        self.assertEqual((p.src, p.sport, p.dst, p.dport, p.length), (*SERVER, *CLIENT, 100))
        self.assertTrue(p.lost)
        self.assertFalse(p.retrans)

    def test_ipv6_columns(self):
        line = "1.0||2001:db8::1|443||2001:db8::2|5000|10||1"
        p = parse_tshark_line(line)
        self.assertEqual((p.src, p.dst), ("2001:db8::1", "2001:db8::2"))
        self.assertTrue(p.retrans)

    def test_malformed_lines_are_ignored(self):
        self.assertIsNone(parse_tshark_line(""))
        self.assertIsNone(parse_tshark_line("a|b"))

    def test_filter_names_both_ports(self):
        f = bpf_filter(frozenset({KEY}))
        self.assertEqual(f, "(host 203.0.113.10 and tcp port 13328 and tcp port 40000)")


class PipelineTests(unittest.TestCase):
    def _line(self, t, lost=False, retrans=False, sport=SERVER[1]):
        return parse_tshark_line(
            f"{t}|{SERVER[0]}||{sport}|{CLIENT[0]}||{CLIENT[1]}|100|{'1' if lost else ''}|{'1' if retrans else ''}")

    def _ours(self, t, length=20):
        return parse_tshark_line(f"{t}|{CLIENT[0]}||{CLIENT[1]}|{SERVER[0]}||{SERVER[1]}|{length}||")

    def _ack(self, t):
        return parse_tshark_line(f"{t}|{SERVER[0]}||{SERVER[1]}|{CLIENT[0]}||{CLIENT[1]}|0||")

    def test_pause_with_acks_is_a_stall(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        pipe.add(self._line(1030.0))
        pipe.add(self._ours(1030.5))
        pipe.add(self._ack(1030.52))
        pipe.add(self._line(1032.5))                 # 2.5 s without data, link answered
        pipe.add(self._line(1032.8))                 # 0.3 s: normal
        (r,) = pipe.take_rows(now=1085.0)
        self.assertEqual((r.data_pkts, r.stalls, r.stall_s, r.stall_max_s, r.silent), (3, 1, 2.5, 2.5, 0))

    def test_skipped_tick_is_a_short_stall(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        pipe.add(self._line(1030.0))
        pipe.add(self._ours(1030.1))
        pipe.add(self._ack(1030.12))
        pipe.add(self._line(1030.6))                 # 0.6 s: one skipped tick
        pipe.add(self._line(1030.9))                 # 0.3 s: normal pace
        (r,) = pipe.take_rows(now=1085.0)
        self.assertEqual((r.stalls, r.stalls_short), (0, 1))

    def test_pause_without_any_answer_is_silent(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        pipe.add(self._line(1030.0))
        pipe.add(self._ours(1030.5))
        pipe.add(self._line(1034.0))
        (r,) = pipe.take_rows(now=1085.0)
        self.assertEqual((r.stalls, r.silent), (0, 1))

    def test_pause_when_neither_side_talks_is_not_counted(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        pipe.add(self._line(1030.0))
        pipe.add(self._ours(1030.5, length=0))      # our bare ACK is not "talking"
        pipe.add(self._ack(1031.0))
        pipe.add(self._line(1040.0))
        (r,) = pipe.take_rows(now=1085.0)
        self.assertEqual((r.data_pkts, r.stalls, r.silent), (2, 0, 0))

    def test_counts_and_partial_coverage(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1030.0)
        pipe.add(self._line(1031.0))
        pipe.add(self._line(1032.0, lost=True))
        pipe.add(self._line(1033.0, retrans=True))
        pipe.add(self._line(1033.5, sport=9999))           # other connection: ignored
        rows = pipe.take_rows(now=1085.0)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r.minute, r.covered_s, r.data_pkts, r.lost_gaps, r.retrans),
                         (1020, 50.0, 3, 1, 1))

    def test_quiet_minute_is_a_zero_row_not_a_missing_row(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        rows = pipe.take_rows(now=1150.0)
        self.assertEqual([(r.minute, r.covered_s, r.data_pkts) for r in rows],
                         [(1020, 60.0, 0), (1080, 60.0, 0)])

    def test_open_minute_waits(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        self.assertEqual(pipe.take_rows(now=1081.0), [])     # within FLUSH_DELAY_S

    def test_final_flush_covers_until_stop(self):
        pipe = Pipeline("eth0", frozenset({KEY}), started=1020.0)
        pipe.add(self._line(1090.0))
        pipe.stopped = 1100.0
        rows = pipe.take_rows(now=1100.0, final=True)
        self.assertEqual([(r.minute, r.covered_s, r.data_pkts) for r in rows],
                         [(1020, 60.0, 0), (1080, 20.0, 1)])


def game_stream() -> list[tuple[float, bytes, int]]:
    """An AION 2-like session with whole packets: the server's stream is
    recognised, then five ping rounds 10 s apart: the client's 12-byte
    request, the reply 30 ms later (round 4: the reply 80 ms later). The
    game clock runs 5000 ms behind the wall clock."""
    t0, pkts, sseq, cseq = 1_800_000_000.0, [], 1000, 1
    def server(t, data):
        nonlocal sseq
        pkts.append((t, *_packet(SERVER, CLIENT, sseq, cseq, 0, payload=data)))
        sseq += len(data)
    def client(t, n):
        nonlocal cseq
        pkts.append((t, *_packet(CLIENT, SERVER, cseq, sseq, 0, payload=bytes(n))))
        cseq += n
    server(t0, START)
    for i in range(5):
        t = t0 + 1 + 10 * i
        client(t, aion2.REQUEST_LEN)
        server(t + (0.080 if i == 3 else 0.030), ping(round(t * 1000) - 5000))
    return sorted(pkts)


class GamePipelineTests(unittest.TestCase):
    def _line(self, t, data=b"", seq=0, ours=False):
        a, b = (CLIENT, SERVER) if ours else (SERVER, CLIENT)
        return parse_tshark_line(f"{t}|{a[0]}||{a[1]}|{b[0]}||{b[1]}|{len(data)}|||{seq}|{data.hex()}")

    def _pipe(self):
        return Pipeline("eth0", frozenset({KEY}), started=1020.0, game=aion2.GameConnection())

    def test_only_game_ports_are_decoded_and_captured_whole(self):
        self.assertTrue(decoded(KEY))
        self.assertFalse(decoded((*CLIENT, SERVER[0], 443)))
        self.assertIn("0", dumpcap_command("eth0", frozenset({KEY}), decode=True)[5])
        self.assertEqual(dumpcap_command("eth0", frozenset({KEY}))[5], "96")

    def test_stall_before_a_map_entry_is_loading_not_a_stall(self):
        # 2026-11-15: the server was quiet 2.3 s, its map entry 0.4 s after.
        pipe = self._pipe()
        seq = 0
        def server(t, data):
            nonlocal seq
            pipe.add(self._line(t, data, seq))
            seq += len(data)
        server(1025.0, START)
        pipe.add(self._line(1025.5, bytes(11), ours=True))
        pipe.add(parse_tshark_line(f"1026.0|{SERVER[0]}||{SERVER[1]}|{CLIENT[0]}||{CLIENT[1]}|0|||{seq}|"))
        server(1027.5, map_frame(4))                   # 2.5 s pause
        server(1027.9, enter_map(600001))
        (r,) = pipe.take_rows(now=1080 + LOADING_AFTER_S + 3)
        self.assertEqual((r.stalls, r.stalls_loading, r.map_entries), (0, 1, 1))

    def test_minute_waits_for_a_late_map_entry(self):
        pipe = self._pipe()
        self.assertEqual(pipe.take_rows(now=1085.0), [])     # plain pipelines close at 1082

    def test_same_stall_without_map_entry_is_a_stall(self):
        pipe = self._pipe()
        pipe.add(self._line(1025.0, START, 0))
        pipe.add(self._line(1025.5, bytes(11), ours=True))
        pipe.add(parse_tshark_line(f"1026.0|{SERVER[0]}||{SERVER[1]}|{CLIENT[0]}||{CLIENT[1]}|0|||{len(START)}|"))
        pipe.add(self._line(1027.5, map_frame(4), len(START)))
        (r,) = pipe.take_rows(now=1080 + LOADING_AFTER_S + 3)
        self.assertEqual((r.stalls, r.stalls_loading), (1, 0))


@unittest.skipUnless(shutil.which("tshark"), "tshark not installed")
class RealTsharkTests(unittest.TestCase):
    """Runs the shipped tshark command on a header-only capture."""

    def test_gap_and_retransmission_are_found_without_payload(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.pcap"
            write_pcap(path, stream_with_gap_and_retransmission())
            out = subprocess.run(tshark_command(str(path)), capture_output=True, text=True,
                                 check=True).stdout
        lines = [parse_tshark_line(x) for x in out.splitlines()]
        from_server = [p for p in lines if p and (p.src, p.sport) == SERVER]
        self.assertEqual(len(from_server), 20)
        self.assertTrue(all(p.length == 100 for p in from_server))
        self.assertEqual(sum(p.lost for p in from_server), 1)
        self.assertEqual(sum(p.retrans for p in from_server), 1)
        self.assertEqual(len(TSHARK_FIELDS), len(out.splitlines()[0].split("|")))

    def test_stall_is_found_through_the_shipped_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.pcap"
            write_pcap(path, stream_with_stall())
            out = subprocess.run(tshark_command(str(path)), capture_output=True, text=True,
                                 check=True).stdout
        pipe = Pipeline("eth0", frozenset({KEY}), started=1_799_999_990.0)
        for x in out.splitlines():
            p = parse_tshark_line(x)
            if p:
                pipe.add(p)
        rows = [r for r in pipe.take_rows(now=1_800_000_200.0) if r.data_pkts]
        self.assertEqual(sum(r.data_pkts for r in rows), 6)
        self.assertEqual(sum(r.stalls for r in rows), 1)
        self.assertAlmostEqual(max(r.stall_max_s for r in rows), 2.4, places=2)
        self.assertEqual(sum(r.retrans + r.lost_gaps for r in rows), 0)


@unittest.skipUnless(shutil.which("dumpcap"), "dumpcap not installed")
class RealFilterTests(unittest.TestCase):
    def test_game_ping_through_the_shipped_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "g.pcap"
            write_pcap(path, game_stream(), snaplen=65535)
            out = subprocess.run(tshark_command(str(path), decode=True), capture_output=True,
                                 text=True, check=True).stdout
        self.assertEqual(len(DECODE_FIELDS), len(out.splitlines()[0].split("|")))
        pipe = Pipeline("eth0", frozenset({KEY}), started=1_800_000_000.0, game=aion2.GameConnection())
        for line in out.splitlines():
            pipe.add(parse_tshark_line(line))
        pings, _ = pipe.take_game()
        self.assertEqual([round(ms) for _, _, _, ms in pings], [30, 30, 30, 80, 30])
        r = pipe.take_rows(now=1_800_000_200.0)[0]          # all five in the first minute
        self.assertEqual((r.game_pings, r.game_ping_ms, r.game_ping_max_ms), (5, 30.0, 80.0))

    def test_dumpcap_compiles_the_filter(self):
        f = bpf_filter(frozenset({KEY, ("192.0.2.20", 40001, "198.51.100.7", 443)}))
        r = subprocess.run(["dumpcap", "-d", "-i", "lo", "-f", f], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
