import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from vpnct.capture import (Pipeline, bpf_filter, parse_tshark_line, tshark_command,
                           TSHARK_FIELDS)

SERVER = ("203.0.113.10", 13328)
CLIENT = ("192.0.2.20", 40000)
KEY = (CLIENT[0], CLIENT[1], SERVER[0], SERVER[1])


def _ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def _packet(src, dst, seq, ack, payload_len, flags=0x18) -> tuple[bytes, int]:
    """IPv4 + TCP headers only; the payload is declared in the IP total length
    but not included, exactly like a capture cut at the snap length."""
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
    total = 20 + len(tcp) + payload_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, _ip(src[0]), _ip(dst[0]))
    return ip + tcp, total


def write_pcap(path: Path, packets: list[tuple[float, bytes, int]]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 101))  # LINKTYPE_RAW
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


@unittest.skipUnless(shutil.which("dumpcap"), "dumpcap not installed")
class RealFilterTests(unittest.TestCase):
    def test_dumpcap_compiles_the_filter(self):
        f = bpf_filter(frozenset({KEY, ("192.0.2.20", 40001, "198.51.100.7", 443)}))
        r = subprocess.run(["dumpcap", "-d", "-i", "lo", "-f", f], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
