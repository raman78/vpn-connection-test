"""Count packet loss on watched connections from packet headers.

One pipeline per interface: `dumpcap` captures only the first CAPTURE_SNAPLEN
bytes of each packet (IP + TCP headers, no payload) and writes pcapng to a
pipe; `tshark` reads the pipe and runs its TCP sequence analysis. Nothing is
written to disk — `tshark -i` would spool to a temporary file in /tmp, the
pipe does not. Payload-free headers still carry everything the analysis
needs: the TCP length comes from the IP header, losses from sequence numbers.

Per watched connection and per minute, for data packets from the remote end:
- data_pkts: packets carrying data;
- lost_gaps: places where the sequence jumped (`tcp.analysis.lost_segment`);
  a burst of consecutive losses is one gap;
- retrans: retransmissions by the remote end, which is the closer count of
  packets actually lost.
`covered_s` says how much of the minute the capture was running, so a minute
with zeros because nothing was lost is distinguishable from one the capture
did not see.

One pipeline per captured connection, its filter naming that connection
exactly (both addresses and ports). Connections come and go independently:
starting or ending one never restarts another, so the TCP analysis of a
long-lived connection keeps its state for the connection's whole life.
(A shared per-interface pipeline restarted on every change was tried first;
a game opening short HTTPS requests restarted it every few seconds.)
"""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass, field

CAPTURE_SNAPLEN = 96
FLUSH_DELAY_S = 2.0          # wait for late lines before closing a minute
RETRY_AFTER_S = 10.0

TSHARK_FIELDS = ["frame.time_epoch", "ip.src", "ipv6.src", "tcp.srcport",
                 "ip.dst", "ipv6.dst", "tcp.dstport", "tcp.len",
                 "tcp.analysis.lost_segment", "tcp.analysis.retransmission"]

Key = tuple[str, int, str, int]   # local ip, local port, remote ip, remote port


def bpf_filter(keys: frozenset[Key]) -> str:
    parts = [f"(host {rip} and tcp port {rport} and tcp port {lport})"
             for lip, lport, rip, rport in sorted(keys)]
    return " or ".join(parts)


def tshark_command(source: str = "-") -> list[str]:
    cmd = ["tshark", "-l", "-n", "-r", source, "-Y", "tcp.len>0",
           "-T", "fields", "-E", "separator=|"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    return cmd


def dumpcap_command(interface: str, keys: frozenset[Key]) -> list[str]:
    return ["dumpcap", "-q", "-i", interface, "-s", str(CAPTURE_SNAPLEN),
            "-f", bpf_filter(keys), "-w", "-"]


@dataclass
class PacketLine:
    time: float
    src: str
    sport: int
    dst: str
    dport: int
    length: int
    lost: bool
    retrans: bool


def parse_tshark_line(line: str) -> PacketLine | None:
    f = line.rstrip("\n").split("|")
    if len(f) != len(TSHARK_FIELDS) or not f[0] or not f[3]:
        return None
    return PacketLine(
        time=float(f[0]), src=f[1] or f[2], sport=int(f[3]),
        dst=f[4] or f[5], dport=int(f[6]), length=int(f[7] or 0),
        lost=bool(f[8]), retrans=bool(f[9]))


@dataclass
class MinuteRow:
    minute: int
    interface: str
    key: Key
    covered_s: float
    data_pkts: int
    lost_gaps: int
    retrans: int


@dataclass
class Pipeline:
    interface: str
    keys: frozenset[Key]
    started: float
    stopped: float | None = None
    counts: dict = field(default_factory=dict)       # (minute, key) -> [data, lost, retrans]
    lock: threading.Lock = field(default_factory=threading.Lock)
    procs: list = field(default_factory=list)
    stderr_tail: list = field(default_factory=list)
    flushed_until: int = 0                            # minute start already emitted
    reader: threading.Thread | None = None
    stderr_readers: list = field(default_factory=list)
    drop_stats: str | None = None     # dumpcap's own "received/dropped" line

    def add(self, p: PacketLine) -> None:
        key = (p.dst, p.dport, p.src, p.sport)       # packet from the remote end
        if key not in self.keys:
            return
        minute = int(p.time // 60) * 60
        with self.lock:
            c = self.counts.setdefault((minute, key), [0, 0, 0])
            c[0] += 1
            c[1] += p.lost
            c[2] += p.retrans

    def take_rows(self, now: float, final: bool = False) -> list[MinuteRow]:
        """Rows for every minute that has ended (or all, when final)."""
        end = self.stopped if self.stopped is not None else now
        first = max(self.flushed_until, int(self.started // 60) * 60)
        last_open = int((now - FLUSH_DELAY_S) // 60) * 60
        rows = []
        minute = first
        with self.lock:
            while minute < last_open or (final and minute <= end):
                covered = max(0.0, min(minute + 60, end) - max(minute, self.started))
                if covered > 0:
                    for key in sorted(self.keys):
                        d, l, r = self.counts.pop((minute, key), (0, 0, 0))
                        rows.append(MinuteRow(minute, self.interface, key, round(covered, 1), d, l, r))
                minute += 60
            self.flushed_until = minute
        return rows

    @property
    def running(self) -> bool:
        return bool(self.procs) and all(p.poll() is None for p in self.procs)


def _fmt(key: Key) -> str:
    lip, lport, rip, rport = key
    return f"{lip}:{lport} -> {rip}:{rport}"


class CaptureManager:
    """Keeps one pipeline per captured connection."""

    def __init__(self, on_event) -> None:
        self.on_event = on_event          # callable(kind, text)
        self.active: dict[Key, Pipeline] = {}
        self.stopped: list[Pipeline] = []
        self._last_failure: dict[Key, float] = {}

    def update(self, wanted: dict[Key, str], now: float) -> None:
        """`wanted`: connection -> the interface it runs on."""
        for key, pipe in list(self.active.items()):
            if not pipe.running and pipe.stopped is None:
                self._stop(pipe, now, reason="capture ended: " + (" | ".join(pipe.stderr_tail[-3:]) or "no message"))
                self._last_failure[key] = now
            elif key not in wanted:
                self._stop(pipe, now, reason="connection closed or no longer captured")
            elif wanted[key] != pipe.interface:
                self._stop(pipe, now, reason=f"connection moved to {wanted[key]}")
        for key, itf in wanted.items():
            if key in self.active:
                continue
            if now - self._last_failure.get(key, 0) < RETRY_AFTER_S:
                continue
            self._start(itf, key, now)
        for key in [k for k in self._last_failure if k not in wanted]:
            del self._last_failure[key]

    def _start(self, itf: str, key: Key, now: float) -> None:
        keys = frozenset({key})
        pipe = Pipeline(itf, keys, started=now)
        try:
            dc = subprocess.Popen(dumpcap_command(itf, keys), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            ts = subprocess.Popen(tshark_command(), stdin=dc.stdout, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            self.on_event("capture-error", f"{itf} {_fmt(key)}: cannot start capture: {exc}")
            self._last_failure[key] = now
            return
        dc.stdout.close()     # tshark owns the read end now
        pipe.procs = [dc, ts]
        pipe.reader = threading.Thread(target=self._read, args=(pipe, ts), daemon=True)
        pipe.reader.start()
        for proc, name in ((dc, "dumpcap"), (ts, "tshark")):
            t = threading.Thread(target=self._read_stderr, args=(pipe, proc, name), daemon=True)
            t.start()
            pipe.stderr_readers.append(t)
        self.active[key] = pipe
        self.on_event("capture-start", f"{itf} {_fmt(key)}")

    def _stop(self, pipe: Pipeline, now: float, reason: str) -> None:
        # Stop the capture only; tshark then reads the rest of the pipe, sees
        # end of file and exits, so no packet already captured is lost.
        dc, ts = pipe.procs
        if dc.poll() is None:
            dc.terminate()
        for proc in (dc, ts):
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for t in [pipe.reader, *pipe.stderr_readers]:
            if t is not None:
                t.join(timeout=3)
        pipe.stopped = now
        # Packets the kernel dropped before dumpcap saw them are losses the
        # analysis cannot see; dumpcap's own count says whether that happened.
        if pipe.drop_stats:
            reason += f"; {pipe.drop_stats}"
        (key,) = pipe.keys
        del self.active[key]
        self.stopped.append(pipe)
        self.on_event("capture-stop", f"{pipe.interface} {_fmt(key)}: {reason}")

    @staticmethod
    def _read(pipe: Pipeline, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            p = parse_tshark_line(line)
            if p is not None:
                pipe.add(p)

    @staticmethod
    def _read_stderr(pipe: Pipeline, proc: subprocess.Popen, name: str) -> None:
        for line in proc.stderr:
            if isinstance(line, bytes):
                line = line.decode("utf-8", "replace")
            line = line.strip()
            # dumpcap/tshark announce themselves on stderr; keep only real messages
            if line.startswith("Packets received/dropped"):
                pipe.drop_stats = line
            elif line and not line.startswith(("Capturing on", "File:")):
                pipe.stderr_tail.append(f"{name}: {line}")
                del pipe.stderr_tail[:-10]

    def take_rows(self, now: float) -> list[MinuteRow]:
        rows = []
        for pipe in self.active.values():
            rows += pipe.take_rows(now)
        for pipe in list(self.stopped):
            rows += pipe.take_rows(now, final=True)
            self.stopped.remove(pipe)
        return rows

    def stop_all(self, now: float) -> list[MinuteRow]:
        for pipe in list(self.active.values()):
            self._stop(pipe, now, reason="recording stopped")
        return self.take_rows(now)

    def status(self) -> dict[str, int]:
        """Interface -> number of connections captured on it."""
        result: dict[str, int] = {}
        for p in self.active.values():
            result[p.interface] = result.get(p.interface, 0) + 1
        return result

    def captured(self) -> set[Key]:
        return set(self.active)
