"""Count packet loss on watched connections from packet headers.

`dumpcap` captures only the first CAPTURE_SNAPLEN bytes of each packet and
writes pcapng to a pipe; `tshark` reads the pipe and runs its TCP sequence
analysis. Those bytes are the IP and TCP headers and, when the headers are
shorter than the limit, the first bytes of the payload (up to 44 on a
WireGuard device with IPv4 and TCP timestamps); tshark prints only the
fields in TSHARK_FIELDS. Nothing is written to disk — `tshark -i` would
spool to a temporary file in /tmp, the pipe does not. The headers carry
everything the analysis needs: the TCP length comes from the IP header,
losses from sequence numbers.

Per watched connection and per minute, for data packets from the remote end:
- data_pkts: packets carrying data;
- lost_gaps: places where the sequence jumped (`tcp.analysis.lost_segment`);
  a burst of consecutive losses is one gap;
- retrans: retransmissions by the remote end, which is the closer count of
  packets actually lost.
`covered_s` says how much of the minute the capture was running, so a minute
with zeros because nothing was lost is distinguishable from one the capture
did not see.

Stalls, per connection and minute: a pause of at least STALL_MIN_S between
two data packets from the remote end, during which our side sent data.
- stalls / stall_s / stall_max_s: such pauses in which the remote end still
  answered (acknowledged our data). The connection was alive and the remote
  program sent nothing: the server lagging, not the route losing. Measured
  2026-11-14 on AION 2: the server normally sends every ~0.3 s; on a day many
  players reported lag it paused for 0.6, 1.2, 2.4 and 7.5 s (whole ticks)
  while acknowledging our packets within 17-58 ms, without a single
  retransmission — invisible to loss, and to RTT, which the kernel updates
  only when data arrives.
- silent: such pauses in which nothing at all came back: the connection
  itself went quiet.
- stalls_short: pauses of STALL_SHORT_S up to STALL_MIN_S, link answering.
  The AION 2 server skips single 0.6 s ticks this way; the game's own ping
  (which Questlog shows, read from the game's ping reply) jumps by as much.
  Recorded to learn how many a normal evening has before anything judges
  them.
A pause is counted in the minute it ends in. A pause in which our side sent
nothing either is not counted: nobody was talking.

AION 2 connections (remote port in aion2.DEFAULT_PORTS) are captured whole
and their server stream is decoded for three messages (`vpnct/games/aion2.py`):
the game's own ping, map entries (loading screens) and the server's clock.
Their packets reach the decoder through the same pipe and are never written
anywhere; every other connection stays headers-only. Per minute this adds:
- game_pings / game_ping_ms / game_ping_max_ms: the game's ping replies,
  their median and highest (the ping Questlog shows);
- map_entries: loading screens begun;
- stalls_loading: stalls with a map entry from LOADING_BEFORE_S before the
  stall began to LOADING_AFTER_S after it ended, counted here instead of in
  stalls. Measured 2026-11-15:
  the server went quiet for 2.3 s while a new instance loaded, and its map
  entry came 0.4 s after the pause (once 6.5 s after it). Because the entry
  can come after the stall, minutes of a decoded connection are closed
  LOADING_AFTER_S + FLUSH_DELAY_S after they end, not FLUSH_DELAY_S.

One pipeline per captured connection, its filter naming that connection
exactly (both addresses and ports). Connections come and go independently:
starting or ending one never restarts another, so the TCP analysis of a
long-lived connection keeps its state for the connection's whole life.
(A shared per-interface pipeline restarted on every change was tried first;
a game opening short HTTPS requests restarted it every few seconds.)
"""

from __future__ import annotations

import statistics
import subprocess
import threading
import time
from dataclasses import dataclass, field

from .games import aion2

CAPTURE_SNAPLEN = 96
FLUSH_DELAY_S = 2.0          # wait for late lines before closing a minute
RETRY_AFTER_S = 10.0
STALL_MIN_S = 1.0            # a pause in the remote end's data this long is a stall
STALL_SHORT_S = 0.5          # and from this long up to STALL_MIN_S, a short stall
LOADING_BEFORE_S = 5.0       # a map entry up to this long before a stall makes it a loading screen
LOADING_AFTER_S = 10.0       # and so does one up to this long after it
DECODE_SNAPLEN = 0           # whole packets, for connections whose stream is decoded

TSHARK_FIELDS = ["frame.time_epoch", "ip.src", "ipv6.src", "tcp.srcport",
                 "ip.dst", "ipv6.dst", "tcp.dstport", "tcp.len",
                 "tcp.analysis.lost_segment", "tcp.analysis.retransmission"]
DECODE_FIELDS = TSHARK_FIELDS + ["tcp.seq_raw", "tcp.payload"]

Key = tuple[str, int, str, int]   # local ip, local port, remote ip, remote port


def bpf_filter(keys: frozenset[Key]) -> str:
    parts = [f"(host {rip} and tcp port {rport} and tcp port {lport})"
             for lip, lport, rip, rport in sorted(keys)]
    return " or ".join(parts)


def decoded(key: Key) -> bool:
    """Whether this connection's stream is decoded (and so captured whole)."""
    return key[3] in aion2.DEFAULT_PORTS


def tshark_command(source: str = "-", decode: bool = False) -> list[str]:
    # Every packet, not only those with data: the remote end's bare
    # acknowledgements tell a server that stopped sending (stall) from a
    # connection that went quiet (silent).
    cmd = ["tshark", "-l", "-n", "-r", source,
           "-T", "fields", "-E", "separator=|"]
    for f in DECODE_FIELDS if decode else TSHARK_FIELDS:
        cmd += ["-e", f]
    return cmd


def dumpcap_command(interface: str, keys: frozenset[Key], decode: bool = False) -> list[str]:
    return ["dumpcap", "-q", "-i", interface, "-s", str(DECODE_SNAPLEN if decode else CAPTURE_SNAPLEN),
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
    seq: int | None = None          # decoded connections only
    payload: bytes | None = None


def parse_tshark_line(line: str) -> PacketLine | None:
    f = line.rstrip("\n").split("|")
    if len(f) not in (len(TSHARK_FIELDS), len(DECODE_FIELDS)) or not f[0] or not f[3]:
        return None
    seq = payload = None
    if len(f) == len(DECODE_FIELDS):
        seq = int(f[10]) if f[10] else None
        payload = bytes.fromhex(f[11].replace(":", "")) if f[11] else None
    return PacketLine(
        time=float(f[0]), src=f[1] or f[2], sport=int(f[3]),
        dst=f[4] or f[5], dport=int(f[6]), length=int(f[7] or 0),
        lost=bool(f[8]), retrans=bool(f[9]), seq=seq, payload=payload)


@dataclass
class MinuteRow:
    minute: int
    interface: str
    key: Key
    covered_s: float
    data_pkts: int
    lost_gaps: int
    retrans: int
    stalls: int = 0
    stall_s: float = 0.0
    stall_max_s: float = 0.0
    silent: int = 0
    stalls_short: int = 0
    stalls_loading: int = 0
    map_entries: int = 0
    game_pings: int = 0
    game_ping_ms: float | None = None
    game_ping_max_ms: float | None = None


@dataclass
class _Pause:
    """Since the remote end's last data packet."""
    last_data: float | None = None
    remote_seen: bool = False      # any packet from the remote end since
    local_data: bool = False       # our side sent data since


@dataclass
class Pipeline:
    interface: str
    keys: frozenset[Key]
    started: float
    stopped: float | None = None
    counts: dict = field(default_factory=dict)       # (minute, key) -> [data, lost, retrans, stalls, stall_s, stall_max_s, silent, stalls_short]
    pauses: dict = field(default_factory=dict)       # key -> _Pause
    lock: threading.Lock = field(default_factory=threading.Lock)
    procs: list = field(default_factory=list)
    stderr_tail: list = field(default_factory=list)
    flushed_until: int = 0                            # minute start already emitted
    reader: threading.Thread | None = None
    stderr_readers: list = field(default_factory=list)
    drop_stats: str | None = None     # dumpcap's own "received/dropped" line
    game: aion2.GameConnection | None = None          # set when the stream is decoded
    stall_log: list = field(default_factory=list)    # (minute, key, start, end) of stalls, until their minute closes
    game_pings: list = field(default_factory=list)   # (minute, key, arrival, ms), until taken for game_ping.csv
    game_minutes: dict = field(default_factory=dict)  # (minute, key) -> [ping ms, ...]
    map_log: list = field(default_factory=list)      # (arrival, map id) of every map entry
    new_maps: list = field(default_factory=list)     # (arrival, map id), until taken for events

    def add(self, p: PacketLine) -> None:
        key = (p.dst, p.dport, p.src, p.sport)       # packet from the remote end
        if key not in self.keys:
            out = (p.src, p.sport, p.dst, p.dport)   # our packet
            if out in self.keys:
                with self.lock:
                    if p.length > 0:
                        self.pauses.setdefault(out, _Pause()).local_data = True
                    if self.game is not None:
                        self.game.add(p.time, False, p.length, p.seq, p.payload)
            return
        minute = int(p.time // 60) * 60
        with self.lock:
            if self.game is not None:
                self.game.add(p.time, True, p.length, p.seq, p.payload)
                pings, maps = self.game.take()
                for at, ms in pings:
                    m = int(at // 60) * 60
                    self.game_pings.append((m, key, at, ms))
                    self.game_minutes.setdefault((m, key), []).append(ms)
                self.map_log += maps
                self.new_maps += maps
            c = self.counts.setdefault((minute, key), [0, 0, 0, 0, 0.0, 0.0, 0, 0])
            pause = self.pauses.setdefault(key, _Pause())
            if p.length == 0:
                pause.remote_seen = True
                return
            c[0] += 1
            c[1] += p.lost
            c[2] += p.retrans
            if pause.last_data is not None and pause.local_data:
                gap = p.time - pause.last_data
                if gap >= STALL_MIN_S:
                    if pause.remote_seen:
                        # Judged when the minute closes: a map entry after
                        # it may still make it a loading screen.
                        self.stall_log.append((minute, key, pause.last_data, p.time))
                    else:
                        c[6] += 1
                elif gap >= STALL_SHORT_S and pause.remote_seen:
                    c[7] += 1
            pause.last_data, pause.remote_seen, pause.local_data = p.time, False, False

    def _loading(self, start: float, end: float) -> bool:
        return any(start - LOADING_BEFORE_S <= at <= end + LOADING_AFTER_S for at, _ in self.map_log)

    def take_rows(self, now: float, final: bool = False) -> list[MinuteRow]:
        """Rows for every minute that has ended (or all, when final)."""
        end = self.stopped if self.stopped is not None else now
        first = max(self.flushed_until, int(self.started // 60) * 60)
        delay = FLUSH_DELAY_S + (LOADING_AFTER_S if self.game is not None else 0.0)
        last_open = int((now - delay) // 60) * 60
        rows = []
        minute = first
        with self.lock:
            while minute < last_open or (final and minute <= end):
                covered = max(0.0, min(minute + 60, end) - max(minute, self.started))
                if covered > 0:
                    for key in sorted(self.keys):
                        d, l, r, _, _, _, si, sh = self.counts.pop((minute, key),
                                                                   (0, 0, 0, 0, 0.0, 0.0, 0, 0))
                        st = loading = 0
                        ss = sm = 0.0
                        for m, k, a, b in self.stall_log:
                            if (m, k) != (minute, key):
                                continue
                            if self._loading(a, b):
                                loading += 1
                            else:
                                st, ss, sm = st + 1, ss + (b - a), max(sm, b - a)
                        pings = self.game_minutes.pop((minute, key), [])
                        rows.append(MinuteRow(
                            minute, self.interface, key, round(covered, 1), d, l, r,
                            st, round(ss, 2), round(sm, 2), si, sh, loading,
                            sum(minute <= at < minute + 60 for at, _ in self.map_log),
                            len(pings),
                            round(statistics.median(pings), 1) if pings else None,
                            max(pings) if pings else None))
                minute += 60
            self.flushed_until = minute
            self.stall_log = [s for s in self.stall_log if s[0] >= minute]
            self.map_log = [x for x in self.map_log if x[0] >= minute - LOADING_BEFORE_S - 60]
        return rows

    def take_game(self) -> tuple[list, list]:
        """(game pings, map entries) since the last call, for the session files."""
        with self.lock:
            pings, maps = self.game_pings, self.new_maps
            self.game_pings, self.new_maps = [], []
        return pings, maps

    def decoder_state(self) -> str | None:
        """"recognised", "given up", "searching", or None when not decoded."""
        if self.game is None:
            return None
        d = self.game.decoder
        return "recognised" if d.recognised else "given up" if d.given_up else "searching"

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
        self._decoder_said: dict[int, str] = {}     # pipeline id -> decoder state last reported
        self._resyncs_said: dict[int, int] = {}

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
        decode = decoded(key)
        pipe = Pipeline(itf, keys, started=now, game=aion2.GameConnection() if decode else None)
        try:
            dc = subprocess.Popen(dumpcap_command(itf, keys, decode), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            ts = subprocess.Popen(tshark_command(decode=decode), stdin=dc.stdout, stdout=subprocess.PIPE,
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
        self.on_event("capture-start", f"{itf} {_fmt(key)}"
                      + ("; whole packets, AION 2 stream decoded for ping and loading" if decode else ""))

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

    def take_game(self) -> tuple[list, list]:
        """Game pings [(key, arrival, ms)] and map entries [(key, arrival,
        map id)] since the last call; decoder state changes as events."""
        pings, maps = [], []
        for pipe in [*self.active.values(), *self.stopped]:
            if pipe.game is None:
                continue
            (key,) = pipe.keys
            p, m = pipe.take_game()
            pings += [(key, at, ms) for _, _, at, ms in p]
            maps += [(key, at, map_id) for at, map_id in m]
            state = pipe.decoder_state()
            d = pipe.game.decoder
            if state != self._decoder_said.get(id(pipe), "searching"):
                self._decoder_said[id(pipe)] = state
                self.on_event("decode", f"{_fmt(key)}: " + (
                    "AION 2 stream recognised; game ping and loading screens measured"
                    if state == "recognised" else
                    f"not recognised as an AION 2 stream after {d.seen_bytes} bytes "
                    f"(a game update may have changed it); measured from headers only"))
            seen = self._resyncs_said.get(id(pipe), 0)
            lost = d.resyncs                 # capture gaps included: they resync too
            if lost > seen:
                self._resyncs_said[id(pipe)] = lost
                self.on_event("decode", f"{_fmt(key)}: lost the message boundaries "
                                        f"{lost - seen}x ({lost} in all); found again by resync")
        return pings, maps

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
