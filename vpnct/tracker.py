"""Follow connections over time and turn cumulative kernel counters into
per-second changes.

A connection is its 4-tuple. Counters in `ss` are cumulative for the life of
the socket; a reconnect is a new 4-tuple and starts from zero. A counter that
goes *down* on the same 4-tuple means the socket was replaced between two
samples: that is reported as an event and the new values become the
baseline — it is never turned into a negative delta.

Which connections are watched (sampled into the log and captured for loss):
- pinned: the program name or remote port matches what the user asked for;
- otherwise automatic: the busiest internet connections, by data segments
  received over the last minute, above a minimum rate.
Connections to loopback and to private/LAN addresses are not watched; how
many were skipped is reported, so a filtered connection is never invisible.

Which watched connections are *captured* (loss counted from packet headers):
those that have lived at least CAPTURE_MIN_AGE_S and received at least
CAPTURE_MIN_SEGMENTS data segments in the last minute, busiest first, at
most MAX_CAPTURED. A program's short HTTPS requests are watched (sampled)
but not captured: a few packets say nothing about loss, and each would cost
a capture process. Once captured, a connection stays captured until it
closes or changes path.
"""

from __future__ import annotations

import ipaddress
import time
from collections import deque
from dataclasses import dataclass, field

from .interfaces import UNKNOWN_PATH_PREFIX, NetPath, PathMap
from .procs import ProgramNames
from .ss import SocketStats

AUTO_WINDOW_S = 60
AUTO_MIN_SEGMENTS = 120      # data segments received per AUTO_WINDOW_S
AUTO_MAX_WATCHED = 5
CAPTURE_MIN_AGE_S = 10
CAPTURE_MIN_SEGMENTS = 10    # data segments received per AUTO_WINDOW_S
MAX_CAPTURED = 8


def is_internet(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


@dataclass
class Delta:
    """What one connection did during one sampling interval."""
    time: float
    key: tuple[str, int, str, int]
    program: str
    path: NetPath
    rtt_ms: float | None
    rttvar_ms: float | None
    minrtt_ms: float | None
    d_bytes_in: int
    d_data_segs_in: int
    d_retrans: int
    d_ooopack: int


@dataclass
class Tracked:
    first: SocketStats
    last: SocketStats
    program: str
    path: NetPath
    opened_at: float
    history: deque = field(default_factory=deque)   # (time, data_segs_in)
    watched: bool = False
    captured: bool = False

    def rate(self, now: float) -> int:
        """Data segments received in the last AUTO_WINDOW_S."""
        while self.history and self.history[0][0] < now - AUTO_WINDOW_S:
            self.history.popleft()
        if not self.history:
            return 0
        return self.last.data_segs_in - self.history[0][1]


@dataclass
class Event:
    time: float
    kind: str
    text: str


class Selection:
    """What the user asked to watch. Empty means automatic."""

    def __init__(self, programs: list[str] | None = None, ports: list[int] | None = None) -> None:
        self.programs = {p.lower() for p in programs or []}
        self.ports = set(ports or [])

    @property
    def automatic(self) -> bool:
        return not self.programs and not self.ports

    def pins(self, program: str, remote_port: int) -> bool:
        return program.lower() in self.programs or remote_port in self.ports

    def describe(self) -> str:
        if self.automatic:
            return (f"automatic: up to {AUTO_MAX_WATCHED} busiest internet connections "
                    f"with >= {AUTO_MIN_SEGMENTS} data segments/{AUTO_WINDOW_S}s")
        parts = [f"program {p}" for p in sorted(self.programs)]
        parts += [f"remote port {p}" for p in sorted(self.ports)]
        return "pinned: " + ", ".join(parts)


class Tracker:
    def __init__(self, selection: Selection, names: ProgramNames | None = None) -> None:
        self.selection = selection
        self.names = names or ProgramNames()
        self.conns: dict[tuple, Tracked] = {}
        self.skipped_local = 0

    def update(self, sockets: list[SocketStats], paths: PathMap,
               now: float | None = None) -> tuple[list[Delta], list[Event]]:
        now = time.time() if now is None else now
        deltas: list[Delta] = []
        events: list[Event] = []
        seen = set()
        skipped = 0
        for s in sockets:
            if not is_internet(s.remote_ip):
                skipped += 1
                continue
            seen.add(s.key)
            path = paths.path_for(s.local_ip)
            tr = self.conns.get(s.key)
            if tr is None:
                program = self.names.name(s.pid, s.comm)
                tr = Tracked(first=s, last=s, program=program, path=path, opened_at=now)
                tr.history.append((now, s.data_segs_in))
                self.conns[s.key] = tr
                continue
            prev = tr.last
            if (s.data_segs_in < prev.data_segs_in or s.bytes_received < prev.bytes_received
                    or s.retrans_total < prev.retrans_total):
                events.append(Event(now, "counters-reset",
                                    f"{tr.program} {_fmt_key(s.key)}: counters went down "
                                    f"(socket replaced between samples); new baseline"))
                tr.first = s
                tr.last = s
                tr.history.clear()
                tr.history.append((now, s.data_segs_in))
                continue
            if path != tr.path:
                if tr.watched:           # other connections' moves are not this session's subject
                    events.append(Event(now, "path-change",
                                        f"{tr.program} {_fmt_key(s.key)}: {tr.path.label} -> {path.label}"))
                tr.path = path
            tr.last = s
            tr.history.append((now, s.data_segs_in))
            if tr.watched:
                deltas.append(Delta(
                    time=now, key=s.key, program=tr.program, path=path,
                    rtt_ms=s.rtt_ms, rttvar_ms=s.rttvar_ms, minrtt_ms=s.minrtt_ms,
                    d_bytes_in=s.bytes_received - prev.bytes_received,
                    d_data_segs_in=s.data_segs_in - prev.data_segs_in,
                    d_retrans=s.retrans_total - prev.retrans_total,
                    d_ooopack=max(0, s.rcv_ooopack - prev.rcv_ooopack),
                ))
        self.skipped_local = skipped
        for key in [k for k in self.conns if k not in seen]:
            tr = self.conns.pop(key)
            if tr.watched:
                events.append(Event(now, "closed",
                                    f"{tr.program} {_fmt_key(key)} on {tr.path.label} after "
                                    f"{now - tr.opened_at:.0f}s, "
                                    f"{tr.last.data_segs_in - tr.first.data_segs_in} data segments in"))
        events += self._select(now)
        self.names.forget_except({t.last.pid for t in self.conns.values() if t.last.pid})
        return deltas, events

    def _select(self, now: float) -> list[Event]:
        events = []
        if self.selection.automatic:
            ranked = sorted(self.conns.values(), key=lambda t: t.rate(now), reverse=True)
            wanted = {id(t) for t in ranked[:AUTO_MAX_WATCHED] if t.rate(now) >= AUTO_MIN_SEGMENTS}
            # Hysteresis: a watched connection stays watched until it closes,
            # so its log is continuous; new ones join while there is room.
            n_watched = sum(t.watched for t in self.conns.values())
            for t in ranked:
                if not t.watched and id(t) in wanted and n_watched < AUTO_MAX_WATCHED:
                    t.watched = True
                    n_watched += 1
                    events.append(self._watch_event(now, t, f"busy ({t.rate(now)} segments/{AUTO_WINDOW_S}s)"))
        else:
            for t in self.conns.values():
                if not t.watched and self.selection.pins(t.program, t.last.remote_port):
                    t.watched = True
                    events.append(self._watch_event(now, t, "pinned"))
        return events

    @staticmethod
    def _watch_event(now: float, t: Tracked, why: str) -> Event:
        return Event(now, "watch", f"{t.program} {_fmt_key(t.last.key)} on {t.path.label}: {why}")

    def select_captured(self, now: float) -> list[Tracked]:
        """Update and return the connections whose packets are captured."""
        for t in self.conns.values():
            if t.captured and t.path.interface.startswith(UNKNOWN_PATH_PREFIX):
                t.captured = False
        current = [t for t in self.conns.values() if t.captured]
        candidates = sorted(
            (t for t in self.conns.values()
             if t.watched and not t.captured
             and now - t.opened_at >= CAPTURE_MIN_AGE_S
             and t.rate(now) >= CAPTURE_MIN_SEGMENTS
             and not t.path.interface.startswith(UNKNOWN_PATH_PREFIX)),
            key=lambda t: t.rate(now), reverse=True)
        for t in candidates[:max(0, MAX_CAPTURED - len(current))]:
            t.captured = True
            current.append(t)
        return current

    def watched(self) -> list[Tracked]:
        return [t for t in self.conns.values() if t.watched]

    def unwatched_count(self) -> int:
        return sum(not t.watched for t in self.conns.values())


def _fmt_key(key: tuple) -> str:
    lip, lport, rip, rport = key
    return f"{lip}:{lport} -> {rip}:{rport}"
