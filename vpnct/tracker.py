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
When something is pinned, each skipped connection of a pinned program or
port (loopback aside) is also a `skip` event, once, with the kind of
address: a game server outside the public address space would otherwise
vanish from the session without a trace.

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


def address_kind(ip: str) -> str:
    """Why an address is not a public internet address, in words."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not an IP address"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return "shared address space (100.64.0.0/10, carrier-grade NAT)"
    if addr.is_private:
        return "private"
    if addr.is_multicast:
        return "multicast"
    return "reserved, not public"


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
    first_program: str = ""      # the name when first seen ("?" while the socket had no owner)

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
        self.skip_pinned: dict[tuple, bool] = {}   # skipped key -> pinned (reported once)

    def update(self, sockets: list[SocketStats], paths: PathMap,
               now: float | None = None) -> tuple[list[Delta], list[Event]]:
        now = time.time() if now is None else now
        deltas: list[Delta] = []
        events: list[Event] = []
        seen = set()
        skipped = 0
        skipped_keys = set()
        for s in sockets:
            if not is_internet(s.remote_ip):
                skipped += 1
                skipped_keys.add(s.key)
                event = self._skip_event(now, s)
                if event:
                    events.append(event)
                continue
            seen.add(s.key)
            path = paths.path_for(s.local_ip)
            tr = self.conns.get(s.key)
            if tr is None:
                program = self._program(s)
                tr = Tracked(first=s, last=s, program=program, path=path, opened_at=now,
                             first_program=program)
                tr.history.append((now, s.data_segs_in))
                self.conns[s.key] = tr
                continue
            if not tr.watched:
                # Owners are read again until the connection is watched: a new
                # socket can be listed without its owner for a moment, and a
                # name fixed at first sight left the game's connection to a
                # dungeon unwatched for its whole life.
                tr.program = self._program(s)
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
        self.skip_pinned = {k: v for k, v in self.skip_pinned.items() if k in skipped_keys}
        for key in [k for k in self.conns if k not in seen]:
            tr = self.conns.pop(key)
            if tr.watched:
                events.append(Event(now, "closed",
                                    f"{tr.program} {_fmt_key(key)} on {tr.path.label} after "
                                    f"{now - tr.opened_at:.0f}s, "
                                    f"{tr.last.data_segs_in - tr.first.data_segs_in} data segments in"))
        events += self._select(now)
        self.names.forget_except({pid for t in self.conns.values()
                                  for _, pid in (t.last.owners or ((t.last.comm, t.last.pid),)) if pid})
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
                    why = "pinned"
                    if t.program != t.first_program:
                        why += (f", {now - t.opened_at:.0f}s after first seen as "
                                f"'{t.first_program}' (owner not known yet then)")
                    events.append(self._watch_event(now, t, why))
        return events

    def _program(self, s: SocketStats) -> str:
        """The program owning a socket. Every listed owner is considered, not
        only the first: when one of them is pinned, that one names it."""
        owners = s.owners or ((s.comm, s.pid),)
        names = [self.names.name(pid, comm) for comm, pid in owners]
        if not self.selection.automatic:
            for n in names:
                if self.selection.pins(n, s.remote_port):
                    return n
        return names[0]

    def _skip_event(self, now: float, s: SocketStats) -> Event | None:
        """A `skip` event the first time a pinned program's or port's
        connection is skipped for its address; None otherwise."""
        if s.key in self.skip_pinned or self.selection.automatic:
            return None
        kind = address_kind(s.remote_ip)
        program = self._program(s)
        pinned = kind != "loopback" and self.selection.pins(program, s.remote_port)
        self.skip_pinned[s.key] = pinned
        if not pinned:
            return None
        return Event(now, "skip", f"{program} {_fmt_key(s.key)}: not watched, remote address is "
                                  f"{kind}; only public internet addresses are measured")

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
