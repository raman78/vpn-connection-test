"""The recorder: samples connections every second, keeps the captures in
step with the watched connections, runs probes on a schedule, and writes
everything to the session.

Threads:
- the sampling loop (`run`, or a thread started by `start`): `ss`, interface
  listing, tracker, capture management, minute rows — once per SAMPLE_PERIOD_S;
- one probe thread, so a slow tracepath never delays a sample;
- per capture pipeline, the reader threads in `capture`.

`snapshot()` gives a consistent copy of the current state for a display;
`mark()` records "it stutters now" and runs an immediate probe round with
route traces.
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from dataclasses import dataclass, field

from . import __version__, interfaces, probes, ss
from .capture import CaptureManager, MinuteRow
from .monitor import MONITOR_MAX_TARGETS, MonitorManager, MonitorMinute
from .report import CAL_PING_BAD_PCT
from .interfaces import NetPath, PathMap
from .session import Session, iso
from .tracker import Delta, Event, Selection, Tracker

SAMPLE_PERIOD_S = 1.0
PROBE_PERIOD_S = 60.0
TRACE_PERIOD_S = 300.0
LOSS_TRACE_COOLDOWN_S = 120.0     # at most one loss-triggered trace per server this often
LOSS_TRACE_MIN_PINGS = 30         # a monitor minute needs this many pings to trigger one
NM_REFRESH_S = 5.0
DEFAULT_EXTRA_TARGETS = ("8.8.8.8", "1.1.1.1")
MAX_CONNECTION_TARGETS = 4


def _ep(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


@dataclass
class SecondPoint:
    """One watched connection during one second, for a live chart."""
    time: float
    program: str
    port: int
    path: str
    is_vpn: bool
    rtt_ms: float | None
    d_data_segs_in: int


@dataclass
class MinutePoint:
    """One captured connection during one minute, for a live chart."""
    minute: float
    program: str
    port: int
    host: str
    local_port: int
    path: str
    is_vpn: bool
    covered_s: float
    data_pkts: int
    lost_gaps: int
    retrans: int


@dataclass
class RouteResult:
    """One judged trace of a path to a server, for the display."""
    time: float
    target: str
    interface: str
    path: str
    trigger: str
    verdict: probes.RouteVerdict


@dataclass
class ConnView:
    program: str
    local: str
    remote: str
    path: str
    is_vpn: bool
    rtt_ms: float | None
    minrtt_ms: float | None
    segs_per_min: int
    captured: bool


@dataclass
class Snapshot:
    session_dir: str
    started: float
    now: float
    selection: str
    connections: list[ConnView]
    unwatched: int
    skipped_local: int
    captures: dict[str, int]
    last_minute: list[MinuteRow]
    last_probes: list[dict]
    recent_events: list[str]
    last_monitor: list[MonitorMinute]
    last_routes: list[RouteResult]
    paths: list[str] = field(default_factory=list)


class Engine:
    def __init__(self, selection: Selection, extra_targets: list[str] | None = None,
                 echo=print, session_root=None) -> None:
        self.selection = selection
        self.extra_targets = list(DEFAULT_EXTRA_TARGETS if extra_targets is None else extra_targets)
        self.echo = echo
        self.started = time.time()
        self.session = Session.create({
            "version": __version__,
            "started": iso(self.started),
            "host": socket.gethostname(),
            "selection": selection.describe(),
            "extra_targets": self.extra_targets,
            "sample_period_s": SAMPLE_PERIOD_S,
            "probe_period_s": PROBE_PERIOD_S,
            "trace_period_s": TRACE_PERIOD_S,
        }, self.started, session_root)
        self.tracker = Tracker(selection)
        self.captures = CaptureManager(self._capture_event)
        self.monitors = MonitorManager(self._capture_event)
        self._default_devs: set[str] = set()
        self._last_monitor: list[MonitorMinute] = []
        self._loss_trace_at: dict[str, float] = {}
        self._last_routes: dict[tuple[str, str], RouteResult] = {}
        self.paths = PathMap([], {})
        self._nm_names: dict[str, str] = {}
        self._nm_at = 0.0
        self._signature = None
        self._key_info: dict[tuple, tuple[str, NetPath]] = {}
        self._lock = threading.RLock()     # guards tracker, paths and display state
        self._stop = threading.Event()
        self._probe_requests: queue.Queue = queue.Queue()
        self._last_minute: list[MinuteRow] = []
        self._last_probes: list[dict] = []
        self._recent_events: list[str] = []
        self._updates: list = []          # SecondPoint / MinutePoint since the last drain
        self._thread: threading.Thread | None = None
        self._probe_thread: threading.Thread | None = None
        self._event(self.started, "start", f"session {self.session.dir} ({selection.describe()})")

    # ---- events -------------------------------------------------------------

    def _event(self, t: float, kind: str, text: str) -> None:
        line = self.session.event(t, kind, text)
        with self._lock:
            self._recent_events.append(line)
            del self._recent_events[:-50]
        self.echo(line)

    def _capture_event(self, kind: str, text: str) -> None:
        self._event(time.time(), kind, text)

    # ---- sampling -----------------------------------------------------------

    def _refresh_paths(self, now: float) -> None:
        if now - self._nm_at >= NM_REFRESH_S:
            self._nm_names = interfaces.read_nm_active()
            self._default_devs = interfaces.read_default_route_devices()
            self._nm_at = now
        itfs = interfaces.read_interfaces()
        candidate = PathMap(itfs, self._nm_names)
        if candidate.signature() != self._signature:
            # The device set changed: re-read NetworkManager's names now, so a
            # VPN server switch is labelled with the new server at once.
            self._nm_names = interfaces.read_nm_active()
            self._default_devs = interfaces.read_default_route_devices()
            self._nm_at = now
            candidate = PathMap(itfs, self._nm_names)
            if self._signature is not None:
                self._event(now, "interfaces", ", ".join(
                    f"{i.name}({'vpn' if i.is_vpn else i.kind}, idx {i.index}"
                    f"{', ' + self._nm_names[i.name] if i.name in self._nm_names else ''})"
                    for i in itfs if i.name != "lo"))
            self._signature = candidate.signature()
        self.paths = candidate

    def step(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        sockets = ss.read_sockets()
        with self._lock:
            self._refresh_paths(now)
            deltas, events = self.tracker.update(sockets, self.paths, now)
            for t in self.tracker.watched():
                self._key_info[t.last.key] = (t.program, t.path)
            captured = self.tracker.select_captured(now)
            wanted = {t.last.key: t.path.interface for t in captured}
            # Direct-path monitor: the busiest captured connections' servers,
            # pinged through every direct interface, whichever path the
            # traffic itself is on.
            hosts: list[str] = []
            for t in sorted(captured, key=lambda t: t.rate(now), reverse=True):
                if t.last.remote_ip not in hosts and len(hosts) < MONITOR_MAX_TARGETS:
                    hosts.append(t.last.remote_ip)
            monitor_wanted = {(h, d.name) for h in hosts
                              for d in self.paths.direct_interfaces(self._default_devs)}
        for e in events:
            self._event(e.time, e.kind, e.text)
        points = []
        for d in deltas:
            self._write_sample(d)
            points.append(SecondPoint(d.time, d.program, d.key[3], d.path.label, d.path.is_vpn,
                                      d.rtt_ms, d.d_data_segs_in))
        with self._lock:
            self._updates += points
        self.captures.update(wanted, now)
        self._write_minutes(self.captures.take_rows(now))
        self.monitors.update(monitor_wanted, now)
        self._write_monitor(self.monitors.take_rows(now))

    def _write_monitor(self, rows: list[MonitorMinute]) -> None:
        if not rows:
            return
        for r in rows:
            self.session.write("monitor.csv", {
                "minute": iso(r.minute), "target": r.target, "interface": r.interface,
                "path": self.paths.path_for_interface(r.interface).label,
                "covered_s": r.covered_s, "sent": r.sent, "received": r.received,
                "loss_pct": r.loss_pct, "rtt_p50": r.rtt_p50, "rtt_max": r.rtt_max,
            })
        with self._lock:
            self._last_monitor = rows
            self._updates += rows
        # A minute in which the direct path lost pings: trace it now, while
        # the loss is likely still there, to see where it starts.
        now = time.time()
        for r in rows:
            if (r.sent >= LOSS_TRACE_MIN_PINGS and r.loss_pct is not None
                    and r.loss_pct >= CAL_PING_BAD_PCT
                    and now - self._loss_trace_at.get(r.target, 0) >= LOSS_TRACE_COOLDOWN_S):
                self._loss_trace_at[r.target] = now
                self._event(now, "watch-loss", f"ping {r.target} via {r.interface} lost "
                                               f"{r.loss_pct:.0f}% in the last minute; tracing the route")
                self._probe_requests.put(("watch-loss", r.target))

    def _write_sample(self, d: Delta) -> None:
        lip, lport, rip, rport = d.key
        self.session.write("samples.csv", {
            "time": iso(d.time), "program": d.program, "local": _ep(lip, lport),
            "remote": _ep(rip, rport), "path": d.path.label,
            "rtt_ms": d.rtt_ms, "rttvar_ms": d.rttvar_ms, "minrtt_ms": d.minrtt_ms,
            "d_bytes_in": d.d_bytes_in, "d_data_segs_in": d.d_data_segs_in,
            "d_retrans": d.d_retrans, "d_ooopack": d.d_ooopack,
        })

    def _write_minutes(self, rows: list[MinuteRow]) -> None:
        if not rows:
            return
        for r in rows:
            lip, lport, rip, rport = r.key
            program, path = self._key_info.get(r.key, ("?", self.paths.path_for_interface(r.interface)))
            self.session.write("losses.csv", {
                "minute": iso(r.minute), "interface": r.interface, "path": path.label,
                "program": program, "local": _ep(lip, lport), "remote": _ep(rip, rport),
                "covered_s": r.covered_s, "data_pkts": r.data_pkts,
                "lost_gaps": r.lost_gaps, "retrans": r.retrans,
            })
        points = []
        for r in rows:
            program, path = self._key_info.get(r.key, ("?", self.paths.path_for_interface(r.interface)))
            points.append(MinutePoint(r.minute, program, r.key[3], r.key[2], r.key[1], path.label, path.is_vpn,
                                      r.covered_s, r.data_pkts, r.lost_gaps, r.retrans))
        with self._lock:
            self._last_minute = rows
            self._updates += points

    # ---- probes -------------------------------------------------------------

    def _probe_targets(self) -> list[tuple[str, str]]:
        """Remote hosts of the busiest captured connections (watched ones if
        none is captured yet), at most MAX_CONNECTION_TARGETS, then extras."""
        targets: list[tuple[str, str]] = []
        now = time.time()
        with self._lock:
            pool = [t for t in self.tracker.watched() if t.captured] or self.tracker.watched()
            pool = sorted(pool, key=lambda t: t.rate(now), reverse=True)
        for t in pool:
            item = (t.last.remote_ip, "connection")
            if item not in targets and len(targets) < MAX_CONNECTION_TARGETS:
                targets.append(item)
        for x in self.extra_targets:
            if all(x != tgt for tgt, _ in targets):
                targets.append((x, "extra"))
        return targets

    def _probe_round(self, with_traces: bool, reason: str) -> None:
        paths = self.paths
        jobs: list[tuple[str, str, str | None]] = []      # target, role, bind interface
        targets = self._probe_targets()
        for target, role in targets:
            jobs.append((target, role, None))
        vpns = paths.vpn_interfaces()
        if vpns:
            # With a VPN up, also try the direct path to the same targets:
            # this is what the comparison needs, and if a kill switch blocks
            # it, the error says so in the log.
            for direct in paths.direct_interfaces(interfaces.read_default_route_devices()):
                for target, role in targets:
                    jobs.append((target, role, direct.name))
            for v in vpns:
                gw = interfaces.read_vpn_gateway(v.name)
                if gw:
                    jobs.append((gw, f"vpn-gateway({v.name})", v.name))
                else:
                    self._event(time.time(), "probe-skip",
                                f"{v.name}: no gateway or DNS server known to NetworkManager; "
                                f"tunnel's first hop not probed")
        # Pings over one path one at a time (see probes.run_serial_per_path).
        now = time.time()
        pings = probes.run_serial_per_path(
            jobs, lambda j: j[2] or interfaces.route_interface(j[0]) or "?",
            lambda j: probes.ping(j[0], j[2]), stop=self._stop)
        # Pings skipped because recording stopped are not results; leave them out.
        results = [(j, r) for j, r in zip(jobs, pings) if r is not None]
        rows = []
        for (target, role, bind), res in results:
            itf = bind or interfaces.route_interface(target)
            path = paths.path_for_interface(itf) if itf else NetPath("?", False, None)
            row = {
                "time": iso(now), "target": target, "role": role, "bound": "yes" if bind else "no",
                "interface": itf or "?", "path": path.label, "sent": res.sent,
                "received": res.received, "loss_pct": res.loss_pct, "rtt_min": res.rtt_min,
                "rtt_avg": res.rtt_avg, "rtt_max": res.rtt_max, "error": res.error or "",
            }
            self.session.write("probes.csv", row)
            rows.append(row)
            if res.error:
                self._event(time.time(), "probe-error", f"ping {target} via {itf or '?'}: {res.error}")
        with self._lock:
            self._last_probes = rows
        if with_traces:
            for target, role in targets:
                if self._stop.is_set():
                    break
                if role != "connection" and reason == "schedule":
                    continue
                self._trace_paths(target, reason)

    def _trace_paths(self, target: str, trigger: str) -> None:
        """The direct path through every direct interface (ping with a TTL,
        so it works while a VPN is up); with a VPN up, also the route the
        system uses, which is the tunnel (tracepath)."""
        directs = self.paths.direct_interfaces(interfaces.read_default_route_devices())
        for d in directs:
            if self._stop.is_set():
                return
            self._trace_direct(target, d.name, trigger)
        if self.paths.vpn_interfaces() or not directs:
            self._trace(target)

    def _trace_direct(self, target: str, itf: str, trigger: str) -> None:
        now = time.time()
        path = self.paths.path_for_interface(itf).label
        hops, error = probes.trace_via(target, itf, stop=self._stop)
        if error == "stopped":
            return
        for h in hops:
            pr = h.ping
            self.session.write("hops.csv", {
                "time": iso(now), "target": target, "path": path, "hop": h.number,
                "address": h.address or "", "sent": pr.sent if pr else "",
                "received": pr.received if pr else "", "loss_pct": pr.loss_pct if pr else "",
                "rtt_avg": pr.rtt_avg if pr else "",
                "error": (pr.error or "") if pr else "no reply to the TTL probe"})
        verdict = probes.classify_route(hops, error, probes.reverse_name)
        self.session.write("routes.csv", {
            "time": iso(now), "target": target, "interface": itf, "path": path, "trigger": trigger,
            "verdict": verdict.kind, "start_hop": verdict.start_hop or "",
            "start_address": verdict.start_address or "",
            "target_loss_pct": verdict.target_loss if verdict.target_loss is not None else "",
            "hops": len(hops), "text": verdict.text})
        self._event(time.time(), "route", f"{target} via {itf} ({trigger}): {verdict.text}")
        result = RouteResult(now, target, itf, path, trigger, verdict)
        with self._lock:
            self._last_routes[(target, itf)] = result
            self._updates.append(result)

    def _trace(self, target: str) -> None:
        now = time.time()
        itf = interfaces.route_interface(target)
        path = self.paths.path_for_interface(itf).label if itf else "?"
        hops, error = probes.trace_route(target, stop=self._stop)
        if error:
            self.session.write("hops.csv", {"time": iso(now), "target": target, "path": path,
                                            "hop": "", "address": "", "error": error})
            self._event(time.time(), "trace-error", f"tracepath {target}: {error}")
            return
        for h in hops:
            p = h.ping
            self.session.write("hops.csv", {
                "time": iso(now), "target": target, "path": path, "hop": h.number,
                "address": h.address or "", "sent": p.sent if p else "",
                "received": p.received if p else "",
                "loss_pct": p.loss_pct if p else "", "rtt_avg": p.rtt_avg if p else "",
                "error": (p.error or "") if p else "no reply to tracepath",
            })

    def _probe_loop(self) -> None:
        next_probe = time.time() + 5          # first round once connections are known
        next_trace = next_probe
        while not self._stop.is_set():
            try:
                reason = self._probe_requests.get(timeout=max(0.0, next_probe - time.time()))
            except queue.Empty:
                reason = "schedule"
            if self._stop.is_set():
                break
            now = time.time()
            if isinstance(reason, tuple):            # ("watch-loss", target): that route only
                try:
                    self._trace_paths(reason[1], reason[0])
                except Exception as exc:
                    self._event(time.time(), "trace-error", f"route of {reason[1]} failed: {exc!r}")
                continue
            traces = reason != "schedule" or now >= next_trace
            try:
                self._probe_round(traces, reason)
            except Exception as exc:          # a failed round must not end probing
                self._event(time.time(), "probe-error", f"probe round failed: {exc!r}")
            if reason == "schedule":
                next_probe = now + PROBE_PERIOD_S
            if traces and reason == "schedule":
                next_trace = now + TRACE_PERIOD_S

    # ---- control ------------------------------------------------------------

    def mark(self, note: str = "") -> None:
        self._event(time.time(), "mark", note or "it stutters now")
        self._probe_requests.put("mark")

    def run(self) -> None:
        """Sample until stop() is called (or KeyboardInterrupt)."""
        self._probe_thread = threading.Thread(target=self._probe_loop, daemon=True)
        self._probe_thread.start()
        next_t = time.time()
        try:
            while not self._stop.is_set():
                try:
                    self.step()
                except Exception as exc:      # keep recording; say what failed
                    self._event(time.time(), "error", f"sampling failed: {exc!r}")
                next_t += SAMPLE_PERIOD_S
                delay = next_t - time.time()
                if delay < 0:
                    next_t = time.time()
                    delay = 0
                self._stop.wait(delay)
        finally:
            self._finish()

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    STOP_TIMEOUT_S = 60

    def stop(self) -> bool:
        """Stop and wait until the session is closed (its `stop` event
        written). Probes stop between pings, so this takes about one ping
        (~5 s) plus the capture shutdown. False if it did not finish in time."""
        self._stop.set()
        self._probe_requests.put("stop")
        if self._thread is not None:
            self._thread.join(timeout=self.STOP_TIMEOUT_S)
            return not self._thread.is_alive()
        return True

    def _finish(self) -> None:
        self._stop.set()
        self._probe_requests.put("stop")
        self._write_minutes(self.captures.stop_all(time.time()))
        self._write_monitor(self.monitors.stop_all(time.time()))
        if self._probe_thread is not None:
            self._probe_thread.join(timeout=30)
        self._event(time.time(), "stop", f"session {self.session.dir} closed")
        self.session.close()

    def drain_updates(self) -> list:
        """New SecondPoints, MinutePoints and MonitorMinutes since the
        previous call (single consumer)."""
        with self._lock:
            out, self._updates = self._updates, []
        return out

    def snapshot(self) -> Snapshot:
        now = time.time()
        with self._lock:
            return self._snapshot(now)

    def _snapshot(self, now: float) -> Snapshot:
        captured = self.captures.captured()
        conns = [ConnView(t.program, _ep(t.last.local_ip, t.last.local_port),
                          _ep(t.last.remote_ip, t.last.remote_port), t.path.label, t.path.is_vpn,
                          t.last.rtt_ms, t.last.minrtt_ms, t.rate(now), t.last.key in captured)
                 for t in self.tracker.watched()]
        return Snapshot(str(self.session.dir), self.started, now, self.selection.describe(),
                        conns, self.tracker.unwatched_count(), self.tracker.skipped_local,
                        self.captures.status(), list(self._last_minute),
                        list(self._last_probes), list(self._recent_events[-10:]),
                        list(self._last_monitor), list(self._last_routes.values()),
                        sorted({c.path for c in conns}))
