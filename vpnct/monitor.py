"""Continuous watch of the direct path: one ping per second per target, sent
through each direct interface, for the whole session.

Why: comparing paths measured at different times compares the times, not
the paths — a route's bad periods come and go within minutes. While the
traffic runs through a VPN, this monitor still says, minute by minute,
whether the direct path to the same server is losing packets right now; and
while the traffic runs directly, it records ping loss next to the
connection's real TCP loss, so the report can check how well ping predicts
TCP loss (`report.calibrate`) before anything relies on it.

A direct interface is not rate limited the way a VPN tunnel can be (§5 of
docs/ARCHITECTURE.md), so a steady 1/s stream measures the path, not the
probe.

Per target, interface and minute (`monitor.csv`): pings sent in that minute,
replies, loss %, RTT median and maximum, and `covered_s`. A ping belongs to
the minute it was *sent* in: a reply's send time is its arrival minus its
RTT, a miss's is when ping gave up on it minus the wait (`-W`). A reply
that arrives after its miss was reported turns the miss back into a reply.
"""

from __future__ import annotations

import re
import statistics
import subprocess
import threading
from dataclasses import dataclass, field

MONITOR_INTERVAL_S = 1
MONITOR_WAIT_S = 1
MONITOR_MAX_TARGETS = 2
FLUSH_DELAY_S = MONITOR_WAIT_S + 3
RETRY_AFTER_S = 10.0

_REPLY_RE = re.compile(r"^\[(\d+\.\d+)\] \d+ bytes from .*icmp_seq=(\d+) .*time=([\d.]+) ms")
_MISS_RE = re.compile(r"^\[(\d+\.\d+)\] no answer yet for icmp_seq=(\d+)")


def ping_command(target: str, interface: str) -> list[str]:
    return ["ping", "-D", "-O", "-n", "-i", str(MONITOR_INTERVAL_S), "-W", str(MONITOR_WAIT_S),
            "-I", interface, target]


@dataclass
class MonitorMinute:
    minute: int
    target: str
    interface: str
    covered_s: float
    sent: int
    received: int
    rtt_p50: float | None
    rtt_max: float | None

    @property
    def loss_pct(self) -> float | None:
        return round(100.0 * (self.sent - self.received) / self.sent, 1) if self.sent else None


@dataclass
class Monitor:
    target: str
    interface: str
    started: float
    stopped: float | None = None
    proc: subprocess.Popen | None = None
    reader: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    buckets: dict = field(default_factory=dict)     # minute -> {"sent", "rtts"}
    missed: dict = field(default_factory=dict)      # seq -> minute it was counted lost in
    stderr: str = ""
    flushed_until: int = 0

    def _bucket(self, minute: int) -> dict:
        return self.buckets.setdefault(minute, {"sent": 0, "rtts": []})

    def feed(self, line: str) -> None:
        m = _REPLY_RE.match(line)
        if m:
            t, seq, rtt = float(m.group(1)), int(m.group(2)), float(m.group(3))
            with self.lock:
                if seq in self.missed:                 # late reply: undo the miss
                    minute = self.missed.pop(seq)
                    b = self._bucket(minute)
                    b["rtts"].append(rtt)
                    return
                b = self._bucket(int((t - rtt / 1000) // 60) * 60)
                b["sent"] += 1
                b["rtts"].append(rtt)
            return
        m = _MISS_RE.match(line)
        if m:
            t, seq = float(m.group(1)), int(m.group(2))
            minute = int((t - MONITOR_WAIT_S) // 60) * 60
            with self.lock:
                self._bucket(minute)["sent"] += 1
                self.missed[seq] = minute

    def take_rows(self, now: float, final: bool = False) -> list[MonitorMinute]:
        end = self.stopped if self.stopped is not None else now
        minute = max(self.flushed_until, int(self.started // 60) * 60)
        last_open = int((now - FLUSH_DELAY_S) // 60) * 60
        rows = []
        with self.lock:
            while minute < last_open or (final and minute <= end):
                covered = max(0.0, min(minute + 60, end) - max(minute, self.started))
                b = self.buckets.pop(minute, {"sent": 0, "rtts": []})
                if covered > 0:
                    rtts = b["rtts"]
                    rows.append(MonitorMinute(
                        minute, self.target, self.interface, round(covered, 1), b["sent"], len(rtts),
                        round(statistics.median(rtts), 2) if rtts else None,
                        max(rtts) if rtts else None))
                minute += 60
            self.flushed_until = minute
            # A reply later than FLUSH_DELAY_S for an already written minute
            # cannot change that row any more; drop what it would leave behind.
            self.missed = {s: m for s, m in self.missed.items() if m >= minute}
            for old in [m for m in self.buckets if m < minute]:
                del self.buckets[old]
        return rows

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


class MonitorManager:
    """Keeps one continuous ping per (target, direct interface)."""

    def __init__(self, on_event) -> None:
        self.on_event = on_event
        self.active: dict[tuple[str, str], Monitor] = {}
        self.stopped: list[Monitor] = []
        self._last_failure: dict[tuple[str, str], float] = {}

    def update(self, wanted: set[tuple[str, str]], now: float) -> None:
        for key, mon in list(self.active.items()):
            if not mon.running:
                self._stop(mon, now, f"ping ended: {mon.stderr.strip() or 'no message'}")
                self._last_failure[key] = now
            elif key not in wanted:
                self._stop(mon, now, "target no longer monitored")
        for key in wanted:
            if key in self.active or now - self._last_failure.get(key, 0) < RETRY_AFTER_S:
                continue
            self._start(key, now)

    def _start(self, key: tuple[str, str], now: float) -> None:
        target, itf = key
        mon = Monitor(target, itf, started=now)
        try:
            mon.proc = subprocess.Popen(ping_command(target, itf), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            self.on_event("monitor-error", f"ping {target} via {itf}: {exc}")
            self._last_failure[key] = now
            return
        mon.reader = threading.Thread(target=self._read, args=(mon,), daemon=True)
        mon.reader.start()
        self.active[key] = mon
        self.on_event("monitor-start", f"ping {target} via {itf} every {MONITOR_INTERVAL_S}s")

    @staticmethod
    def _read(mon: Monitor) -> None:
        for line in mon.proc.stdout:
            mon.feed(line)
        mon.stderr = mon.proc.stderr.read()

    def _stop(self, mon: Monitor, now: float, reason: str) -> None:
        if mon.proc.poll() is None:
            mon.proc.terminate()
            try:
                mon.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                mon.proc.kill()
                mon.proc.wait()
        if mon.reader is not None:
            mon.reader.join(timeout=3)
        mon.stopped = now
        del self.active[(mon.target, mon.interface)]
        self.stopped.append(mon)
        self.on_event("monitor-stop", f"ping {mon.target} via {mon.interface}: {reason}")

    def take_rows(self, now: float) -> list[MonitorMinute]:
        rows = []
        for mon in self.active.values():
            rows += mon.take_rows(now)
        for mon in list(self.stopped):
            rows += mon.take_rows(now, final=True)
            self.stopped.remove(mon)
        return rows

    def stop_all(self, now: float) -> list[MonitorMinute]:
        for mon in list(self.active.values()):
            self._stop(mon, now, "recording stopped")
        return self.take_rows(now)
