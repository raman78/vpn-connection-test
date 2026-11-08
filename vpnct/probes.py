"""Active probes: ping a target over a given path, and trace the route.

Passive counters only see connections that carry traffic; probes measure a
path on demand and work for any target, including one the user is not
connected to. Each result records which path it went over.

- ping: PING_COUNT echo requests PING_INTERVAL_S apart. Bound to an interface
  with `-I` when a specific path is wanted (e.g. the direct path while a VPN
  is up). A ping that cannot be sent at all (exit status 2: no such device,
  blocked by a kill switch's firewall, ...) is reported with its error, never
  as 100 % loss — "could not try" and "tried, nothing came back" are
  different findings.
- route: `tracepath -n` lists the hops on the default route; each hop that
  answered is then pinged, one at a time, so that the hop where loss starts is visible.
  tracepath cannot be bound to an interface, so a route always describes the
  path the system routes over at that moment.
"""

from __future__ import annotations

import re
import signal
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

PING_COUNT = 20
PING_INTERVAL_S = 0.2
PING_WAIT_S = 1
TRACE_MAX_HOPS = 20

_SUMMARY_RE = re.compile(r"(\d+) packets transmitted, (\d+) received")
_RTT_RE = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")
_HOP_RE = re.compile(r"^\s*(\d+)\??:\s+(\S+)")


@dataclass
class PingResult:
    target: str
    interface: str | None     # None: whatever the routing table picks
    sent: int
    received: int
    rtt_min: float | None
    rtt_avg: float | None
    rtt_max: float | None
    error: str | None = None

    @property
    def loss_pct(self) -> float | None:
        if self.error is not None or self.sent == 0:
            return None
        return round(100.0 * (self.sent - self.received) / self.sent, 1)


def exit_text(returncode: int) -> str:
    """'exit status N', or the signal that ended the program (e.g. Ctrl+C or
    the recorder stopping reaches the whole process group)."""
    if returncode < 0:
        try:
            return f"interrupted by {signal.Signals(-returncode).name}"
        except ValueError:
            return f"interrupted by signal {-returncode}"
    return f"exit status {returncode}"


def parse_ping(target: str, interface: str | None, returncode: int, stdout: str, stderr: str) -> PingResult:
    summary = _SUMMARY_RE.search(stdout)
    if returncode < 0:
        return PingResult(target, interface, 0, 0, None, None, None, error=exit_text(returncode))
    if returncode == 2 or summary is None:
        msg = (stderr.strip() or stdout.strip() or f"exit status {returncode}").splitlines()[-1]
        return PingResult(target, interface, 0, 0, None, None, None, error=msg)
    rtt = _RTT_RE.search(stdout)
    return PingResult(target, interface, int(summary.group(1)), int(summary.group(2)),
                      *(float(rtt.group(i)) for i in (1, 2, 3)) if rtt else (None, None, None))


def ping(target: str, interface: str | None = None, count: int = PING_COUNT) -> PingResult:
    cmd = ["ping", "-q", "-n", "-c", str(count), "-i", str(PING_INTERVAL_S), "-W", str(PING_WAIT_S)]
    if interface:
        cmd += ["-I", interface]
    cmd.append(target)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=count * PING_INTERVAL_S + PING_WAIT_S + 10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PingResult(target, interface, 0, 0, None, None, None, error=str(exc))
    return parse_ping(target, interface, r.returncode, r.stdout, r.stderr)


@dataclass
class Hop:
    number: int
    address: str | None       # None: the hop did not answer
    ping: PingResult | None = None


def parse_tracepath(stdout: str) -> list[Hop]:
    """One entry per hop number; the first answering address wins."""
    hops: dict[int, Hop] = {}
    for line in stdout.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        number, what = int(m.group(1)), m.group(2)
        if what == "[LOCALHOST]":
            continue
        address = None if what == "no" else what
        if number not in hops or (hops[number].address is None and address):
            hops[number] = Hop(number, address)
    return [hops[n] for n in sorted(hops)]


def trace_route(target: str, stop=None) -> tuple[list[Hop], str | None]:
    """Hops to the target, each answering hop pinged one at a time.
    `stop` (a threading.Event) ends the hop pings early when set."""
    try:
        r = subprocess.run(["tracepath", "-n", "-m", str(TRACE_MAX_HOPS), target],
                           capture_output=True, text=True, timeout=TRACE_MAX_HOPS * 4 + 10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)
    hops = parse_tracepath(r.stdout)
    if not hops:
        return [], (r.stderr.strip() or f"tracepath gave no hops ({exit_text(r.returncode)})")
    # One hop at a time: the route usually runs through a VPN tunnel when
    # one is up, and ICMP through a tunnel can be rate limited per client.
    for hop in hops:
        if stop is not None and stop.is_set():
            break
        if hop.address:
            hop.ping = ping(hop.address)
    return hops, None


def run_serial_per_path(jobs: list, path_of, run, stop=None) -> list:
    """Run `run(job)` for every job; jobs on the same path (`path_of(job)`)
    one after another, different paths in parallel. Results keep job order.

    ICMP through a VPN tunnel can be rate limited per client: measured
    2026-11-08 on a Proton free server, one ping stream at 5/s lost nothing,
    two at once lost 85 %, eight lost 95-100 %, while the direct path took
    thirty at once. Parallel pings over one tunnel would measure the probe,
    not the path.

    When `stop` (a threading.Event) is set, jobs not yet started are left
    out: their result stays None."""
    groups: dict[str, list[int]] = {}
    for i, job in enumerate(jobs):
        groups.setdefault(path_of(job), []).append(i)
    results: list = [None] * len(jobs)

    def work(indices: list[int]) -> None:
        for i in indices:
            if stop is not None and stop.is_set():
                return
            results[i] = run(jobs[i])

    with ThreadPoolExecutor(max_workers=max(1, len(groups))) as pool:
        list(pool.map(work, groups.values()))
    return results
