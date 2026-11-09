"""Summarise one or more sessions: each path side by side.

Connections are grouped by (program, remote port, path). The remote port
stands for the service — a game talks to several servers for different
purposes, and its main server's numbers must not be averaged with a
telemetry endpoint's. The path is the interface plus the VPN server name,
so every VPN server is its own column.

Numbers and where they come from:
- RTT p50/p95: kernel RTT (`samples.csv`), only seconds in which data arrived
  (the kernel updates RTT only on traffic);
- loss: retransmissions by the remote end per captured data packet
  (`losses.csv`), and per minute of capture; gaps alongside;
- probes and hops: ping results per target and path (`probes.csv`,
  `hops.csv`);
- direct-path monitor (`monitor.csv`): per target and minute, ping loss on
  the direct path — also in the minutes the traffic itself used a VPN;
- calibration: in minutes where the traffic used the direct path, ping loss
  of the monitor next to the connection's TCP loss to the same server, to
  establish whether ping can stand in for TCP loss at all. A hop that drops pings while later hops do not is rate
  limiting its own replies, not losing traffic — read hop loss together with
  the hops after it.
"""

from __future__ import annotations

import csv
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def _f(value: str) -> float | None:
    return float(value) if value not in ("", None) else None


def _port(endpoint: str) -> str:
    return endpoint.rpartition(":")[2]


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


class MinuteAgg:
    """One minute of one or more connections, built from losses rows.

    A connection's capture can restart within a minute, leaving one row per
    pipeline; those rows do not overlap, so a connection's coverage is their
    sum. The minute is as well covered as its least covered connection."""

    __slots__ = ("data", "retrans", "_cover")

    def __init__(self) -> None:
        self.data = 0
        self.retrans = 0
        self._cover: dict = {}

    def add(self, connection, data: int, retrans: int, covered_s: float) -> None:
        self.data += data
        self.retrans += retrans
        self._cover[connection] = self._cover.get(connection, 0.0) + covered_s

    @property
    def cover(self) -> float:
        return min((min(60.0, c) for c in self._cover.values()), default=0.0)

    @property
    def judged(self) -> bool:
        return self.data >= CAL_MIN_DATA and self.cover >= CAL_MIN_COVER_S

    @property
    def bad(self) -> bool:
        return self.judged and 100.0 * self.retrans / self.data >= CAL_TCP_BAD_PCT


@dataclass
class Group:
    """Times are wall-clock: several parallel connections in one group count
    each second (and each captured minute) once, not once per connection."""
    stamps: set = field(default_factory=set)            # (session, sample time)
    coverage: dict = field(default_factory=dict)        # (session, minute, interface) -> covered_s
    seconds_with_data: int = 0
    rtts: list = field(default_factory=list)
    connections: set = field(default_factory=set)
    data_pkts: int = 0
    lost_gaps: int = 0
    retrans: int = 0
    worst_minute_pct: float = 0.0
    minute_tcp: dict = field(default_factory=dict)      # (session, minute) -> MinuteAgg

    @property
    def judged_minutes(self) -> int:
        """Minutes with enough captured data to call them good or bad."""
        return sum(m.judged for m in self.minute_tcp.values())

    @property
    def bad_minutes(self) -> int:
        return sum(m.bad for m in self.minute_tcp.values())

    @property
    def judged_sessions(self) -> set[str]:
        return {s for (s, _), m in self.minute_tcp.items() if m.judged}

    @property
    def hosts(self) -> set[str]:
        return {_host(remote) for _, _, remote in self.connections}

    @property
    def sessions(self) -> set[str]:
        return {s for s, _ in self.minute_tcp} | {s for s, _ in self.stamps}

    @property
    def seconds(self) -> int:
        return len(self.stamps)

    @property
    def covered_s(self) -> float:
        return sum(self.coverage.values())


@dataclass
class ProbeGroup:
    rounds: int = 0
    losses: list = field(default_factory=list)
    rtts: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    replies: int = 0          # rounds in which at least one reply came back

    @property
    def never_answers(self) -> bool:
        """Every completed round got nothing back: the target does not answer
        ping at all. That is not packet loss and must not read as 100 %."""
        return bool(self.losses) and self.replies == 0


CAL_TCP_BAD_PCT = 0.5        # a minute with at least this TCP loss is "bad"
CAL_PING_BAD_PCT = 3.0       # ping loss counted as "the path is losing" (2+ of 60)
CAL_MIN_DATA = 100           # data packets a minute needs to judge its TCP loss
CAL_MIN_PINGS = 50
CAL_MIN_COVER_S = 55
CAL_MIN_BAD = 5              # bad TCP minutes needed before a verdict on ping
CAL_SENSITIVITY = 0.8        # share of bad TCP minutes ping must flag
CAL_PRECISION = 0.7          # share of ping alarms that must be real


@dataclass
class MonitorGroup:
    minutes: int = 0
    bad: int = 0
    losses: list = field(default_factory=list)
    rtts: list = field(default_factory=list)
    minutes_on_vpn: int = 0      # traffic to this server used a VPN in that minute
    bad_on_vpn: int = 0
    sessions_on_vpn: set = field(default_factory=set)
    short: int = 0               # minutes not fully covered or with too few pings


@dataclass
class Calibration:
    pairs: int = 0
    tcp_bad: int = 0
    ping_bad: int = 0
    both: int = 0

    @property
    def sensitivity(self) -> float | None:
        return self.both / self.tcp_bad if self.tcp_bad else None

    @property
    def precision(self) -> float | None:
        return self.both / self.ping_bad if self.ping_bad else None

    @property
    def status(self) -> str:
        """'confirmed', 'refuted' or 'unconfirmed' — ping as a stand-in for TCP loss."""
        if self.tcp_bad < CAL_MIN_BAD:
            return "unconfirmed"
        ok = (self.sensitivity >= CAL_SENSITIVITY
              and self.precision is not None and self.precision >= CAL_PRECISION)
        return "confirmed" if ok else "refuted"

    def describe(self) -> str:
        head = (f"{self.pairs} paired minute(s) on the direct path; TCP lost >= "
                f"{CAL_TCP_BAD_PCT}% in {self.tcp_bad}, ping lost >= {CAL_PING_BAD_PCT:.0f}% in "
                f"{self.ping_bad}, both in {self.both}")
        if self.status == "unconfirmed":
            return (f"{head}. UNCONFIRMED: ping can stand in for TCP loss only after "
                    f"{CAL_MIN_BAD} bad TCP minutes have been seen ({self.tcp_bad} so far)")
        sens = f"{100 * self.sensitivity:.0f}%"
        prec = f"{100 * self.precision:.0f}%" if self.precision is not None else "-"
        word = "CONFIRMED" if self.status == "confirmed" else "NOT RELIABLE"
        return (f"{head}. {word}: ping flagged {sens} of the bad TCP minutes "
                f"(need {100 * CAL_SENSITIVITY:.0f}%), and {prec} of its alarms were real "
                f"(need {100 * CAL_PRECISION:.0f}%)")


def _host(endpoint: str) -> str:
    return endpoint.rpartition(":")[0].strip("[]")


def summarise(session_dirs: list[Path]) -> dict:
    groups: dict[tuple, Group] = defaultdict(Group)
    probe_groups: dict[tuple, ProbeGroup] = defaultdict(ProbeGroup)
    hop_groups: dict[tuple, ProbeGroup] = defaultdict(ProbeGroup)
    marks: list[str] = []
    monitor_groups: dict[tuple, MonitorGroup] = defaultdict(MonitorGroup)
    calibration = Calibration()
    for d in session_dirs:
        # TCP per (minute, interface, server host), and which minutes each
        # server's traffic used a VPN, for the monitor and the calibration.
        tcp: dict[tuple, MinuteAgg] = defaultdict(MinuteAgg)
        on_vpn: set[tuple] = set()
        for r in _read(d / "losses.csv"):
            k = (r["minute"], r["interface"], _host(r["remote"]))
            tcp[k].add(r["local"], int(r["data_pkts"]), int(r["retrans"]), float(r["covered_s"]))
            if r["path"].startswith("vpn:") and int(r["data_pkts"]) > 0:
                on_vpn.add((r["minute"], _host(r["remote"])))
        for r in _read(d / "monitor.csv"):
            mg = monitor_groups[(r["target"], r["path"])]
            sent, cover = int(r["sent"] or 0), float(r["covered_s"] or 0)
            if sent < CAL_MIN_PINGS or cover < CAL_MIN_COVER_S:
                mg.short += 1
                continue
            loss = float(r["loss_pct"])
            bad = loss >= CAL_PING_BAD_PCT
            mg.minutes += 1
            mg.bad += bad
            mg.losses.append(loss)
            if _f(r["rtt_p50"]) is not None:
                mg.rtts.append(float(r["rtt_p50"]))
            if (r["minute"], r["target"]) in on_vpn:
                mg.minutes_on_vpn += 1
                mg.bad_on_vpn += bad
                mg.sessions_on_vpn.add(d.name)
            t = tcp.get((r["minute"], r["interface"], r["target"]))
            if t is not None and t.judged:
                tcp_bad = t.bad
                calibration.pairs += 1
                calibration.tcp_bad += tcp_bad
                calibration.ping_bad += bad
                calibration.both += tcp_bad and bad
        for r in _read(d / "samples.csv"):
            g = groups[(r["program"], _port(r["remote"]), r["path"])]
            g.stamps.add((d.name, r["time"]))
            g.connections.add((d.name, r["local"], r["remote"]))
            if int(r["d_data_segs_in"] or 0) > 0:
                g.seconds_with_data += 1
                rtt = _f(r["rtt_ms"])
                if rtt is not None:
                    g.rtts.append(rtt)
        for r in _read(d / "losses.csv"):
            g = groups[(r["program"], _port(r["remote"]), r["path"])]
            ck = (d.name, r["minute"], r["interface"])
            g.coverage[ck] = max(g.coverage.get(ck, 0.0), float(r["covered_s"]))
            data, gaps, rtx = int(r["data_pkts"]), int(r["lost_gaps"]), int(r["retrans"])
            g.data_pkts += data
            g.lost_gaps += gaps
            g.retrans += rtx
            if data >= 50:
                g.worst_minute_pct = max(g.worst_minute_pct, 100.0 * rtx / data)
            g.minute_tcp.setdefault((d.name, r["minute"]), MinuteAgg()).add(
                r["local"], data, rtx, float(r["covered_s"]))
            g.connections.add((d.name, r["local"], r["remote"]))
        for r in _read(d / "probes.csv"):
            key = (r["target"], r["role"], r["path"], r["bound"])
            pg = probe_groups[key]
            pg.rounds += 1
            if r["error"]:
                pg.errors.append(r["error"])
            else:
                if _f(r["loss_pct"]) is not None:
                    pg.losses.append(float(r["loss_pct"]))
                    pg.replies += int(r["received"] or 0) > 0
                if _f(r["rtt_avg"]) is not None:
                    pg.rtts.append(float(r["rtt_avg"]))
        for r in _read(d / "hops.csv"):
            if not r["hop"]:
                continue
            hg = hop_groups[(r["path"], r["target"], int(r["hop"]), r["address"])]
            hg.rounds += 1
            if r["error"]:
                hg.errors.append(r["error"])
            elif _f(r["loss_pct"]) is not None:
                hg.losses.append(float(r["loss_pct"]))
                hg.replies += int(r["received"] or 0) > 0
                if _f(r["rtt_avg"]) is not None:
                    hg.rtts.append(float(r["rtt_avg"]))
        events = d / "events.log"
        if events.exists():
            marks += [line.rstrip() for line in events.read_text().splitlines() if " mark " in line]
    return {"groups": groups, "probes": probe_groups, "hops": hop_groups, "marks": marks,
            "monitor": monitor_groups, "calibration": calibration}


MIN_MINUTES_FOR_VERDICT = 5.0
LOSS_NOTICEABLE_PCT = 0.5


def loss_pct(g: Group) -> float | None:
    return 100.0 * g.retrans / g.data_pkts if g.data_pkts else None


def compare_paths(paths: dict[str, Group]) -> list[str]:
    """Plain statements comparing each VPN path of one service with its
    direct path(s). Says "not enough data" rather than judging a path that
    was captured for less than MIN_MINUTES_FOR_VERDICT minutes."""
    direct = {p: g for p, g in paths.items() if p.startswith("direct:")}
    vpn = {p: g for p, g in paths.items() if p.startswith("vpn:")}
    lines = []
    short = [p for p, g in paths.items() if g.covered_s / 60 < MIN_MINUTES_FOR_VERDICT]
    for p in short:
        lines.append(f"{p}: not enough data yet ({paths[p].covered_s / 60:.1f} of "
                     f"{MIN_MINUTES_FOR_VERDICT:.0f} captured minutes)")
    if not direct or not vpn:
        missing = "direct" if not direct else "VPN"
        lines.append(f"no {missing} path recorded for this service yet; nothing to compare")
        return lines
    for dp, dg in direct.items():
        for vp, vg in vpn.items():
            if dp in short or vp in short:
                continue
            dl, vl = loss_pct(dg), loss_pct(vg)
            drtt, vrtt = percentile(dg.rtts, .5), percentile(vg.rtts, .5)
            extra = (f"{vrtt - drtt:+.0f} ms" if drtt is not None and vrtt is not None else "unknown")
            if dl is None or vl is None:
                lines.append(f"{vp} vs {dp}: no captured data packets on one side")
            elif dl >= LOSS_NOTICEABLE_PCT and vl < dl / 4:
                lines.append(f"{vp} vs {dp}: VPN reduces loss {dl:.2f}% -> {vl:.2f}%, RTT {extra}")
            elif dl < LOSS_NOTICEABLE_PCT and vl < LOSS_NOTICEABLE_PCT:
                lines.append(f"{vp} vs {dp}: little loss on either ({dl:.2f}% / {vl:.2f}%); "
                             f"VPN costs RTT {extra} for no gain in this data")
            elif vl > dl:
                lines.append(f"{vp} vs {dp}: VPN loses more ({vl:.2f}% vs {dl:.2f}%), RTT {extra}")
            else:
                lines.append(f"{vp} vs {dp}: loss {dl:.2f}% direct, {vl:.2f}% VPN, RTT {extra}")
    return lines


def by_service(groups: dict) -> dict[tuple[str, str], dict[str, Group]]:
    """(program, port) -> {path: Group}."""
    out: dict[tuple[str, str], dict[str, Group]] = defaultdict(dict)
    for (program, port, path), g in groups.items():
        out[(program, port)][path] = g
    return out


def _n(v: float | None, fmt: str = "{:.1f}") -> str:
    return "-" if v is None else fmt.format(v)


def format_report(summary: dict) -> str:
    out = []
    groups = summary["groups"]
    out.append("CONNECTIONS (program, remote port, path)")
    header = (f"{'program':<20} {'port':>6}  {'path':<36} {'time':>7} {'conns':>5} "
              f"{'RTT p50':>8} {'RTT p95':>8} {'captured':>9} {'data pkts':>9} "
              f"{'retrans':>7} {'loss %':>7} {'rtx/min':>7} {'gaps':>5} {'worst min %':>11}")
    out.append(header)
    out.append("-" * len(header))
    for (program, port, path), g in sorted(groups.items()):
        minutes = g.covered_s / 60
        loss = 100.0 * g.retrans / g.data_pkts if g.data_pkts else None
        per_min = g.retrans / minutes if minutes else None
        out.append(
            f"{program[:20]:<20} {port:>6}  {path[:36]:<36} {g.seconds / 60:>6.1f}m {len(g.connections):>5} "
            f"{_n(percentile(g.rtts, .5)):>8} {_n(percentile(g.rtts, .95)):>8} "
            f"{minutes:>8.1f}m {g.data_pkts:>9} {g.retrans:>7} {_n(loss, '{:.2f}'):>7} "
            f"{_n(per_min, '{:.2f}'):>7} {g.lost_gaps:>5} {g.worst_minute_pct:>11.1f}")
    if not groups:
        out.append("(no watched connections recorded)")
    out.append("")
    out.append("COMPARISON")
    for (program, port), paths in sorted(by_service(groups).items()):
        if sum(g.data_pkts for g in paths.values()) == 0:
            continue
        out.append(f"  {program} :{port}")
        out += [f"    {line}" for line in compare_paths(paths)]
    out.append("")
    out.append("DIRECT-PATH MONITOR (1 ping/s per server through the direct interface,")
    out.append(f"whichever path the traffic used; a bad minute loses >= {CAL_PING_BAD_PCT:.0f}% of its pings)")
    header = (f"{'target':<18} {'path':<36} {'minutes':>7} {'bad':>5} {'loss avg':>8} "
              f"{'RTT med':>8} {'on VPN':>7} {'bad then':>8} {'short':>6}")
    out.append(header)
    out.append("-" * len(header))
    for (target, path), mg in sorted(summary["monitor"].items()):
        out.append(f"{target:<18} {path[:36]:<36} {mg.minutes:>7} {mg.bad:>5} "
                   f"{_n(statistics.fmean(mg.losses) if mg.losses else None):>8} "
                   f"{_n(statistics.median(mg.rtts) if mg.rtts else None):>8} "
                   f"{mg.minutes_on_vpn:>7} {mg.bad_on_vpn:>8} {mg.short:>6}")
    if not summary["monitor"]:
        out.append("(no monitor data: no captured connection, or no direct interface)")
    out.append("")
    out.append("CALIBRATION (can ping on the direct path stand in for TCP loss?)")
    out.append("  " + summary["calibration"].describe())
    out.append("")
    out.append("PROBES (ping; 'bound' = sent through that interface explicitly)")
    header = (f"{'target':<18} {'role':<22} {'path':<36} {'bound':>5} {'rounds':>6} "
              f"{'loss avg':>8} {'loss max':>8} {'RTT med':>8}  errors")
    out.append(header)
    out.append("-" * len(header))
    for (target, role, path, bound), pg in sorted(summary["probes"].items()):
        err = f"{len(pg.errors)}: {pg.errors[-1]}" if pg.errors else ""
        if pg.never_answers:
            out.append(f"{target:<18} {role[:22]:<22} {path[:36]:<36} {bound:>5} {pg.rounds:>6} "
                       f"{'does not answer ping':>26}  {err}")
            continue
        out.append(
            f"{target:<18} {role[:22]:<22} {path[:36]:<36} {bound:>5} {pg.rounds:>6} "
            f"{_n(statistics.fmean(pg.losses) if pg.losses else None):>8} "
            f"{_n(max(pg.losses) if pg.losses else None):>8} "
            f"{_n(statistics.median(pg.rtts) if pg.rtts else None):>8}  {err}")
    out.append("")
    out.append("ROUTE HOPS (ping per hop; loss that continues to the last hop is real,")
    out.append("loss at one hop only is that router limiting its replies)")
    last = None
    for (path, target, hop, address), hg in sorted(summary["hops"].items()):
        if (path, target) != last:
            out.append(f"  {target} over {path}")
            last = (path, target)
        loss = statistics.fmean(hg.losses) if hg.losses else None
        if not hg.losses and hg.errors:
            out.append(f"    {hop:>2}  {address or '(no reply)':<18} rounds {hg.rounds:>3}  {hg.errors[-1]}")
            continue
        if hg.never_answers:
            out.append(f"    {hop:>2}  {address:<18} rounds {hg.rounds:>3}  does not answer ping")
            continue
        out.append(f"    {hop:>2}  {address or '(no reply)':<18} rounds {hg.rounds:>3}  "
                   f"loss avg {_n(loss):>5} %  max {_n(max(hg.losses) if hg.losses else None):>5} %  "
                   f"RTT {_n(statistics.median(hg.rtts) if hg.rtts else None):>6} ms"
                   + (f"  errors {len(hg.errors)}" if hg.errors else ""))
    if summary["marks"]:
        out.append("")
        out.append("MARKS ('it stutters now')")
        out += [f"  {m}" for m in summary["marks"]]
    return "\n".join(out)
