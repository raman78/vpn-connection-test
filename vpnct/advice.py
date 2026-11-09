"""What to do: a hint for right now, and a recommendation from many sessions.

Both only read numbers the recorder already wrote; neither switches
anything. Switching a VPN mid-connection can break the program using it (a
game freezes when its address disappears), so the person decides when.

A *bad minute* is the same everywhere (`report.CAL_*`): for the
connection's own traffic, at least CAL_TCP_BAD_PCT retransmitted of at
least CAL_MIN_DATA data packets over a fully captured minute; for the
direct-path watch, at least CAL_PING_BAD_PCT of a minute's pings lost.

The thresholds below are judgement calls, named so they can be changed in
one place; docs/ARCHITECTURE.md §10 gives the reasoning for each.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .report import (CAL_MIN_COVER_S, CAL_MIN_PINGS, CAL_PING_BAD_PCT, Group, MinuteAgg,
                     by_service, loss_pct, percentile)

# Live hint
RECENT_MINUTES = 3          # look at the last this many judged minutes
RECENT_BAD = 2              # this many bad among them means "losing now"
CLEAN_MINUTES = 10          # direct watch clean this long before "you may return"

# Recommendation
REC_MIN_DIRECT_MINUTES = 120    # direct-path minutes needed before any verdict
REC_MIN_SESSIONS = 3            # spread over at least this many sessions
REC_MIN_SERVER_MINUTES = 10     # a VPN server needs this many judged minutes to be ranked
REC_RARE = 0.02                 # direct bad less often than this: stay direct
REC_OFTEN = 0.10                # direct bad at least this often: VPN always


# ---- live hint -----------------------------------------------------------------

@dataclass
class Hint:
    level: str      # "switch" | "return" | "stay" | "ok" | "unknown"
    text: str


def _tcp_minutes(minutes) -> list[tuple[float, bool, bool, float]]:
    """MinutePoints -> per minute and path: (minute, is_vpn, bad, loss %),
    judged minutes only, oldest first."""
    agg: dict[tuple, MinuteAgg] = {}
    vpn: dict[tuple, bool] = {}
    for m in minutes:
        agg.setdefault((m.minute, m.path), MinuteAgg()).add(
            (m.host, m.local_port), m.data_pkts, m.retrans, m.covered_s)
        vpn[(m.minute, m.path)] = m.is_vpn
    return [(k[0], vpn[k], a.bad, 100.0 * a.retrans / a.data)
            for k, a in sorted(agg.items()) if a.judged]


def _watch_minutes(monitor) -> list[tuple[float, bool, float]]:
    """MonitorMinutes -> per minute: (minute, bad, worst loss %) over all
    watched servers and direct interfaces, full minutes only, oldest first."""
    agg: dict[float, list] = {}
    for m in monitor:
        if m.sent < CAL_MIN_PINGS or m.covered_s < CAL_MIN_COVER_S or m.loss_pct is None:
            continue
        a = agg.setdefault(m.minute, [0.0])
        a[0] = max(a[0], m.loss_pct)
    return [(minute, worst >= CAL_PING_BAD_PCT, worst) for minute, (worst,) in sorted(agg.items())]


def live_hint(minutes, monitor, on_vpn: bool | None, calibration: str,
              rtt_cost_ms: float | None = None) -> Hint:
    """`minutes`: the service's MinutePoints; `monitor`: MonitorMinutes for its
    servers; `on_vpn`: the path its traffic uses now (None: no traffic);
    `calibration`: report.Calibration.status."""
    if on_vpn is None:
        return Hint("unknown", "no traffic on this service right now")
    tcp = [t for t in _tcp_minutes(minutes) if t[1] == on_vpn][-RECENT_MINUTES:]
    watch = _watch_minutes(monitor)
    recent_watch = watch[-RECENT_MINUTES:]
    tcp_losing = sum(t[2] for t in tcp) >= RECENT_BAD
    watch_losing = sum(w[1] for w in recent_watch) >= RECENT_BAD
    cost = f"; the VPN costs about {rtt_cost_ms:+.0f} ms" if rtt_cost_ms is not None else ""
    unconfirmed = ("" if calibration == "confirmed" else
                   " (the direct-path ping is not yet confirmed as a stand-in for this "
                   "connection's own loss)")
    if not on_vpn:
        if tcp_losing:
            return Hint("switch", f"Direct path is losing packets ({tcp[-1][3]:.1f}% in the last "
                                  f"judged minute) — switch to the VPN at the next safe moment "
                                  f"(e.g. character select){cost}.")
        if len(tcp) < RECENT_MINUTES:
            return Hint("unknown", "direct path: not enough captured minutes yet to judge")
        return Hint("ok", "Direct path is clean.")
    # on a VPN
    if tcp_losing:
        if recent_watch and not watch_losing:
            return Hint("return", f"This VPN server is losing packets ({tcp[-1][3]:.1f}%) while "
                                  f"the direct path is clean — switch back or try another server"
                                  f"{unconfirmed}.")
        return Hint("stay", f"Both this VPN server ({tcp[-1][3]:.1f}%) and the direct path are "
                            f"losing packets; try another VPN server.")
    if watch_losing:
        return Hint("stay", f"Direct path is losing now ({recent_watch[-1][2]:.0f}% of pings) — "
                            f"the VPN is sparing you this; stay on it.")
    clean = 0
    for _minute, bad, _w in reversed(watch):
        if bad:
            break
        clean += 1
    if clean >= CLEAN_MINUTES:
        return Hint("return", f"Direct path has been clean for {clean} min{cost} — you may switch "
                              f"back at the next safe moment{unconfirmed}.")
    if not watch:
        return Hint("unknown", "VPN is clean; the direct path is not being watched (no direct "
                               "interface, or no full minute yet)")
    return Hint("ok", f"VPN is clean; direct path clean for {clean} of the "
                      f"{CLEAN_MINUTES} minutes needed before suggesting a return.")


# ---- recommendation ------------------------------------------------------------

@dataclass
class ServerRank:
    path: str
    minutes: int
    bad: int
    loss: float | None
    rtt_p50: float | None

    @property
    def bad_fraction(self) -> float:
        return self.bad / self.minutes if self.minutes else 1.0


@dataclass
class Recommendation:
    verdict: str        # "not-enough-data" | "stay-direct" | "vpn-always" | "vpn-when-losing" | "vpn-no-help" | "no-vpn-data"
    headline: str
    details: list[str] = field(default_factory=list)
    ranking: list[ServerRank] = field(default_factory=list)
    provisional: bool = False


PROVISIONAL_PREFIX = "Provisional (direct path partly judged by ping): "


def recommend(summary: dict, service: tuple[str, str]) -> Recommendation:
    rec, provisional = _recommend(summary, service)
    if provisional and rec.verdict != "not-enough-data":
        rec.headline = PROVISIONAL_PREFIX + rec.headline
        rec.provisional = True
    return rec


def _recommend(summary: dict, service: tuple[str, str]) -> tuple[Recommendation, bool]:
    """Verdict for one service (program, remote port) over the summarised
    sessions, by the criterion in the project plan: a VPN is worth it if it
    keeps loss near zero in the periods the direct path is bad, at an
    acceptable latency; without bad periods the direct path wins."""
    paths: dict[str, Group] = by_service(summary["groups"]).get(service, {})
    direct = {p: g for p, g in paths.items() if p.startswith("direct:")}
    vpn = {p: g for p, g in paths.items() if p.startswith("vpn:")}
    cal = summary["calibration"]
    hosts = set().union(*(g.hosts for g in paths.values())) if paths else set()

    d_judged = sum(g.judged_minutes for g in direct.values())
    d_bad = sum(g.bad_minutes for g in direct.values())
    mgs = [mg for (t, _p), mg in summary["monitor"].items() if t in hosts]
    watch_min = sum(mg.minutes_on_vpn for mg in mgs)
    watch_bad = sum(mg.bad_on_vpn for mg in mgs)
    watch_real = sum(mg.bad_on_vpn_real for mg in mgs)
    watch_dismissed = sum(mg.bad_on_vpn_dismissed for mg in mgs)
    watch_counted = sum(mg.bad_on_vpn_counted for mg in mgs)
    # The direct-path ping counts once calibration confirms it, and provisionally
    # while calibration has not had the bad minutes to decide; not when it was
    # refuted. A clean ping is strong evidence (the game's packets take the same
    # route); a lossy minute counts unless a trace right after it showed only
    # routers limiting their ping replies.
    use_watch = cal.status in ("confirmed", "unconfirmed")
    provisional = cal.status == "unconfirmed" and watch_min > 0
    exposure = d_judged + (watch_min if use_watch else 0)
    bad = d_bad + (watch_counted if use_watch else 0)
    sessions = set().union(*(g.judged_sessions for g in direct.values())) if direct else set()
    if use_watch:
        sessions |= {s for (t, _p), mg in summary["monitor"].items() if t in hosts
                     for s in mg.sessions_on_vpn}

    ranking = sorted(
        (ServerRank(p, g.judged_minutes, g.bad_minutes, loss_pct(g), percentile(g.rtts, .5))
         for p, g in vpn.items() if g.judged_minutes >= REC_MIN_SERVER_MINUTES),
        key=lambda r: (r.bad_fraction, r.loss if r.loss is not None else 100, r.rtt_p50 or 1e9))
    d_rtts = [x for g in direct.values() for x in g.rtts]
    d_rtt = percentile(d_rtts, .5)

    def cost(r: ServerRank) -> str:
        """RTT difference to the direct path, with how much direct data it rests on."""
        if r.rtt_p50 is None or d_rtt is None:
            return "RTT cost unknown (no direct-path RTT recorded)"
        basis = f"direct RTT from {len(d_rtts)} s of traffic"
        if len(d_rtts) < 60 * REC_MIN_SERVER_MINUTES:
            basis += ", too little to rely on"
        return f"{r.rtt_p50 - d_rtt:+.0f} ms ({basis})"

    details = [
        f"direct path judged in {d_judged} minute(s) of direct traffic, bad in {d_bad}",
        (f"direct path watched by ping in {watch_min} minute(s) while on the VPN, bad in {watch_bad} "
         f"({watch_real} confirmed by a route trace, {watch_dismissed} dismissed as routers limiting "
         f"ping, {watch_bad - watch_real - watch_dismissed} unverified) — "
         + ("counted (ping confirmed as a stand-in)" if cal.status == "confirmed" else
            "counted provisionally (ping not yet confirmed as a stand-in)" if use_watch else
            f"not counted: ping proved {cal.status} as a stand-in for TCP loss")),
        f"sessions with direct-path data: {len(sessions)}",
    ]
    for r in ranking:
        loss = f"{r.loss:.2f}%" if r.loss is not None else "-"
        rtt = f"{r.rtt_p50:.0f} ms" if r.rtt_p50 is not None else "-"
        details.append(f"{r.path}: {r.minutes} judged min, bad {r.bad} "
                       f"({100 * r.bad_fraction:.1f}%), loss {loss}, RTT {rtt}, vs direct {cost(r)}")
    short = [p for p, g in vpn.items() if g.judged_minutes < REC_MIN_SERVER_MINUTES]
    if short:
        details.append("not ranked (under %d judged minutes): %s" % (REC_MIN_SERVER_MINUTES, ", ".join(short)))

    if exposure < REC_MIN_DIRECT_MINUTES or len(sessions) < REC_MIN_SESSIONS:
        need = []
        if exposure < REC_MIN_DIRECT_MINUTES:
            need.append(f"{REC_MIN_DIRECT_MINUTES - exposure} more minute(s) of the direct path")
        if len(sessions) < REC_MIN_SESSIONS:
            need.append(f"{REC_MIN_SESSIONS - len(sessions)} more session(s)")
        return (Recommendation("not-enough-data", "Not enough data yet: need " + " and ".join(need) + ".",
                              details, ranking), provisional)
    frac = bad / exposure
    rate = f"bad in {bad} of {exposure} minutes ({100 * frac:.1f}%)"
    if frac < REC_RARE:
        best = f"; the best VPN server would cost {cost(ranking[0])}" if ranking else ""
        return (Recommendation("stay-direct", f"Stay on the direct path: it was {rate}{best}.",
                              details, ranking), provisional)
    if not ranking:
        return (Recommendation("no-vpn-data", f"The direct path was {rate}, but no VPN server has "
                              f"{REC_MIN_SERVER_MINUTES} judged minutes yet to recommend one.",
                              details, ranking), provisional)
    best = ranking[0]
    if best.bad_fraction >= frac / 2:
        return (Recommendation("vpn-no-help", f"The VPN does not help: the direct path was {rate}, the "
                              f"best server {best.path} {100 * best.bad_fraction:.1f}%.",
                              details, ranking), provisional)
    if frac >= REC_OFTEN:
        return (Recommendation("vpn-always", f"Use the VPN: the direct path was {rate}; best server "
                              f"{best.path} ({100 * best.bad_fraction:.1f}% bad, {cost(best)}).",
                              details, ranking), provisional)
    signal = ("follow the tray's hints — the direct-path watch is a confirmed signal" if use_watch
              else "switch when it stutters — the direct-path watch is not yet confirmed as a signal")
    return (Recommendation("vpn-when-losing", f"Use the VPN only when the direct path is losing: it was "
                          f"{rate}; best server {best.path} ({cost(best)}); {signal}.",
                          details, ranking), provisional)


def main_services(summary: dict) -> tuple[list[tuple], list[tuple]]:
    """Services with at least REC_MIN_SERVER_MINUTES judged minutes on some
    path, busiest first; and the rest (a program's side connections)."""
    main, rest = [], []
    for service, paths in by_service(summary["groups"]).items():
        judged = sum(g.judged_minutes for g in paths.values())
        (main if judged >= REC_MIN_SERVER_MINUTES else rest).append((judged, service))
    return [s for _, s in sorted(main, reverse=True)], [s for _, s in sorted(rest, reverse=True)]


def format_recommendations(summary: dict) -> list[str]:
    out = []
    main, rest = main_services(summary)
    for service in main:
        rec = recommend(summary, service)
        out.append(f"  {service[0]} :{service[1]}")
        out.append(f"    {rec.headline}")
        out += [f"      - {d}" for d in rec.details]
    if rest:
        out.append(f"  not judged (under {REC_MIN_SERVER_MINUTES} judged minutes on any path): "
                   + ", ".join(f"{p} :{port}" for p, port in rest))
    return out


# ---- overview cards -------------------------------------------------------------

STABLE_PCT = 99.0      # stability at or above: shown green
SHAKY_PCT = 95.0       # at or above: amber; below: red


@dataclass
class PathCard:
    """One path of one service, as the overview shows it."""
    path: str
    title: str             # "Direct" / "VPN · <connection name>"
    subtitle: str          # the interface
    is_vpn: bool
    ping_ms: float | None  # median RTT over seconds with data
    spikes_ms: float | None  # RTT p95 minus median: how far the ping jumps above usual
    stability_pct: float | None  # judged minutes without loss
    loss_pct: float | None       # remote retransmissions per captured data packet
    judged_minutes: int
    sessions: int          # sessions with judged minutes on this path
    enough: bool           # judged long enough to be compared
    best: bool = False
    best_reason: str = ""

    @property
    def stability_level(self) -> str:
        if self.stability_pct is None:
            return "unknown"
        return ("good" if self.stability_pct >= STABLE_PCT
                else "fair" if self.stability_pct >= SHAKY_PCT else "poor")


def path_title(path: str) -> tuple[str, str]:
    """'vpn:wg0 [Name]' -> ('VPN · Name', 'wg0'); 'direct:eth0 [x]' -> ('Direct', 'eth0')."""
    kind, _, rest = path.partition(":")
    itf, _, name = rest.partition(" [")
    name = name.rstrip("]")
    if kind == "vpn":
        return (f"VPN · {name}" if name else "VPN"), itf
    return "Direct", itf


def path_cards(paths: dict[str, Group]) -> list[PathCard]:
    """Cards for a service's paths, direct first. `best` goes to one path
    only when at least two paths have enough judged minutes to compare:
    fewest bad minutes, then lowest ping, then least loss."""
    cards = []
    for path, g in paths.items():
        if not (path.startswith("direct:") or path.startswith("vpn:")):
            continue                         # gone(...): an address that vanished mid-switch
        judged = g.judged_minutes
        p50, p95 = percentile(g.rtts, .5), percentile(g.rtts, .95)
        title, sub = path_title(path)
        cards.append(PathCard(
            path, title, sub, path.startswith("vpn:"), p50,
            (p95 - p50) if p50 is not None and p95 is not None else None,
            100.0 * (judged - g.bad_minutes) / judged if judged else None,
            loss_pct(g), judged, len(g.judged_sessions), judged >= REC_MIN_SERVER_MINUTES))
    # Stability decides; among equally stable paths the lower ping wins, since
    # loss below the bad-minute threshold is not felt; loss only breaks a tie.
    ranked = sorted((c for c in cards if c.enough),
                    key=lambda c: (-(c.stability_pct or 0), c.ping_ms if c.ping_ms is not None else 1e9,
                                   c.loss_pct if c.loss_pct is not None else 100))
    if len(ranked) >= 2:
        first, others = ranked[0], ranked[1:]
        first.best = True
        if all((first.stability_pct or 0) > (o.stability_pct or 0) for o in others):
            first.best_reason = "most stable"
        else:
            first.best_reason = "as stable, lowest ping"
    return sorted(cards, key=lambda c: (c.is_vpn, c.title))


# ---- recent window --------------------------------------------------------------

RECENT_WINDOWS = [("15 min", 900), ("1 h", 3600), ("3 h", 3 * 3600)]
RECENT_MIN_CLEAN = 10       # watched minutes needed before "direct was clean, VPN not needed"


@dataclass
class RecentLine:
    level: str          # good | fair | poor | unknown
    title: str
    text: str


@dataclass
class RecentView:
    lines: list[RecentLine]
    conclusion: Hint


def recent_view(minutes, seconds, monitor, routes, on_vpn: bool | None, window_s: float,
                now: float, rtt_cost_ms: float | None = None, best_vpn: str | None = None) -> RecentView:
    """What each path did over the last `window_s` seconds of this session.

    `minutes`/`seconds`: the service's MinutePoints/SecondPoints; `monitor`:
    MonitorMinutes for its servers; `routes`: engine.RouteResults for them.
    `rtt_cost_ms`: VPN minus direct RTT of the connection itself, if known
    (ping RTT and the connection's RTT are not comparable)."""
    t0 = now - window_s
    lines: list[RecentLine] = []

    # the traffic's own paths
    agg: dict[tuple, MinuteAgg] = {}
    vpn_of: dict[str, bool] = {}
    for m in minutes:
        if m.minute >= t0:
            agg.setdefault((m.minute, m.path), MinuteAgg()).add(
                (m.host, m.local_port), m.data_pkts, m.retrans, m.covered_s)
            vpn_of[m.path] = m.is_vpn
    rtts: dict[str, list[float]] = {}
    for s in seconds:
        if s.time >= t0 and s.rtt_ms is not None and s.d_data_segs_in > 0:
            rtts.setdefault(s.path, []).append(s.rtt_ms)
    per_path: dict[str, list[MinuteAgg]] = {}
    for (_minute, path), a in agg.items():
        if a.judged:
            per_path.setdefault(path, []).append(a)
    own_bad: dict[str, tuple[int, int]] = {}
    for path in sorted(per_path, key=lambda p: (vpn_of[p], p)):
        judged = per_path[path]
        bad = sum(a.bad for a in judged)
        own_bad[path] = (bad, len(judged))
        rtt = percentile(rtts.get(path, []), .5)
        title, _itf = path_title(path)
        lvl = "good" if bad == 0 else "fair" if bad == 1 else "poor"
        lines.append(RecentLine(lvl, title, f"{len(judged)} min measured, packets lost in {bad}"
                                + (f", ping {rtt:.0f} ms" if rtt is not None else "")))

    # the direct path watched by ping (meaningful while the traffic is on a VPN)
    watch = [w for w in _watch_minutes([m for m in monitor if m.minute >= t0])]
    route_list = sorted((r for r in routes if r.time >= t0 and not r.path.startswith("vpn:")),
                        key=lambda r: r.time)
    real = [r for r in route_list if r.verdict.kind in ("real", "target-only")]
    limited = [r for r in route_list if r.verdict.kind == "hop-limit"]
    w_bad = sum(b for _m, b, _w in watch)
    if watch and (on_vpn or not per_path):
        worst = max(w for _m, _b, w in watch)
        lvl = "good" if w_bad == 0 else "fair" if w_bad == 1 else "poor"
        lines.append(RecentLine(lvl, "Direct (ping in the background)",
                                f"{len(watch)} min watched, pings lost in {w_bad}"
                                + (f" (worst {worst:.0f} %)" if w_bad else "")))
    if route_list:
        last = (real or route_list)[-1]
        lvl = "poor" if last.verdict.kind in ("real", "target-only") else "good"
        lines.append(RecentLine(lvl, "Direct route", last.verdict.text
                                + f" — traced {time.strftime('%H:%M', time.localtime(last.time))}"))

    # conclusion
    cost = f" (it costs about {rtt_cost_ms:+.0f} ms)" if rtt_cost_ms is not None else ""
    where = f": {real[-1].verdict.text}" if real else ""
    span = _span_text(window_s)
    if on_vpn is None and not per_path:
        return RecentView(lines, Hint("unknown", f"No traffic on this connection in the last {span}."))
    if on_vpn:
        vpn_paths = [p for p in own_bad if vpn_of[p]]
        vbad = sum(own_bad[p][0] for p in vpn_paths)
        vmin = sum(own_bad[p][1] for p in vpn_paths)
        if vbad >= RECENT_BAD:
            return RecentView(lines, Hint("return", f"This VPN server lost packets in {vbad} of {vmin} "
                                                    f"minutes — try another server or the direct path."))
        if w_bad >= RECENT_BAD and (real or not limited):
            check = "" if real else " (not yet confirmed by a route trace)"
            return RecentView(lines, Hint("stay", f"The direct path was losing in {w_bad} of {len(watch)} "
                                                  f"minutes{where}{check} — the VPN spared you this."))
        if w_bad >= RECENT_BAD:
            return RecentView(lines, Hint("ok", f"Pings on the direct path were lost in {w_bad} minutes, but "
                                                f"the route trace shows only routers limiting ping replies — "
                                                f"the direct path itself looked fine."))
        if len(watch) >= RECENT_MIN_CLEAN and w_bad == 0:
            return RecentView(lines, Hint("return", f"The direct path was clean for all {len(watch)} watched "
                                                    f"minutes — the VPN is not needed right now{cost}."))
        return RecentView(lines, Hint("unknown", f"The VPN is clean; the direct path has {len(watch)} of "
                                                 f"{RECENT_MIN_CLEAN} watched minutes needed to judge it."))
    dbad, dmin = (sum(own_bad[p][0] for p in own_bad if not vpn_of[p]),
                  sum(own_bad[p][1] for p in own_bad if not vpn_of[p]))
    if dbad >= RECENT_BAD:
        to = f" ({best_vpn} has been the best so far)" if best_vpn else ""
        return RecentView(lines, Hint("switch", f"The direct path lost packets in {dbad} of {dmin} minutes"
                                                f"{where} — switch to the VPN{to}."))
    if dmin == 0:
        return RecentView(lines, Hint("unknown", f"Not enough measured minutes in the last {span} yet."))
    return RecentView(lines, Hint("ok", f"The direct path was stable in the last {span} "
                                        f"({dmin} min, packets lost in {dbad})."))


def _span_text(window_s: float) -> str:
    for name, secs in RECENT_WINDOWS:
        if secs == window_s:
            return name
    return f"{window_s / 60:.0f} min"
