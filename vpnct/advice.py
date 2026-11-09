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


def recommend(summary: dict, service: tuple[str, str]) -> Recommendation:
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
    watch_min = sum(mg.minutes_on_vpn for (t, _p), mg in summary["monitor"].items() if t in hosts)
    watch_bad = sum(mg.bad_on_vpn for (t, _p), mg in summary["monitor"].items() if t in hosts)
    use_watch = cal.status == "confirmed"
    exposure = d_judged + (watch_min if use_watch else 0)
    bad = d_bad + (watch_bad if use_watch else 0)
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
        (f"direct path watched by ping in {watch_min} minute(s) while on the VPN, bad in "
         f"{watch_bad} — " + ("counted (ping confirmed as a stand-in)" if use_watch else
                              f"not counted: ping is {cal.status} as a stand-in for TCP loss")),
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
        return Recommendation("not-enough-data", "Not enough data yet: need " + " and ".join(need) + ".",
                              details, ranking)
    frac = bad / exposure
    rate = f"bad in {bad} of {exposure} minutes ({100 * frac:.1f}%)"
    if frac < REC_RARE:
        best = f"; the best VPN server would cost {cost(ranking[0])}" if ranking else ""
        return Recommendation("stay-direct", f"Stay on the direct path: it was {rate}{best}.",
                              details, ranking)
    if not ranking:
        return Recommendation("no-vpn-data", f"The direct path was {rate}, but no VPN server has "
                              f"{REC_MIN_SERVER_MINUTES} judged minutes yet to recommend one.",
                              details, ranking)
    best = ranking[0]
    if best.bad_fraction >= frac / 2:
        return Recommendation("vpn-no-help", f"The VPN does not help: the direct path was {rate}, the "
                              f"best server {best.path} {100 * best.bad_fraction:.1f}%.",
                              details, ranking)
    if frac >= REC_OFTEN:
        return Recommendation("vpn-always", f"Use the VPN: the direct path was {rate}; best server "
                              f"{best.path} ({100 * best.bad_fraction:.1f}% bad, {cost(best)}).",
                              details, ranking)
    signal = ("follow the tray's hints — the direct-path watch is a confirmed signal" if use_watch
              else "switch when it stutters — the direct-path watch is not yet confirmed as a signal")
    return Recommendation("vpn-when-losing", f"Use the VPN only when the direct path is losing: it was "
                          f"{rate}; best server {best.path} ({cost(best)}); {signal}.",
                          details, ranking)


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
