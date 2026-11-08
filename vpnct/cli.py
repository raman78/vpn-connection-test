"""Command line: `vpnct record`, `vpnct mark`, `vpnct report`, `vpnct sessions`."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path

from .session import sessions_root

MARK_SIGNAL = signal.SIGUSR1


def _pidfile() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return Path(base) / "vpn-connection-test.pid"


def cmd_record(args) -> int:
    from .engine import Engine
    from .tracker import Selection

    engine = Engine(Selection(args.program, args.port),
                    extra_targets=args.target if args.target else None)
    pidfile = _pidfile()
    pidfile.write_text(str(os.getpid()))
    signal.signal(MARK_SIGNAL, lambda *_: engine.mark("mark requested from the command line"))
    signal.signal(signal.SIGTERM, lambda *_: engine.stop())
    try:
        engine.start()
        while engine._thread.is_alive():
            engine._thread.join(timeout=args.status_every)
            if engine._thread.is_alive():
                _print_status(engine.snapshot())
    except KeyboardInterrupt:
        engine.stop()
    finally:
        pidfile.unlink(missing_ok=True)
    print(f"session: {engine.session.dir}")
    return 0


def _print_status(snap) -> None:
    ts = time.strftime("%H:%M:%S", time.localtime(snap.now))
    if not snap.connections:
        print(f"{ts} no watched connection ({snap.selection}); "
              f"{snap.unwatched} other internet connection(s), {snap.skipped_local} local/LAN skipped")
        return
    for c in snap.connections:
        rtt = f"{c.rtt_ms:.0f} ms" if c.rtt_ms is not None else "-"
        print(f"{ts} {c.program} {c.remote} via {c.path}: RTT {rtt}, "
              f"{c.segs_per_min} segs/min{'' if c.captured else ', NOT captured'}")
    for r in snap.last_minute:
        print(f"{ts}   last minute on {r.interface}: {r.data_pkts} data pkts, "
              f"{r.retrans} retrans, {r.lost_gaps} gaps (covered {r.covered_s:.0f}s)")


def cmd_mark(args) -> int:
    pidfile = _pidfile()
    try:
        pid = int(pidfile.read_text())
        os.kill(pid, MARK_SIGNAL)
    except (OSError, ValueError) as exc:
        print(f"no recording is running ({pidfile}: {exc})", file=sys.stderr)
        return 1
    print(f"mark sent to recorder pid {pid}")
    return 0


def _session_dirs(names: list[str]) -> list[Path]:
    root = sessions_root()
    if not names:
        latest = sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []
        if not latest:
            raise SystemExit(f"no sessions in {root}")
        return [latest[-1]]
    result = []
    for n in names:
        p = Path(n)
        if not p.is_dir():
            p = root / n
        if not p.is_dir():
            raise SystemExit(f"no such session: {n}")
        result.append(p)
    return result


def cmd_report(args) -> int:
    from .report import format_report, summarise
    dirs = _session_dirs(args.sessions)
    print("sessions: " + ", ".join(d.name for d in dirs))
    print(format_report(summarise(dirs)))
    return 0


def cmd_sessions(args) -> int:
    root = sessions_root()
    for p in sorted(root.iterdir()) if root.exists() else []:
        if p.is_dir():
            print(p.name)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vpnct", description="Compare direct and VPN network paths.")
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("record", help="record a session until Ctrl+C")
    r.add_argument("--program", action="append", default=[],
                   help="watch every connection of this program (e.g. AION2.exe); repeatable")
    r.add_argument("--port", action="append", type=int, default=[],
                   help="watch connections to this remote port; repeatable")
    r.add_argument("--target", action="append", default=[],
                   help="extra ping target (default 8.8.8.8 and 1.1.1.1); repeatable")
    r.add_argument("--status-every", type=float, default=10.0, help="seconds between status lines")
    r.set_defaults(func=cmd_record)
    m = sub.add_parser("mark", help="tell the running recorder 'it stutters now'")
    m.set_defaults(func=cmd_mark)
    rp = sub.add_parser("report", help="summarise sessions (default: the latest)")
    rp.add_argument("sessions", nargs="*", help="session names or directories")
    rp.set_defaults(func=cmd_report)
    s = sub.add_parser("sessions", help="list recorded sessions")
    s.set_defaults(func=cmd_sessions)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
