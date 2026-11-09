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


def running_recorder() -> int | None:
    """Pid of a recorder that is already running (terminal or window), if any."""
    try:
        pid = int(_pidfile().read_text())
        os.kill(pid, 0)
    except (OSError, ValueError):
        return None
    return pid


def claim_pidfile() -> None:
    """One recorder at a time: two would ping through the same tunnel at
    once, which a VPN server's ICMP limit turns into false loss."""
    pid = running_recorder()
    if pid is not None and pid != os.getpid():
        raise SystemExit(f"a recorder is already running (pid {pid}); "
                         f"use 'vpnct mark' or its window instead of a second one")
    _pidfile().write_text(str(os.getpid()))


def release_pidfile() -> None:
    if running_recorder() == os.getpid():
        _pidfile().unlink(missing_ok=True)


def cmd_record(args) -> int:
    from .engine import Engine
    from .tracker import Selection

    claim_pidfile()
    engine = Engine(Selection(args.program, args.port),
                    extra_targets=args.target if args.target else None)
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
        release_pidfile()
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
    pid = running_recorder()
    if pid is None:
        print(f"no recording is running (no live pid in {_pidfile()})", file=sys.stderr)
        return 1
    os.kill(pid, MARK_SIGNAL)
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
    from .advice import format_recommendations
    from .report import format_report, summarise
    dirs = _session_dirs(args.sessions)
    print("sessions: " + ", ".join(d.name for d in dirs))
    summary = summarise(dirs)
    print(format_report(summary))
    print()
    print("RECOMMENDATION (over these sessions)")
    print("\n".join(format_recommendations(summary)) or "  (no service with captured data)")
    return 0


def all_session_dirs() -> list[Path]:
    root = sessions_root()
    return sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []


def cmd_recommend(args) -> int:
    from .advice import format_recommendations
    from .report import summarise
    dirs = _session_dirs(args.sessions) if args.sessions else all_session_dirs()
    if not dirs:
        raise SystemExit(f"no sessions in {sessions_root()}")
    print(f"RECOMMENDATION over {len(dirs)} session(s): {dirs[0].name} .. {dirs[-1].name}")
    print("\n".join(format_recommendations(summarise(dirs))) or "  (no service with captured data)")
    return 0


def cmd_sessions(args) -> int:
    root = sessions_root()
    for p in sorted(root.iterdir()) if root.exists() else []:
        if p.is_dir():
            print(p.name)
    return 0


DESKTOP_FILE = "vpn-connection-test.desktop"


def desktop_entry(exec_cmd: str, icon: Path) -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=VPN connection test\n"
        "Comment=Compare direct and VPN paths: RTT, loss, route\n"
        f"Exec={exec_cmd}\n"
        f"Icon={icon}\n"
        "Terminal=false\n"
        "Categories=Network;Monitor;\n"
        "StartupNotify=false\n"
    )


def cmd_install_desktop(args) -> int:
    """Write the menu entry that starts the tray program. It points at this
    installation: the `vpnct-gui` command if it is on PATH, else this
    interpreter with `-m vpnct.gui`."""
    import shutil
    gui = shutil.which("vpnct-gui")
    exec_cmd = gui if gui else f"{sys.executable} -m vpnct.gui"
    icon = Path(__file__).with_name("icon.svg")
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    target = Path(base) / "applications" / DESKTOP_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(desktop_entry(exec_cmd, icon))
    print(f"menu entry: {target}\n  runs: {exec_cmd}\n  icon: {icon}")
    if not gui:
        print("  note: 'vpnct-gui' is not on PATH, so the entry runs this Python directly; "
              "after 'pipx install --editable .' run this command again")
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
    rc = sub.add_parser("recommend", help="what to use, from all sessions (or the ones named)")
    rc.add_argument("sessions", nargs="*", help="session names or directories (default: all)")
    rc.set_defaults(func=cmd_recommend)
    s = sub.add_parser("sessions", help="list recorded sessions")
    s.set_defaults(func=cmd_sessions)
    d = sub.add_parser("install-desktop", help="add the tray program to the application menu")
    d.set_defaults(func=cmd_install_desktop)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
