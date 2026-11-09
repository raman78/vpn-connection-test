"""Session directory and its log files.

Every recording gets its own directory under
`$XDG_DATA_HOME/vpn-connection-test/sessions/<YYYY-MM-DD_HHMMSS>/` holding
CSV files of numbers and an event log. No packet content is ever written.
Rows are flushed as they are written, so a crash loses at most the current
line.
"""

from __future__ import annotations

import csv
import json
import os
import threading
from datetime import datetime
from pathlib import Path

SAMPLES_FIELDS = ["time", "program", "local", "remote", "path", "rtt_ms", "rttvar_ms",
                  "minrtt_ms", "d_bytes_in", "d_data_segs_in", "d_retrans", "d_ooopack"]
LOSSES_FIELDS = ["minute", "interface", "path", "program", "local", "remote",
                 "covered_s", "data_pkts", "lost_gaps", "retrans"]
PROBES_FIELDS = ["time", "target", "role", "bound", "interface", "path", "sent", "received",
                 "loss_pct", "rtt_min", "rtt_avg", "rtt_max", "error"]
HOPS_FIELDS = ["time", "target", "path", "hop", "address", "sent", "received", "loss_pct",
               "rtt_avg", "error"]

MONITOR_FIELDS = ["minute", "target", "interface", "path", "covered_s", "sent", "received",
                  "loss_pct", "rtt_p50", "rtt_max"]

FILES = {"samples.csv": SAMPLES_FIELDS, "losses.csv": LOSSES_FIELDS,
         "probes.csv": PROBES_FIELDS, "hops.csv": HOPS_FIELDS, "monitor.csv": MONITOR_FIELDS}


def sessions_root() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "vpn-connection-test" / "sessions"


def iso(t: float) -> str:
    return datetime.fromtimestamp(t).astimezone().isoformat(timespec="milliseconds")


class Session:
    def __init__(self, directory: Path, meta: dict) -> None:
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=False)
        (self.dir / "session.json").write_text(json.dumps(meta, indent=2) + "\n")
        self._lock = threading.Lock()
        self._files = {}
        self._writers = {}
        for name, fields in FILES.items():
            fh = open(self.dir / name, "w", newline="", buffering=1)
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            self._files[name] = fh
            self._writers[name] = w
        self._events = open(self.dir / "events.log", "w", buffering=1)

    @classmethod
    def create(cls, meta: dict, start: float, root: Path | None = None) -> "Session":
        root = root or sessions_root()
        name = datetime.fromtimestamp(start).strftime("%Y-%m-%d_%H%M%S")
        return cls(root / name, meta)

    def write(self, name: str, row: dict) -> None:
        with self._lock:
            self._writers[name].writerow(row)

    def event(self, t: float, kind: str, text: str) -> str:
        line = f"{iso(t)} {kind:<15} {text}"
        with self._lock:
            self._events.write(line + "\n")
        return line

    def close(self) -> None:
        with self._lock:
            for fh in self._files.values():
                fh.close()
            self._events.close()
