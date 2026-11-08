"""Name the program that owns a connection.

`ss -p` reports the thread name (`comm`), which for games under Wine is a
thread such as "GameThread". The program's own name comes from the first
argument of /proc/<pid>/cmdline; under Wine that is a Windows path
(`Z:\\...\\AION2.exe`), so both separators are handled. Electron programs
rewrite their command line into one string with spaces; see
`program_from_cmdline`.
"""

from __future__ import annotations

from pathlib import Path


def program_from_cmdline(raw: bytes) -> str | None:
    fields = raw.rstrip(b"\0").split(b"\0")
    first = fields[0].decode("utf-8", "replace").strip()
    if len(fields) == 1 and " -" in first:
        # Electron programs (Discord, Rambox, ...) rewrite their command line
        # into one space-separated string; the program is before the first
        # option. Only then: a real argv keeps arguments in separate fields,
        # and a Windows path may itself contain " -".
        first = first.split(" -", 1)[0].strip()
    if not first:
        return None
    return first.replace("\\", "/").rsplit("/", 1)[-1] or None


class ProgramNames:
    """pid -> program name, cached for the life of the pid."""

    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        self._root = proc_root
        self._cache: dict[int, str | None] = {}

    def name(self, pid: int | None, comm: str | None) -> str:
        if pid is None:
            return comm or "?"
        if pid not in self._cache:
            try:
                raw = (self._root / str(pid) / "cmdline").read_bytes()
            except OSError:
                raw = b""
            self._cache[pid] = program_from_cmdline(raw)
        return self._cache[pid] or comm or "?"

    def forget_except(self, live_pids: set[int]) -> None:
        """Drop pids that no longer own any connection (pids get reused)."""
        for pid in list(self._cache):
            if pid not in live_pids:
                del self._cache[pid]
