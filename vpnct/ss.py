"""Read per-connection TCP statistics from the kernel through `ss`.

`ss -tinpH state established` prints each socket on two lines: the socket line
(queues, addresses, owning process) and an indented line of `key:value`
statistics. The kernel omits counters that are zero (`retrans`, `rcv_ooopack`,
`bytes_retrans`, ...), so a missing counter means 0, never "unknown".
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

SS_COMMAND = ["ss", "-tinpH", "state", "established"]

_PROCESS_RE = re.compile(r'\("([^"]*)",pid=(\d+)')
_STAT_RE = re.compile(r"(\w+):(\S+)")


@dataclass(frozen=True)
class SocketStats:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    pid: int | None
    comm: str | None
    rtt_ms: float | None
    rttvar_ms: float | None
    minrtt_ms: float | None
    retrans_total: int
    rcv_ooopack: int
    bytes_received: int
    bytes_sent: int
    segs_in: int
    data_segs_in: int

    @property
    def key(self) -> tuple[str, int, str, int]:
        return (self.local_ip, self.local_port, self.remote_ip, self.remote_port)


def split_endpoint(text: str) -> tuple[str, int]:
    """'192.0.2.20:5000' / '[::1]:631' / '192.0.2.20%eth0:68' -> (ip, port)."""
    host, _, port = text.rpartition(":")
    host = host.strip("[]")
    host = host.split("%", 1)[0]
    if host.startswith("::ffff:") and "." in host:
        host = host[len("::ffff:"):]
    return host, int(port)


def _int(stats: dict[str, str], name: str) -> int:
    value = stats.get(name)
    return int(value) if value is not None else 0


def _rtt(value: str | None) -> tuple[float | None, float | None]:
    if value is None:
        return None, None
    avg, _, var = value.partition("/")
    return float(avg), (float(var) if var else None)


def parse_ss(output: str) -> list[SocketStats]:
    """Parse the two-line-per-socket output of SS_COMMAND."""
    result: list[SocketStats] = []
    socket_line: str | None = None

    def finish(info: str) -> None:
        assert socket_line is not None
        fields = socket_line.split()
        # Recv-Q Send-Q Local Peer [Process]
        local_ip, local_port = split_endpoint(fields[2])
        remote_ip, remote_port = split_endpoint(fields[3])
        process = _PROCESS_RE.search(socket_line)
        stats = dict(_STAT_RE.findall(info))
        rtt, rttvar = _rtt(stats.get("rtt"))
        minrtt = stats.get("minrtt")
        retrans = stats.get("retrans")  # "current/total"
        result.append(SocketStats(
            local_ip=local_ip, local_port=local_port,
            remote_ip=remote_ip, remote_port=remote_port,
            pid=int(process.group(2)) if process else None,
            comm=process.group(1) if process else None,
            rtt_ms=rtt, rttvar_ms=rttvar,
            minrtt_ms=float(minrtt) if minrtt else None,
            retrans_total=int(retrans.partition("/")[2] or 0) if retrans else 0,
            rcv_ooopack=_int(stats, "rcv_ooopack"),
            bytes_received=_int(stats, "bytes_received"),
            bytes_sent=_int(stats, "bytes_sent"),
            segs_in=_int(stats, "segs_in"),
            data_segs_in=_int(stats, "data_segs_in"),
        ))

    for line in output.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if socket_line is not None:
                finish(line)
                socket_line = None
        else:
            if socket_line is not None:
                finish("")  # socket without a statistics line
            socket_line = line
    if socket_line is not None:
        finish("")
    return result


def read_sockets() -> list[SocketStats]:
    out = subprocess.run(SS_COMMAND, capture_output=True, text=True, check=True).stdout
    return parse_ss(out)
