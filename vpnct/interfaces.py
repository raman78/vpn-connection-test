"""Which network path a connection uses.

A connection's local address names its interface (`ip -j -d addr`). The
interface's kind decides whether the path is a VPN: WireGuard and tun devices
(OpenVPN and most VPN clients) are VPNs, everything else is the direct path.
NetworkManager supplies the human name of the active connection on the
device (for Proton VPN: the server, e.g. "ProtonVPN NL-FREE#1"), so two VPN
servers on the same interface name are told apart.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

VPN_KINDS = frozenset({"wireguard", "tun", "tap", "ipip", "gre", "openvpn"})


@dataclass(frozen=True)
class Interface:
    name: str
    index: int
    kind: str          # linkinfo.info_kind, or link_type when there is none
    is_vpn: bool
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class NetPath:
    """The path a connection takes: interface plus the connection on it."""
    interface: str
    is_vpn: bool
    connection: str | None   # NetworkManager connection name, if any

    @property
    def label(self) -> str:
        if self.interface.startswith(UNKNOWN_PATH_PREFIX):
            return self.interface        # neither direct nor VPN: the address is gone
        kind = "vpn" if self.is_vpn else "direct"
        base = f"{kind}:{self.interface}"
        return f"{base} [{self.connection}]" if self.connection else base


UNKNOWN_PATH_PREFIX = "gone"


def parse_ip_addr(json_text: str) -> list[Interface]:
    result = []
    for item in json.loads(json_text):
        linkinfo = item.get("linkinfo") or {}
        kind = linkinfo.get("info_kind") or item.get("link_type") or "?"
        is_vpn = kind in VPN_KINDS or item.get("link_type") == "none"
        addrs = tuple(a["local"] for a in item.get("addr_info", []) if "local" in a)
        result.append(Interface(item["ifname"], int(item["ifindex"]), kind, is_vpn, addrs))
    return result


def read_interfaces() -> list[Interface]:
    out = subprocess.run(["ip", "-j", "-d", "addr", "show"],
                         capture_output=True, text=True, check=True).stdout
    return parse_ip_addr(out)


def _split_terse(line: str) -> list[str]:
    """Split one `nmcli -t` line on ':' honouring the '\\:' escape."""
    fields, current, escaped = [], [], False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


def parse_nm_active(output: str) -> dict[str, str]:
    """`nmcli -t -f NAME,DEVICE con show --active` -> {device: name}."""
    result = {}
    for line in output.splitlines():
        if not line:
            continue
        name, device = _split_terse(line)[:2]
        if device:
            result[device] = name
    return result


def read_nm_active() -> dict[str, str]:
    """Empty when NetworkManager is absent; the path then has no name."""
    try:
        out = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"],
                             capture_output=True, text=True, check=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_nm_active(out)


class PathMap:
    """Local address -> NetPath, rebuilt from a fresh interface listing."""

    def __init__(self, interfaces: list[Interface], nm_names: dict[str, str]) -> None:
        self.interfaces = interfaces
        self._nm_names = nm_names
        self._by_addr: dict[str, NetPath] = {}
        for itf in interfaces:
            path = NetPath(itf.name, itf.is_vpn, nm_names.get(itf.name))
            for addr in itf.addresses:
                self._by_addr[addr] = path

    def path_for(self, local_ip: str) -> NetPath:
        """A connection whose address no longer exists (VPN switched off under
        it) gets a 'gone' path that names the address, never a guess."""
        return self._by_addr.get(local_ip) or NetPath(f"{UNKNOWN_PATH_PREFIX}({local_ip})", False, None)

    def path_for_interface(self, name: str) -> NetPath:
        for itf in self.interfaces:
            if itf.name == name:
                return NetPath(itf.name, itf.is_vpn, self._nm_names.get(itf.name))
        return NetPath(f"{UNKNOWN_PATH_PREFIX}({name})", False, None)

    def local_addresses(self) -> set[str]:
        return set(self._by_addr)

    def signature(self) -> tuple:
        """Changes when an interface appears, disappears or is recreated
        (a VPN server switch recreates the device with a new index)."""
        return tuple(sorted((i.name, i.index, i.addresses) for i in self.interfaces))

    def direct_interfaces(self, default_route_devices: set[str]) -> list[Interface]:
        """Non-VPN interfaces that carry a default route: the paths to the
        internet without the tunnel. An interface merely having an address
        is not one — Proton's kill switch adds a dummy device with IPv6
        addresses (`ipv6leakintrf0`) that leads nowhere."""
        return [i for i in self.interfaces if not i.is_vpn and i.name in default_route_devices]

    def vpn_interfaces(self) -> list[Interface]:
        return [i for i in self.interfaces if i.is_vpn and i.addresses]


def route_interface(target: str) -> str | None:
    """The interface the routing table sends `target` over right now."""
    try:
        out = subprocess.run(["ip", "-j", "route", "get", target],
                             capture_output=True, text=True, check=True, timeout=5).stdout
        return json.loads(out)[0].get("dev")
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def parse_nm_device_targets(output: str) -> list[str]:
    """`nmcli -g IP4.GATEWAY,IP4.DNS device show DEV` -> addresses, gateway first."""
    result = []
    for line in output.splitlines():
        for item in line.split("|"):
            item = item.strip()
            if item and item not in result:
                result.append(item)
    return result


def read_vpn_gateway(device: str) -> str | None:
    """First hop inside a VPN tunnel: the device's gateway, else its first DNS
    server (WireGuard tunnels have no gateway; Proton puts its resolver on
    the tunnel's far end)."""
    try:
        out = subprocess.run(["nmcli", "-g", "IP4.GATEWAY,IP4.DNS", "device", "show", device],
                             capture_output=True, text=True, check=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    targets = parse_nm_device_targets(out)
    return targets[0] if targets else None


def read_default_route_devices() -> set[str]:
    """Devices with a default route in the main routing table."""
    try:
        out = subprocess.run(["ip", "-j", "route", "show", "default"],
                             capture_output=True, text=True, check=True, timeout=5).stdout
        return {r["dev"] for r in json.loads(out) if "dev" in r}
    except (OSError, subprocess.SubprocessError, ValueError):
        return set()
