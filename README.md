# vpn-connection-test

Compares network paths: the direct connection versus one or more VPN
interfaces, to the hosts that matter. The question it answers for a given
service is whether a VPN makes the connection more stable than the direct
route, and whether the latency it adds is worth it.

The idea: intermittent stutter usually comes from short bursts of packet loss
on some segment of the internet route, not from the local machine or the
service itself. A VPN only helps if its route avoids that segment. So the test
records the live connection continuously, alternates blocks with and without
the VPN, probes the route on each path, and compares loss and round-trip time
between them — especially during the periods when the direct route is bad.

First case: the connection to the AION 2 game server through Proton VPN
(WireGuard).

## Installing

```
pipx install --editable .        # commands vpnct and vpnct-gui; edits apply at once
vpnct install-desktop            # "VPN connection test" in the application menu
```

## The tray program

Start **VPN connection test** from the menu. It starts recording at once and
sits in the system tray:

| Icon | Meaning (last captured minute of the busiest service) |
|---|---|
| green | no packet lost |
| yellow | some retransmissions |
| red | 2 % or more of the packets retransmitted |
| grey | nothing captured yet |

Hovering shows the path in use, the round trip time and the last minute's
numbers. Click the icon for the window; right-click for **It stutters now**
and **Quit**. Closing the window only hides it — recording goes on until
Quit.

The window shows, for one service at a time (a program and the server port
it talks to — e.g. a game's main server):

- what is happening now: path, RTT, last minute;
- a chart of RTT and of retransmissions per minute, with the path in use
  shaded behind it, so a switch to or from the VPN is visible;
- the comparison of paths — the same numbers as `vpnct report` — with a
  plain statement under it (or "not enough data yet" until a path has five
  captured minutes); **Compare sessions…** adds earlier recordings;
- the last round of pings and the recent events.

Switch between the direct connection and the VPN, or between VPN servers,
whenever it suits the program you are using; the recorder notices the change
by itself and keeps the paths apart. When it stutters, press **It stutters
now**: the moment is noted and the route is probed at once.

**What to watch.** Started from the menu, it reads
`~/.config/vpn-connection-test/config.toml`:

```toml
programs = ["AION2.exe"]     # every connection of these programs
ports = [13328]              # and/or connections to these server ports
targets = ["8.8.8.8"]        # extra ping targets (default 8.8.8.8 and 1.1.1.1)
```

Without that file it watches the busiest internet connections by itself.
Only one recording runs at a time; starting a second one says so.

## From a terminal

The same recorder without a window, stopped with Ctrl+C:

```
vpnct record --program AION2.exe        # every connection of that program
vpnct record --port 13328               # or: connections to that remote port
vpnct record                            # or: the busiest internet connections
vpnct mark                              # "it stutters now", from another terminal
vpnct sessions                          # list recordings
vpnct report                            # the latest one
vpnct report 2026-11-08_230446 ...      # one or several, combined
```

The report shows, for each program, service (remote port) and path: round
trip time, packets lost by the remote end per minute and in total, a
comparison of the paths, ping results for each target, and loss per hop of
the route. Each session is a directory under
`~/.local/share/vpn-connection-test/sessions/` with plain CSV files and an
event log; `docs/ARCHITECTURE.md` explains every column.

**Ping through a VPN.** Some VPN servers limit ping (ICMP) per user; Proton's
free servers drop nearly all of it as soon as two pings run at once. The
recorder therefore pings one target at a time over each path, and the
connection's own TCP numbers are the ones to trust.

Needs: `ss` and `ip` (iproute2), `ping` and `tracepath` (iputils), `dumpcap`
and `tshark` (Wireshark) with your user in the `wireshark` group,
NetworkManager's `nmcli` for VPN server names (optional); PyQt6 for the
tray program (pipx installs it).

Rules the tools follow:

- No `sudo`. Packet capture works through membership in the `wireshark` group.
- Nothing from the measured traffic stays on disk after a measurement:
  captures can contain private content (game chat), so they are counted and
  deleted at once. Only numbers are kept.
