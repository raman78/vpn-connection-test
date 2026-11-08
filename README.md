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

Status: the recorder and the report work from the command line; a tray
program with a window is next.

## Using it

Install (editable, so changes apply at once):

```
pipx install --editable .
```

Record while you use the connection you care about; stop with Ctrl+C:

```
vpnct record --program AION2.exe        # every connection of that program
vpnct record --port 13328               # or: connections to that remote port
vpnct record                            # or: the busiest internet connections
```

Switch between the direct connection and the VPN, or between VPN servers,
whenever it suits the program you are using; the recorder notices the change
by itself and keeps the paths apart. When it stutters, run `vpnct mark` in
another terminal: the moment is noted and the route is probed at once.

Afterwards:

```
vpnct sessions                          # list recordings
vpnct report                            # the latest one
vpnct report 2026-11-08_230446 ...      # one or several, combined
```

The report shows, for each program, service (remote port) and path: round
trip time, packets lost by the remote end per minute and in total, ping
results for each target, and loss per hop of the route. Each session is a
directory under `~/.local/share/vpn-connection-test/sessions/` with plain CSV
files and an event log; `docs/ARCHITECTURE.md` explains every column.

Needs: `ss` and `ip` (iproute2), `ping` and `tracepath` (iputils), `dumpcap`
and `tshark` (Wireshark) with your user in the `wireshark` group,
NetworkManager's `nmcli` for VPN server names (optional).

Rules the tools follow:

- No `sudo`. Packet capture works through membership in the `wireshark` group.
- Nothing from the measured traffic stays on disk after a measurement:
  captures can contain private content (game chat), so they are counted and
  deleted at once. Only numbers are kept.
