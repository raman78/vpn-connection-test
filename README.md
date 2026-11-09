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

The window opens on an **overview** for one connection — e.g. your game's
server:

- a banner saying what is happening now and what to do (switch, stay, or
  you can go back), with the path in use and its ping;
- **Recently**: what each path did over the last 15 minutes, hour or three
  hours — while you play through the VPN, also whether the direct
  connection was losing packets meanwhile and where on the route the loss
  starts (or that it was just a router not answering pings) — with a
  one-line conclusion such as "the VPN is not needed right now";
- one card per path you have tested — the direct connection and each VPN
  server — with its **ping**, **spikes** (how far the ping jumps above its
  usual value), **stability** (share of minutes without packet loss) and
  **loss**; the best one is marked ★ once at least two have enough data;
- a chart of ping and lost packets, with the path in use shaded behind it;
- the recommendation from all your recordings.

**Advanced** shows everything behind it: the full comparison table, how
reliable the direct-path ping is, the recommendation's reasoning, the last
probes, events, earlier sessions and the folder with the logs.

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
vpnct recommend                         # what to use, from all recordings
```

The report shows, for each program, service (remote port) and path: round
trip time, packets lost by the remote end per minute and in total, a
comparison of the paths, ping results for each target, and loss per hop of
the route. Each session is a directory under
`~/.local/share/vpn-connection-test/sessions/` with plain CSV files and an
event log; `docs/ARCHITECTURE.md` explains every column.

**Watching the direct path while on the VPN.** Throughout a recording, the
program pings the server you are connected to once a second through your
normal connection, bypassing the VPN. So while you play through the VPN it
still knows whether the direct route would be losing packets right now — the
comparison is made in the same minutes, not between an evening on one path
and an evening on the other. Whether this ping is a good enough stand-in
for the game's own losses is checked from the minutes you play directly;
the report and the window say "unconfirmed" until enough bad minutes have
been seen to tell.

**Hints and the recommendation.** At the top of the window (and as a tray
notification when it changes) the program says what to do now: switch to
the VPN when the direct path has been losing packets for two of the last
three minutes; stay on the VPN while the direct path is losing; switch back
once the direct path has been clean for ten minutes. It never switches by
itself — you pick the safe moment.

Under the comparison, the **recommendation** draws on all your recordings:
stay direct, use the VPN always, use it only when the direct path is losing,
or "the VPN does not help" — with the best VPN server and what it costs in
latency. Until there are two hours of direct-path data over three sessions
it says how much is still missing instead. While you play through the VPN,
the background ping of the direct connection counts too; until enough bad
minutes have shown that this ping tracks the game's own losses, such a
recommendation is marked "Provisional". From a terminal:
`vpnct recommend`.

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
