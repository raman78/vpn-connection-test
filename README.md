# vpn-connection-test

Tells you whether a VPN makes your connection to a game (or any other
service) more stable than your normal connection, and whether the extra
latency is worth it. It sits in the system tray while you play, measures
the connection the program really uses, and says which path to use, with
the numbers behind it.

The idea: a connection that stutters now and then usually suffers short
bursts of packet loss somewhere on its internet route, not on your machine
and not at the server. A VPN sends your traffic along a different route, so
it helps only if that route avoids the bad part. The only way to know is to
measure both: the game's own packets on whichever path it uses, and at the
same time a steady ping of your normal connection, so that the two paths are
compared in the same minutes, not on different evenings. When the normal
connection starts losing, the program traces the route to see where the
loss begins.

It never switches the VPN by itself. Some programs (games especially) break
when their connection disappears, so it tells you, and you pick the moment.

Linux only. Tested on CachyOS (Arch) with Proton VPN (WireGuard), playing
AION 2. Nothing in it is specific to that game or that VPN.

## Quick start

1. Install the system tools and allow packet capture — see
   [Installing](https://github.com/raman78/vpn-connection-test/blob/main/docs/INSTALL.md).
2. `pipx install vpn-connection-test`
3. `vpnct install-desktop`, then start **VPN connection test** from the
   application menu.
4. Use your program as usual: on the normal connection, on the VPN, on
   different VPN servers. The window shows which one is the most stable.

## Documentation

- [docs/INSTALL.md](https://github.com/raman78/vpn-connection-test/blob/main/docs/INSTALL.md) — what it needs, installing,
  updating, removing.
- [docs/USING.md](https://github.com/raman78/vpn-connection-test/blob/main/docs/USING.md) — the window and tray icon, what the
  numbers mean, hints and the recommendation, the terminal commands,
  problems and questions.
- [docs/ARCHITECTURE.md](https://github.com/raman78/vpn-connection-test/blob/main/docs/ARCHITECTURE.md) — how it works and why,
  every log column, failure modes, tests, releases.
- [CHANGELOG.md](https://github.com/raman78/vpn-connection-test/blob/main/CHANGELOG.md) — what changed in each version.

## What it keeps, and what it never does

- **No `sudo`.** Packet capture works through membership in the
  `wireshark` group, ping through the system's normal unprivileged ping.
- **No packet contents on disk.** Only the first 96 bytes of each packet
  are captured: the headers, which are enough to count lost packets, and
  on most packets the first few dozen bytes of what they carry. They go
  through a pipe to the counting tool, which reads only the packet numbers
  from them, and are never written anywhere.
- **Only numbers are kept**: per-second and per-minute figures, ping
  results and route hops, as plain files in
  `~/.local/share/vpn-connection-test/sessions/`.
- **Nothing is sent anywhere.** Router names on a traced route come from
  your system's own name lookup only.
