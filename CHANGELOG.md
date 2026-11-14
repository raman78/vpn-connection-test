# Changelog

What changed for users, release by release. Technical details are in
`docs/ARCHITECTURE.md`.

## [Unreleased]

### Added
- **Server stalls**: the program now notices when the game server stops
  sending for a second or more while the connection itself keeps
  answering — the lag many players feel at once, which loses no packet and
  so never showed in Stability, Loss or the ping. It is a number on every
  card, red marks on the chart, and a line in **Recently** and the banner
  saying the lag is on the server's side.
- **History** view: the cards over all recordings, and the recommendation
  with its reasoning. The **Overview** now shows only what happened since
  the program started, so a bad evening is visible at a glance.
- The window's title shows the program's version.
- When a watched program talks to an address outside the public internet
  (for example a game server in a private or carrier-grade NAT range), the
  event list says so for each such connection. Before, it was left out of
  the measurement with only a count to show for it.

### Fixed
- A game connection could go unmeasured for its whole life when the
  system listed it for a moment without its program, as happens at a switch
  to a dungeon. The program is now looked up again until it is known.
- **★ Best** no longer goes to a VPN server tried only briefly just because
  it had no lost minute yet, while the direct path, recorded for hours, had
  one or two. Paths with the same Stability colour count as equally stable,
  and the steadier, faster ping decides.

## [0.2.0] — 2026-11-10

### Added
- Ping jumps are now shown, not only lost packets: each card has
  **Steady ping**, the share of minutes in which the ping did not jump, and
  **Recently**, the hints and the recommendation say how often the ping
  jumped on each path. Among equally stable paths the steadier one is
  marked best.
- The **Tunnel** line in **Recently** tells where a VPN's ping jumps come
  from: the route to the VPN server, or the VPN server itself.

### Changed
- The window opens maximized.
- VPN servers whose names differ only in their number (such as every
  "NL-FREE#…" server) now share one card and are recommended together;
  **Advanced** and the terminal report still show each server.

### Fixed
- **Quit** no longer waits up to half a minute for a route trace to finish.
- A route trace cut short by Quit is no longer recorded as if the server
  or the routers had not answered.

## [0.1.0] — 2026-11-09

### Added
- First release: a tray program that shows whether a VPN makes the
  connection to a game or another service more stable than the normal
  connection, and whether the extra latency is worth it.
- The normal connection and each VPN server are recognised by themselves
  and measured separately; switching between them during use is picked up
  within seconds.
- Watches the connections of chosen programs or server ports, or by
  default the busiest internet connections.
- The window shows what to do now, what each path did in the last
  15 minutes, hour or three hours, a card per path with ping, spikes,
  stability and loss (the most stable one marked), a chart, and a
  recommendation from all recordings. **Advanced** shows the full data.
- While the traffic goes through a VPN, the normal connection is watched
  in the background, so both paths are compared in the same minutes. When
  it starts losing, the route is traced to show where the loss begins, or
  that only a single router was answering pings sparingly.
- Hints and desktop notifications say when switching to the VPN, or back,
  would pay off. Nothing is ever switched automatically.
- **It stutters now** notes the moment and traces the route at once.
- Recordings are kept as plain files; terminal commands give reports and
  the recommendation.
- Nothing from the traffic itself is written to disk, and no `sudo` is
  needed.
