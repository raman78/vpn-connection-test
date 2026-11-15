# Changelog

What changed for users, release by release. Technical details are in
`docs/ARCHITECTURE.md`.

## [0.3.0] — 2026-11-15

### Added
- **The game's own ping for AION 2**: the program now reads the game's
  ping replies, the same ping Questlog shows, and records it for every
  10-second ping of the game: **Game ping** on every card, and dots on
  the chart. On a calm evening it was 26–74 ms while the network itself
  stayed at 17 ms, so the jumps come from the server's answer, not from
  the route. Only three of the game's messages are read (ping reply,
  loading screen, server clock); everything else, chat included, is
  skipped unread and nothing but numbers is kept.
- **Loading screens are no longer server stalls**: a pause in the server's
  data when you enter a map or an instance is counted apart, and marked
  in grey on the chart.
- **Server stalls**: the program now notices when the game server stops
  sending for a second or more while the connection itself keeps
  answering — the lag many players feel at once, which loses no packet and
  so never showed in the loss figures or the ping. It is a number on every
  card, red marks on the chart, and a line in **Recently** and the banner
  saying the lag is on the server's side. Shorter pauses, half a second to
  a second, are counted under **Advanced**.
- **History** view: the cards over all recordings, and the recommendation
  with its reasoning. The **Overview** now shows only what happened since
  the program started, so a bad evening is visible at a glance.
- The window's title shows the program's version.
- When a watched program talks to an address outside the public internet
  (for example a game server in a private or carrier-grade NAT range), the
  event list says so for each such connection. Before, it was left out of
  the measurement with only a count to show for it.

### Changed
- **Stability** and **Loss** on the cards are now one number, **Packet
  loss**: in how many measured minutes packets were lost (for example
  "2 of 2389 min"), and under it how many packets were lost and what share
  of all.

### Fixed
- The first 10 seconds of every new game server connection (each dungeon
  or instance) were not measured, because the program waited that long
  before capturing any connection. The game's own connections are now
  captured as soon as they appear, and their ping counts from the first
  reply.
- A game connection could go unmeasured for its whole life when the
  system listed it for a moment without its program, as happens at a switch
  to a dungeon. The program is now looked up again until it is known.
- **★ Best** no longer goes to a VPN server tried only briefly just because
  it had no lost minute yet, while the direct path, recorded for hours, had
  one or two. Paths with the same Packet loss colour count as equally good,
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
