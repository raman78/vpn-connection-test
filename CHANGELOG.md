# Changelog

What changed for users, release by release. Technical details are in
`docs/ARCHITECTURE.md`.

## [Unreleased]

### Added
- Ping jumps are now shown, not only lost packets: each card has
  **Steady ping**, the share of minutes in which the ping did not jump, and
  **Recently**, the hints and the recommendation say how often the ping
  jumped on each path. Among equally stable paths the steadier one is
  marked best.
- The **Tunnel** line in **Recently** tells where a VPN's ping jumps come
  from: the route to the VPN server, or the VPN server itself.

### Changed
- VPN servers whose names differ only in their number (such as every
  "NL-FREE#…" server) now share one card and are recommended together;
  **Advanced** and the terminal report still show each server.

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
