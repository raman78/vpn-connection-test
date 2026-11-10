# vpn-connection-test — architecture

How the recorder works, why it is built this way, and what each number in
its logs means. Read it next to a running `vpnct record`: every step below
leaves a trace in the session's `events.log`.

## 1. The question and the idea

A connection stutters when packets are lost on the way, because TCP holds
back everything behind a lost segment until it is retransmitted. The loss is
usually on one segment of the internet route, not on the local machine and
not at the service. A VPN changes the route; it helps only if its route
avoids the lossy segment, and it always adds some latency.

So the recorder answers, per connection and per **path** (interface + the
VPN server on it):

- how long the round trip is (RTT median and 95th percentile);
- how many packets from the remote end were lost;
- where on the route loss starts (ping per hop);

and keeps the numbers of every path apart, so the paths can be compared
side by side — within one session and across sessions, since bad periods
on a route come and go.

Nothing about one program is built in. Programs, ports and probe targets are
inputs; AION 2 is only the first case.

## 2. Pieces

```
              every 1 s                         every 60 s / 300 s / on mark
 ss -tinpH ──► Tracker ──► samples.csv          probe thread ──► probes.csv
 ip -j -d addr ─┐   │                             ping (route / -I iface)
 nmcli (names) ─┴► PathMap                        tracepath + ping per hop ──► hops.csv
                    │ captured connections (lasting, with traffic)
                    ▼
             CaptureManager ── one pipeline per captured connection:
               dumpcap -s 96 -f <its 4-tuple> -w -  │ pipe │  tshark -r - (TCP analysis)
                    │
                    ▼ per minute, per connection
               losses.csv                     events.log ◄── every decision above
```

| Module | Role |
|---|---|
| `vpnct/ss.py` | runs `ss`, parses per-socket statistics |
| `vpnct/procs.py` | pid → program name (Wine's Windows paths; Electron's rewritten command lines) |
| `vpnct/interfaces.py` | interfaces, VPN detection, path labels, route lookup, VPN gateway |
| `vpnct/tracker.py` | connections over time, per-second deltas, which ones are watched |
| `vpnct/capture.py` | header-only capture pipelines and per-minute loss counts |
| `vpnct/probes.py` | ping and tracepath, with their outputs parsed |
| `vpnct/monitor.py` | continuous 1/s ping of the direct path to the busiest servers |
| `vpnct/session.py` | session directory, CSV files, event log |
| `vpnct/engine.py` | `Engine`: the loop that ties it together; `snapshot()` for a display |
| `vpnct/report.py` | summary of one or more sessions; `compare_paths` |
| `vpnct/cli.py` | `vpnct record / mark / report / sessions / install-desktop`; the one-recorder pidfile |
| `vpnct/config.py` | `config.toml` for starts without options (the menu entry) |
| `vpnct/advice.py` | the live hint and the recommendation from many sessions (§10) |
| `vpnct/gui.py` | `vpnct-gui`: tray icon and window around an in-process `Engine` |
| `vpnct/__init__.py` | `__version__`, from the build (§13) |

The recorder and the report use only the Python standard library (PyQt6 is
for `vpnct-gui` alone); the measuring is done by `ss`, `ip`,
`nmcli`, `dumpcap`, `tshark`, `ping` and `tracepath`. Nothing runs with
`sudo`: capture works through the `wireshark` group (dumpcap carries
`cap_net_raw`/`cap_net_admin`), ping through `net.ipv4.ping_group_range`.

## 3. One sampling step (every second)

`Engine.step`:

1. **Read sockets.** `ss -tinpH state established` gives, per TCP socket,
   the owning process and the kernel's counters. The kernel omits counters
   that are zero (`retrans`, `rcv_ooopack`), so a missing counter is read
   as 0 — the parser never leaves it "unknown".
2. **Read the interfaces.** `ip -j -d addr` lists devices with their kind;
   WireGuard and tun devices (and devices with link type `none`) are VPNs,
   the rest is the direct path. NetworkManager's active connection names
   (`nmcli -t -f NAME,DEVICE con show --active`) label each device — for
   Proton VPN the name is the server. Names are re-read every 5 s, and at
   once when the device set changes: a VPN server switch recreates the
   device under the same name with a new index, and that index change is
   what triggers the re-read. Every such change is an `interfaces` event.
3. **Update the tracker.** A connection is its 4-tuple. Its path comes from
   its local address. Cumulative counters become per-second deltas. Three
   things are reported instead of being smoothed over:
   - a counter that goes **down** on the same 4-tuple (socket replaced
     between samples): `counters-reset`, new baseline, no negative delta;
   - a **path change** of a live watched connection — in particular a VPN
     switched off under it: its address no longer exists, and the path
     becomes `gone(<address>)`, labelled neither direct nor VPN, rather
     than a guess. A VPN server switch shows as two changes about a second
     apart: `vpn:… [old server] -> gone(…)` while the device is recreated,
     then `gone(…) -> vpn:… [new server]` (verified 2026-11-09, Proton
     NL-FREE#89 → NO-FREE#2). Connections that are not watched move
     silently — they are not what the session measures;
   - a watched connection that **closes**, with its lifetime and volume.
4. **Choose what is watched.** Pinned (`--program`, `--port`): every
   matching connection, case-insensitive on the program name. Automatic
   (nothing pinned): up to `AUTO_MAX_WATCHED` connections that received at
   least `AUTO_MIN_SEGMENTS` data segments in the last minute; once watched,
   a connection stays watched until it closes, so its log has no holes.
   Connections to loopback and private/LAN addresses are not candidates;
   their number is kept (`skipped_local`) and shown, so they are not
   silently gone.
5. **Write a sample row** for each watched connection.
6. **Choose what is captured.** Of the watched connections, those that have
   lived at least `CAPTURE_MIN_AGE_S` (10 s) and received at least
   `CAPTURE_MIN_SEGMENTS` (10) data segments in the last minute, busiest
   first, at most `MAX_CAPTURED` (8). A program's short HTTPS requests are
   sampled but not captured — a handful of packets says nothing about loss.
   Once captured, a connection stays captured until it closes or its
   address disappears.
7. **Keep the captures in step** (§4) and write any finished minutes.

## 4. Counting loss from headers

Per captured connection, one pipeline:

```
dumpcap -q -i <iface> -s 96 -f "host R and tcp port P and tcp port L" -w -  |  tshark -l -n -r - -Y tcp.len>0 -T fields ...
```

Why this shape:

- **The first 96 bytes (`-s 96`).** IP + TCP headers fit in 96 bytes, and
  the analysis needs nothing more: the TCP length comes from the IP
  header's total length, and loss detection works on sequence numbers.
  Verified on live game traffic (packet counts match the kernel's) and by
  the test that cuts a segment out of a header-only stream. The limit is
  not exactly the headers: when they are shorter, the first bytes of the
  payload (which in a game includes chat) come along — on a WireGuard
  device there is no link header, so IPv4 (20) + TCP with timestamps (32)
  leaves 44 bytes of payload per packet. They exist only in the pipe and
  in tshark's memory; tshark prints only the fields in `TSHARK_FIELDS`, and
  nothing reaches the disk. A tighter limit would have to keep the
  sequence numbers of IPv6 packets on an Ethernet device (14 + 40 + 20
  bytes) and has not been verified against tshark's analysis of truncated
  TCP options.
- **A pipe, not `tshark -i`.** `tshark -i` makes dumpcap spool to a
  temporary file in `/tmp` that grows for the whole session; through the
  pipe nothing is written to disk at all.
- **One pipeline per connection.** Connections start and end independently,
  and neither ever restarts another, so the TCP analysis of a long-lived
  connection keeps its state for the connection's whole life. The first
  version shared one pipeline per interface and restarted it whenever the
  set changed; with `--program AION2.exe` the game's short HTTPS requests
  restarted it every few seconds, each time resetting the analysis of the
  game server's connection.
- **The filter names the connection exactly** (remote host, remote port,
  local port), so other traffic — even to the same server — costs nothing.
  A connection whose interface changes gets a new pipeline on the new one
  (`capture-stop ... moved to`).

Stopping a pipeline stops dumpcap only; tshark reads what is left in the
pipe, reaches end of file and exits, so no captured packet is dropped on the
floor. dumpcap's own exit line (`Packets received/dropped on interface ...`)
is appended to the `capture-stop` event: packets the kernel dropped before
dumpcap saw them would be invisible losses, and that line is the only place
they show.

Per connection and minute (`losses.csv`), for data packets **from the remote
end**:

| Column | Meaning |
|---|---|
| `data_pkts` | packets with data |
| `lost_gaps` | sequence jumps (`tcp.analysis.lost_segment`). A burst of consecutive losses is **one** gap. |
| `retrans` | retransmissions by the remote end (`tcp.analysis.retransmission`) — the closer count of packets actually lost |
| `covered_s` | seconds of that minute the pipeline was running |

A quiet minute is a row of zeros with `covered_s` 60, never a missing row;
a minute the capture did not fully see has a smaller `covered_s`. A
restart mid-minute produces two rows for that minute, one per pipeline.

A pipeline that dies on its own (`capture ended: <dumpcap/tshark stderr>`)
is retried after `RETRY_AFTER_S`.

## 5. Probes

On the probe thread, so a slow `tracepath` never delays a sample.

Every `PROBE_PERIOD_S` (60 s), in parallel, `PING_COUNT` pings per target:

- **targets**: the remote host of every watched connection (role
  `connection`) and the extra targets (`--target`, default 8.8.8.8 and
  1.1.1.1, role `extra`);
- **over the route the system uses now** (`bound=no`; the interface is
  looked up with `ip -j route get`);
- **while a VPN is up, also bound to each direct interface** (`ping -I`,
  `bound=yes`) — the comparison needs the direct path's state while the
  traffic goes through the VPN. A direct interface is a non-VPN interface
  with a default route in the main table; an address alone does not make
  one (Proton's kill switch adds a `dummy` device, `ipv6leakintrf0`, with
  IPv6 addresses that lead nowhere). Proton's kill switch does let
  `ping -I <direct>` through (verified 2026-11-08); a VPN client that
  blocks it leaves the error in the row;
- **the tunnel's first hop** for each VPN interface: NetworkManager's
  gateway for the device, else its first DNS server (role
  `vpn-gateway(<iface>)`). When neither is known, a `probe-skip` event says
  the tunnel's first hop was not probed;
- **the VPN server's public address, outside the tunnel**, through each
  direct interface (role `vpn-endpoint(<iface>)`, `bound=yes`). The address
  is the WireGuard peer's endpoint in NetworkManager's settings for the
  connection (`nmcli -g wireguard.peers connection show id <name>`,
  `interfaces.read_vpn_endpoint`; no root needed). Next to the tunnel's
  first hop it tells where the ping's jumps start (§10, Recently): jumps
  seen outside the tunnel too come from the route to the VPN server; jumps
  only inside come from the server itself. Measured 2026-11-10 on Proton
  NL-FREE#244: the far end answered in 34.5 ms through the tunnel and the
  public address in 36 ms outside it. A VPN that is not a WireGuard
  connection in NetworkManager has no known address; one `probe-skip`
  event per interface and connection says so.

Targets from connections: the remote hosts of the busiest captured
connections, at most `MAX_CONNECTION_TARGETS` (4).

**Pings over one path run one after another; different paths run in
parallel** (`probes.run_serial_per_path`). ICMP through a VPN tunnel can be
rate limited per client. Measured 2026-11-08 on a Proton free server: one
ping stream at 5/s lost nothing, two at once lost 85 %, eight lost
95–100 %, while the direct path took thirty at once without loss. The first
version pinged every target in parallel and recorded 95–100 % "loss"
through the VPN while the game's own TCP traffic over the same tunnel had
no retransmission at all — it measured itself. Hop pings after a trace run
one at a time for the same reason.

A ping that could not be sent (exit status 2, or ended by a signal) is an
**error**, not 100 % loss. Errors are also `probe-error` events.

When recording stops, the probe thread finishes the ping in progress and
starts no other (`stop` in `run_serial_per_path`, `trace_via` and
`trace_route`); the skipped pings are not written at all rather than
written as failures. A running `tracepath` is killed (`probes.run_stoppable`
polls the stop flag every 0.2 s): to a server that stops answering it runs
for tens of seconds, and Quit used to wait for it — 22 and 30 s measured on
2026-11-10. A trace cut short returns `probes.STOPPED` and is written
nowhere — not to `hops.csv`, `routes.csv` or the events. Before this, a
direct trace stopped while its hops were being pinged was judged anyway,
and the unpinged server read as "no answer from the target"; a tunnel
trace wrote its unpinged hops as "no reply to tracepath".

### Route traces

When: every `TRACE_PERIOD_S` (300 s) for the connection targets; after a
mark for all targets; and **at once after a direct-path monitor minute
(§5a) lost `CAL_PING_BAD_PCT` or more of at least `LOSS_TRACE_MIN_PINGS`
pings** (event `watch-loss`), at most once per server every
`LOSS_TRACE_COOLDOWN_S` (120 s) — the loss is most likely still there, and
the trace says where it starts.

How (`Engine._trace_paths`):

- **The direct path, through every direct interface** —
  `probes.trace_via`: `ping -I <iface> -t <ttl>` for ttl 1, 2, …; the router
  that many hops away answers "Time to live exceeded", the target answers
  normally. Two tries per hop. It needs no privileges and, being bound to
  the interface, it traces the direct path even while a VPN is up — which
  `tracepath` cannot (it has no interface option). It also reaches servers
  tracepath does not: on the AION 2 server, tracepath stopped at hop 9, the
  TTL probe reached hop 11 (verified 2026-11-09). Every answering hop is
  then pinged (`PING_COUNT`) through the same interface, one at a time.
- **With a VPN up, also the system's route** (the tunnel) with
  `tracepath -n`, hops pinged one at a time as before.

Both write `hops.csv` (the path column tells them apart). Each direct trace
is then judged (`probes.classify_route`) and written to `routes.csv`, and
as a `route` event:

| Verdict | Hop pings (a hop is losing at `HOP_LOSSY_PCT` 10 %, 2 of 20) |
|---|---|
| `real` | loss starts at a hop and continues on every later answering hop to the server — loss on the path; the starting hop is named |
| `target-only` | only the server loses — the last segment, or the server limiting ping |
| `hop-limit` | the server is clean; single hops before it lose — those routers limit their own ping replies, the path is fine |
| `clean` | nothing loses |
| `no-answer` | the server does not answer ping; the route cannot be judged |
| `error` | the trace failed (the reason is in the text) |

Hops that answer no ping at all (0 of 20) are skipped, not counted as
losing: many routers never answer. The starting hop's reverse-DNS name is
added when the system resolver has one (`probes.reverse_name`, cached) —
no address is sent to an outside lookup service.

## 5a. Direct-path monitor

Comparing a direct period with a VPN period compares two times, not two
paths: a route's bad periods come and go within minutes, so whichever path
happened to get the calm stretch looks better. The monitor measures the
direct path **in the same minutes** the traffic uses the VPN.

`MonitorManager` (in `Engine.step`) keeps one `ping -D -O -i 1 -W 1 -I
<direct iface> <server>` running per pair of:

- server: the remote hosts of the busiest captured connections, at most
  `MONITOR_MAX_TARGETS` (2) — for a game, its server;
- direct interface: every non-VPN interface with a default route.

It runs whichever path the traffic itself is on. The direct path is not
rate limited the way the tunnel is (§5), so a steady 1/s stream measures
the path; Proton's kill switch lets it through (verified 2026-11-09: 60 of
60 replies a minute while the game ran through the tunnel). A new server
(the game reconnects elsewhere) starts a new ping and stops the old one
(`monitor-start` / `monitor-stop` events).

`monitor.csv`, per server, interface and minute: pings sent in that minute,
replies, loss %, RTT median and maximum, `covered_s`. A ping belongs to the
minute it was sent in — a reply's send time is its arrival minus its RTT,
a miss's is ping's "no answer yet" minus the wait — and a reply that comes
after its miss turns the miss back into a reply. A minute in which no ping
went out is a row with `sent` 0, not a missing row.

## 6. Marks

`vpnct mark` (or the display's button) records "it stutters now" in
`events.log` and starts an immediate probe round with route traces for all
targets. From the command line it reaches the recorder through `SIGUSR1`;
the recorder's pid is in `$XDG_RUNTIME_DIR/vpn-connection-test.pid`.

## 7. Session files

`$XDG_DATA_HOME/vpn-connection-test/sessions/<YYYY-MM-DD_HHMMSS>/`
(default `~/.local/share/...`). Rows are written line-buffered, so an
interrupted session keeps everything up to its last second.

| File | One row per | Columns |
|---|---|---|
| `session.json` | session | version, start, host, selection, extra targets, periods |
| `samples.csv` | second × watched connection | time, program, local, remote, path, `rtt_ms`, `rttvar_ms`, `minrtt_ms`, `d_bytes_in`, `d_data_segs_in`, `d_retrans` (our retransmissions), `d_ooopack` (segments that arrived out of order — rises with loss) |
| `losses.csv` | minute × captured connection | §4 |
| `probes.csv` | ping | time, target, role, bound, interface, path, sent, received, `loss_pct`, `rtt_min/avg/max`, error |
| `hops.csv` | hop × trace | time, target, path, hop, address, sent, received, `loss_pct`, `rtt_avg`, error |
| `monitor.csv` | minute × monitored server × direct interface | §5a |
| `routes.csv` | judged direct trace | time, target, interface, path, trigger (`schedule`, `mark`, `watch-loss`), verdict, start_hop, start_address, target_loss_pct, hops, text (§5) |
| `events.log` | event | time, kind, text |

Event kinds: `start`, `stop`, `watch`, `closed`, `path-change`,
`counters-reset`, `interfaces`, `capture-start`, `capture-stop`,
`capture-error`, `monitor-start`, `monitor-stop`, `monitor-error`,
`watch-loss`, `route`, `probe-error`, `probe-skip`, `trace-error`, `mark`,
`error`.

Addresses and names only; no packet content.

## 8. The report

`vpnct report [session ...]` (default: the latest session) groups watched
connections by **program, remote port and path** — here every VPN server
is its own path; the window's cards and the recommendation join servers
into families (§10). The remote port stands for
the service: a game talks to several servers (game server, login, store,
telemetry), and the main server's numbers must not be averaged with the
others. Times are wall-clock: parallel connections in one group count each
second and each captured minute once.

- **RTT p50/p95** — from `samples.csv`, only seconds in which data arrived
  (the kernel updates RTT only on traffic).
- **jumpy min** — minutes in which the ping jumped, of the minutes with
  enough seconds to tell (§10, Jumpy minute).
- **loss %** — remote retransmissions per captured data packet;
  **rtx/min** — per captured minute; **worst min %** — the worst single
  minute with at least 50 data packets.
- **Probes** per target, role, path and binding. A target that answered
  nothing in every round "does not answer ping" — that is a host that
  ignores ping, not 100 % loss. **jumps** counts the rounds whose slowest
  reply came `PROBE_SPIKE_MS` (20 ms) or more after the fastest.
- **Hops**: loss that continues to the last hop is real; loss at one hop
  only is that router limiting its own replies.

**DIRECT-PATH MONITOR** summarises `monitor.csv` per server and direct
path: full minutes (at least `CAL_MIN_PINGS` 50 pings and `CAL_MIN_COVER_S`
55 s; the rest are counted as `short`), bad minutes (ping loss at least
`CAL_PING_BAD_PCT` 3 %, i.e. two or more of 60), and — the point of it —
how many of those minutes the traffic to that server used a VPN (`on VPN`)
and how many of them the direct path was bad (`bad then`): the minutes in
which the VPN actually spared the connection something.

Each bad monitor minute is checked against the first direct trace of the
same server and interface made during it or within `ROUTE_WINDOW_S`
(240 s) after it (`report.route_verdict_for`): **real** when the trace saw
`real` or `target-only` loss, **dismissed** when it saw only `hop-limit`,
otherwise unverified (no trace in time, or `clean` — the loss may simply
have ended). A ping that a single router limits is the one way ping loss
misleads; this is where it is caught.

**CALIBRATION** asks whether ping on the direct path can stand in for TCP
loss at all, before anything relies on it. It pairs each full monitor
minute with the TCP minute of the connections to the same server on the
same interface (at least `CAL_MIN_DATA` 100 data packets) — possible only
while the traffic itself goes directly. A TCP minute is bad at
`CAL_TCP_BAD_PCT` (0.5 %) retransmissions. Until `CAL_MIN_BAD` (5) bad
TCP minutes have been seen the status is **unconfirmed**; after that it is
**confirmed** when ping flagged at least `CAL_SENSITIVITY` (80 %) of the
bad TCP minutes and at least `CAL_PRECISION` (70 %) of its alarms were
real, and **not reliable** otherwise. The one earlier case (17 Oct 2026:
14–22 % ping loss with 13 % TCP loss) suggests it will hold, but one case
is not a measurement.

Under the table, **COMPARISON** states, for each service, how each VPN path
compares with each direct path (`report.compare_paths`): a path with fewer
than `MIN_MINUTES_FOR_VERDICT` (5) captured minutes gets "not enough data
yet" instead of a judgement; otherwise it says whether the VPN reduced loss
(direct at least `LOSS_NOTICEABLE_PCT` 0.5 % and the VPN under a quarter
of it), whether both were nearly loss-free (then the VPN only costs its
extra RTT), or whether the VPN lost more. The window shows the same lines.

## 9. The tray program

`vpnct-gui` runs an `Engine` in its own process and only displays it.

The window opens maximized the first time it is shown (`App.show_window`);
after that it keeps the size it was given when it is hidden and shown again.
The window has two views, switched by **Advanced** in its header:

- **Overview** — the answer to "which path should I play on?" for one
  service (the busiest one with enough judged minutes is chosen first):
  a banner with the live hint (§10) and the path in use; the **Recently**
  panel (`advice.recent_view`, §10) for the last 15 min / 1 h / 3 h of this
  session; one card per tested path (`advice.path_cards`) with five
  numbers — one card per VPN server family (§10), its servers named in the
  subtitle's tooltip;
  the chart; the recommendation's headline. The cards read the all-sessions summary by
  default ("This session" switches to the current session's).
- **Advanced** — everything else: status, the full comparison table,
  calibration, the recommendation's reasoning, the last probes, events,
  Compare sessions…, the session folder.

Card numbers:

| Number | Meaning | Source |
|---|---|---|
| Ping | median RTT over seconds with data | `Group.rtts` |
| Spikes | RTT p95 minus median — how far the ping jumps above usual | `Group.rtts` |
| Steady ping | minutes in which the ping did not jump, of those with enough seconds (§10); shown this way round so that, like Stability, more is better | `Group.ping_minutes`, `spiky_minutes` |
| Stability | judged minutes that were not bad (§10) | `Group.judged_minutes`, `bad_minutes` |
| Loss | remote retransmissions per captured data packet | `report.loss_pct` |

"Spikes" is not the kernel's `rttvar`. Measured on the AION 2 recordings
(2026-11-09): `rttvar` had a median of 12–16 ms on every path, including the
direct one whose RTT moved by 3 ms between seconds — it counts delayed
acknowledgements and the server's own pacing, and would have shown the
steadiest path as shaky. p95 minus median was 3 ms direct, 7–9 ms through
the VPN servers.

**★ Best** goes to one card, and only when at least two paths have
`REC_MIN_SERVER_MINUTES` judged minutes: the highest stability; among
equally stable paths the steadier ping (by level of jumpy minutes: under
`JUMPY_FAIR_PCT` 5 %, under `JUMPY_POOR_PCT` 20 %, or more — Steady ping
95 % and over, 80 % and over, below), then the
lowest ping (loss below the bad-minute threshold is not felt); loss only
breaks a tie. The badge says which ("most stable", "as stable, steadier
ping" or "as stable, lowest ping"). A path with fewer minutes says "Little data". Cards
count only sessions with judged minutes on that path, the same basis as the
recommendation.

Look: a fixed dark theme (`THEME`, `STYLE`, `apply_theme`: Fusion style,
palette and one stylesheet), so the window is the same on any desktop
theme; the chart is painted with the same colours.

- **Settings**: command-line options as for `vpnct record`; without them,
  `config.toml` (`vpnct/config.py`: `programs`, `ports`, `targets`). An
  unreadable file or an unknown key is shown in a message box and the
  program does not start — it never falls back to defaults silently.
- **One recorder at a time**: `cli.claim_pidfile` refuses to start when the
  pid in `$XDG_RUNTIME_DIR/vpn-connection-test.pid` is alive. Two
  recorders would ping through one tunnel at once (§5). The window also
  answers `vpnct mark` through the same pidfile.
- **Direct path watch**: the status shows the monitor's last minute per
  server; the calibration status is shown under the comparison.
- **Live data**: every second the window takes `Engine.drain_updates()` —
  one `SecondPoint` per watched connection and second (with its remote
  host and local port, so jumps are judged per connection), one
  `MinutePoint` per captured connection and minute, the monitor's minutes,
  route results and probe rounds — into an in-memory history (3 h) per
  service, and `Engine.snapshot()` for the status, probes and events.
- **Comparison**: every 15 s a worker thread runs `report.summarise` on the
  session's files (plus any sessions picked with Compare sessions…) and the
  table shows its groups for the chosen service. It is the report's own
  calculation, so the window and `vpnct report` cannot disagree.
- **Tray icon** colour: the newest captured minute of the busiest service —
  green no retransmission, yellow some, red `LOSS_RED_PCT` (2 %) or more,
  grey nothing captured. A desktop without a system tray gets the window
  at start instead.
- **Quit** stops the engine on a background thread and leaves once the
  session is closed. The probe thread stops between pings and kills a
  running `tracepath` (§5), so this takes at most about one ping, a few
  seconds; measured 1.8 s, and 0.2 s with `tracepath` running
  (2026-11-10). SIGTERM and SIGINT
  take the same path.

`vpnct install-desktop` writes
`~/.local/share/applications/vpn-connection-test.desktop`, running
`vpnct-gui` from PATH (else this interpreter with `-m vpnct.gui`), with
`vpnct/icon.svg` as its icon.

## 10. Hint and recommendation

Both only read what the recorder wrote, and neither switches anything:
dropping a VPN under a live connection can break the program using it (a
game freezes when its address disappears), so the person picks the moment.

**Bad minute** — one definition everywhere (`report.MinuteAgg`,
`CAL_*` constants): for the connection's own traffic, at least
`CAL_TCP_BAD_PCT` 0.5 % retransmitted of at least `CAL_MIN_DATA` 100 data
packets, over a minute whose least-covered connection was captured at least
`CAL_MIN_COVER_S` 55 s; for the direct-path watch, at least
`CAL_PING_BAD_PCT` 3 % of at least `CAL_MIN_PINGS` 50 pings lost. A
connection's capture that restarted within a minute leaves several rows for
it; their coverage is **summed** (they do not overlap). The first version
took the minimum, which dropped every minute with a restart from judgement
— 12.5 minutes on one VPN server counted as under 10.

**Jumpy minute** (`report.spiky`, `report.RttMinute`) — counted beside the
bad minute, never instead of it. The connection's ping jumped within the
minute although nothing need have been lost: of one connection's seconds
with data in that minute (at least `SPIKE_MIN_SECONDS` 30), the 95th
percentile is `SPIKE_SPREAD_MS` (10 ms) or more above the minute's median,
or one second is `SPIKE_MAX_MS` (30 ms) or more above it. A minute is
jumpy when any of its connections was; each connection is judged alone,
since two game servers in one minute sit at different levels.

Why against the minute's own median: the obvious baseline, the kernel's
`minrtt`, is wrong. Measured on the recordings to 2026-11-10, the direct
path's TCP RTT sits a steady 10–15 ms above `minrtt` (delayed
acknowledgements), so "seconds 20 ms above `minrtt`" came out worse for the
steady direct path than for the VPN servers. Against the minute's median,
the thresholds split the paths cleanly: 1 % of the direct path's minutes
were jumpy, 14–34 % of the Proton free servers' (2026-11-08 to
2026-11-10). A whole minute at a higher level — a connection whose RTT sat
at 47 ms instead of 35 for ten minutes — is not a jump; it shows in Ping.

Jumps are reported everywhere loss is: on the cards, in Recently, in the
live hint's text and in the recommendation. They order paths that are
equally stable. They never decide a switch by themselves: a switch costs a
trip to character select, and the project's criterion (§10,
Recommendation) is loss.

**VPN server families** (`report.path_family`, `report.by_family`) — the
cards, Recently and the recommendation judge VPN servers by family: the
connection name without its trailing server number, so "ProtonVPN
NL-FREE#244" and "ProtonVPN NL-FREE#221" are both "ProtonVPN NL-FREE".
A family is what a person actually chooses (a country, a plan); a numbered
server often cannot be picked again, and each alone gathers few minutes
(12–40 judged minutes per Proton free server by 2026-11-10). The servers do
differ — NL-FREE#1's far end answered in 42 ms, #221 and #244 in 35 ms —
so the recommendation lists each family's servers under it, and the report
and the Advanced table keep one column per server. Names without a number,
and direct paths, are their own family.

### Live hint (`advice.live_hint`)

For the busiest service (tray) and the chosen one (window), from the
in-memory minutes of this session:

| Traffic on | Situation | Hint |
|---|---|---|
| direct | `RECENT_BAD` (2) of the last `RECENT_MINUTES` (3) judged minutes bad | **switch** to the VPN at the next safe moment |
| direct | otherwise | ok, or unknown with fewer than 3 judged minutes |
| VPN | the VPN's own minutes losing, the direct watch clean | **return** (or try another server) |
| VPN | both losing | stay, try another server |
| VPN | the direct watch losing (2 of the last 3 minutes) | stay — the VPN is sparing you this |
| VPN | the direct watch clean for `CLEAN_MINUTES` (10) in a row | **return** at the next safe moment |

Two of three rather than one: one bad minute is a blip, and a switch costs
the user a trip to character select. Ten clean minutes before suggesting a
return: the bad periods seen so far lasted minutes, so a shorter calm says
little. A hint resting on the direct-path ping says so as long as the
calibration (§8) is not confirmed. When the connection's ping jumped in
`RECENT_BAD` of its last `RECENT_MINUTES` minutes on the path in use, the
hint's text says so (from the last `HINT_JUMPY_LOOKBACK_S` 600 s of
seconds); its level does not change. A change to **switch** or **return** is
also a tray notification, once per change.

### Recommendation (`advice.recommend`, `vpnct recommend`, window)

Over all sessions (window: recalculated every minute and on request) or the
named ones, per service with at least `REC_MIN_SERVER_MINUTES` (10) judged
minutes on some path — a program's side connections are listed, not
judged. The criterion is the project's: a VPN is worth it if it keeps loss
near zero in the periods the direct path is bad, at an acceptable latency;
without bad periods the direct path wins.

1. **Direct-path exposure**: judged minutes of direct traffic, plus the
   direct-path monitor's minutes while on the VPN — counted when ping is
   confirmed as a stand-in, **provisionally** while the calibration has not
   yet seen the bad minutes it needs, and not at all once it is refuted.
   Of the monitor's bad minutes, those a route trace dismissed are not
   counted (§8). The evidence is asymmetric, which is why this is
   defensible before calibration: a clean ping minute is strong evidence
   (the connection's packets take the same route, so loss on it would show),
   a lossy one is weaker (routers may limit ping) — and the weak case is
   the one the trace checks. A recommendation resting on unconfirmed ping
   is headed "Provisional (direct path partly judged by ping)", and its
   reasoning lists how many bad minutes were confirmed, dismissed and
   unverified.
2. **Not enough data** below `REC_MIN_DIRECT_MINUTES` (120) of exposure or
   `REC_MIN_SESSIONS` (3) sessions with it: one evening can be all calm or
   all bad, and the answer depends on how often bad evenings come.
3. **VPN server families** with at least 10 judged minutes are ranked by
   bad-minute fraction, then level of jumpy minutes (as on the cards), then
   loss, then RTT. Each is listed with its Steady ping next to the direct
   path's, and with its servers. The RTT cost against the direct path says
   how many seconds of direct traffic it rests on, and that it is too few
   below ten minutes' worth.
4. Verdict, with `frac` = bad direct minutes / exposure:
   - `frac` < `REC_RARE` (2 %): **stay direct** — a VPN costs latency every
     minute to spare a few; the headline names the best family's latency
     cost and its Steady ping;
   - no ranked server: the direct path's rate, no server to name;
   - best server's bad fraction at least half of `frac`: **the VPN does not
     help**;
   - `frac` ≥ `REC_OFTEN` (10 %): **use the VPN** (best server named);
   - in between: **use the VPN only when the direct path is losing** — by
     the tray's hints if ping is confirmed, by "when it stutters" if not.

`vpnct report` ends with the same recommendation over the sessions it was
given.

### Recently (`advice.recent_view`, window)

What each path did over the last 15 min, 1 h or 3 h of this session, from
the window's in-memory history: per path (VPN servers by family) of the
connection's own traffic, judged minutes, minutes with loss, jumpy minutes
and ping; while on a VPN, the direct-path monitor's minutes, lost-ping
minutes and minutes with a ping `SPIKE_MAX_MS` over the minute's median
(raw ping, so a looser measure than the connection's smoothed RTT); the
**Tunnel** line; the latest route verdict. Then one conclusion.

The **Tunnel** line (`advice._tunnel_line`) counts the jumpy probe rounds
(§8) to the VPN server through the tunnel (`vpn-gateway`) and outside it
(`vpn-endpoint`), and says where the jumps start:

| Rounds that jumped | Says |
|---|---|
| fewer than `TUNNEL_JUMPY_MIN` (2) on both sides | steady up to the VPN server — any jumps come from beyond it |
| outside at least half as often as inside | the jumps start on the route to the VPN server |
| inside only (or far more often) | the VPN server itself adds them (its load) |
| nothing outside was pinged | where they start cannot be told |

The window receives every probe round as an `engine.ProbePoint` through
`Engine.drain_updates()`. The conclusion:

| Traffic on | Situation | Conclusion |
|---|---|---|
| VPN | the VPN server lost packets in `RECENT_BAD` (2)+ minutes | try another server or the direct path |
| VPN | the direct path lost pings in 2+ minutes, a trace saw real loss (or none ran yet — then said so) | the VPN spared you this, with where loss starts |
| VPN | the direct path lost pings, but the trace saw only routers limiting replies | the direct path itself looked fine |
| VPN | the direct path clean for all of at least `RECENT_MIN_CLEAN` (10) watched minutes | the VPN is not needed right now, with its RTT cost, and how often its ping jumped when that was `RECENT_BAD`+ minutes and above `JUMPY_FAIR_PCT` |
| direct | 2+ minutes with loss | switch to the VPN, naming the best one so far |
| direct | otherwise | stable (with the minutes the ping jumped, if any) |

The RTT cost and the best VPN come from the cards (all sessions, the
connection's own RTT on both paths): the monitor's ping RTT is not
comparable with a TCP connection's RTT, which also counts delayed
acknowledgements (measured: 17.5 ms ping against 32 ms TCP to the same
server).

## 11. Failure modes

| Symptom | Meaning |
|---|---|
| `NOT captured` next to a watched connection | its path is `gone(...)`, or its interface's pipeline is down — see the `capture-*` events |
| `capture-stop ... dropped N` with N > 0 | the kernel dropped packets before dumpcap; that minute's loss is undercounted |
| `probe-error ... -I <direct iface>` while a VPN is up | the VPN's kill switch blocks traffic outside the tunnel; the direct path cannot be probed in parallel |
| high ping loss over a VPN path, no retransmissions in `losses.csv` for the same path | ICMP limited by the VPN server; trust the TCP numbers. Check that nothing else pings through the tunnel at the same time |
| `trace-error ... interrupted by SIGINT` | the recorder was stopped with Ctrl+C while a trace ran (the signal reaches the whole process group) |
| `probe-skip ... public address is not known` | the VPN is not a WireGuard connection in NetworkManager; the Tunnel line (§10) cannot say where jumps start, jumps are still counted |
| `counters-reset` | a socket was replaced between two samples on the same 4-tuple; rare, harmless |

## 12. Tests

`python3 -m unittest` in the repository root. Parsers are tested on recorded
output shapes with documentation addresses. `tests/test_capture.py` runs the
shipped tshark command on a generated header-only TCP stream with one
missing and one retransmitted segment, and has dumpcap compile a generated
filter; both are skipped where those programs are absent. The tracker tests
use a public resolver address as the remote end, because documentation
ranges are not global and would — correctly — be filtered out.

CI (`.github/workflows/tests.yml`) runs the same suite on every push to
`develop` and `main`, with tshark installed and capabilities set on dumpcap
so the capture tests run rather than skip.

## 13. Packaging and releases

The distribution is `vpn-connection-test` on PyPI, installed with
`pipx install vpn-connection-test`; it provides `vpnct` and `vpnct-gui`.
PyQt6 is its only dependency; the system tools of §2 are not Python
packages and are listed in `docs/INSTALL.md`.

**Version.** Built by hatchling with `hatch-vcs`: the version is the git
tag (`v0.1.0` → `0.1.0`), written at build time to `vpnct/_version.py`
(ignored by git) and read by `vpnct/__init__.py` into `__version__`, which
goes into every `session.json`. A source tree that was never built or
installed reports `0+unknown`; a build between tags is a development
version, such as `0.1.1.devN` after `v0.1.0` (`local_scheme =
"no-local-version"` keeps it PEP 440 clean). There is no version to edit
by hand.

**What a package contains.** The wheel holds `vpnct/` with `icon.svg`.
The sdist is an explicit include list (`[tool.hatch.build.targets.sdist]`
in `pyproject.toml`): `vpnct/`, `tests/`, `docs/`, `README.md`,
`CHANGELOG.md`, `LICENSE`. It is a list rather than "everything git
tracks" so that `notes/` — private, never committed — cannot reach a
package even from a working tree where it exists.

**Branches.** Work happens on `develop`; `main` only moves at a release,
by fast-forward from `develop`.

**Release** (`.github/workflows/release.yml`, on a published GitHub
Release):

```
tag vX.Y.Z on main ──► GitHub Release ──► build job ──────────► pypi job
                                           unit tests            downloads the
                                           python -m build       attached files,
                                           checks:               publishes with
                                            icon in the wheel    PyPI Trusted
                                            no notes/ in sdist   Publishing
                                            wheel version = tag  (no token)
                                           attach to the release
```

The `pypi` job uploads exactly the files the `build` job checked and
attached, so what is on PyPI is what is on the release page. A version
mismatch between the wheel and the tag stops the release before anything
is uploaded; the usual cause is a tag on a different commit than the one
checked out. `workflow_dispatch` runs the build alone and keeps the files
as a workflow artifact, for checking a build without releasing.

`CHANGELOG.md` says what changed for users, one section per version; the
release notes are that section.
