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

- **Headers only (`-s 96`).** IP + TCP headers fit in 96 bytes; payload
  (which in a game includes chat) is never captured. The TCP length comes
  from the IP header's total length, and loss detection works on sequence
  numbers, so the analysis needs nothing more. Verified on live game
  traffic (packet counts match the kernel's) and by the test that cuts a
  segment out of a header-only stream.
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
  the tunnel's first hop was not probed.

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
starts no other (`stop` in `run_serial_per_path` and `trace_route`); the
skipped pings are not written at all rather than written as failures.

Every `TRACE_PERIOD_S` (300 s) — and for all targets at once after a mark —
`tracepath -n` to each connection target, then a ping to every hop that
answered (`hops.csv`). tracepath cannot be bound to an interface, so a
route always describes the path the system routes over at that moment.

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
| `events.log` | event | time, kind, text |

Event kinds: `start`, `stop`, `watch`, `closed`, `path-change`,
`counters-reset`, `interfaces`, `capture-start`, `capture-stop`,
`capture-error`, `monitor-start`, `monitor-stop`, `monitor-error`,
`probe-error`, `probe-skip`, `trace-error`, `mark`, `error`.

Addresses and names only; no packet content.

## 8. The report

`vpnct report [session ...]` (default: the latest session) groups watched
connections by **program, remote port and path**. The remote port stands for
the service: a game talks to several servers (game server, login, store,
telemetry), and the main server's numbers must not be averaged with the
others. Times are wall-clock: parallel connections in one group count each
second and each captured minute once.

- **RTT p50/p95** — from `samples.csv`, only seconds in which data arrived
  (the kernel updates RTT only on traffic).
- **loss %** — remote retransmissions per captured data packet;
  **rtx/min** — per captured minute; **worst min %** — the worst single
  minute with at least 50 data packets.
- **Probes** per target, role, path and binding. A target that answered
  nothing in every round "does not answer ping" — that is a host that
  ignores ping, not 100 % loss.
- **Hops**: loss that continues to the last hop is real; loss at one hop
  only is that router limiting its own replies.

**DIRECT-PATH MONITOR** summarises `monitor.csv` per server and direct
path: full minutes (at least `CAL_MIN_PINGS` 50 pings and `CAL_MIN_COVER_S`
55 s; the rest are counted as `short`), bad minutes (ping loss at least
`CAL_PING_BAD_PCT` 3 %, i.e. two or more of 60), and — the point of it —
how many of those minutes the traffic to that server used a VPN (`on VPN`)
and how many of them the direct path was bad (`bad then`): the minutes in
which the VPN actually spared the connection something.

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
  one `SecondPoint` per watched connection and second, one `MinutePoint` per
  captured connection and minute — into an in-memory history (3 h) per
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
  session is closed. The probe thread stops between pings (§5), so this
  takes about one ping, a few seconds; measured 1.8 s. SIGTERM and SIGINT
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
calibration (§8) is not confirmed. A change to **switch** or **return** is
also a tray notification, once per change.

### Recommendation (`advice.recommend`, `vpnct recommend`, window)

Over all sessions (window: recalculated every 5 min and on request) or the
named ones, per service with at least `REC_MIN_SERVER_MINUTES` (10) judged
minutes on some path — a program's side connections are listed, not
judged. The criterion is the project's: a VPN is worth it if it keeps loss
near zero in the periods the direct path is bad, at an acceptable latency;
without bad periods the direct path wins.

1. **Direct-path exposure**: judged minutes of direct traffic, plus — only
   once ping is confirmed as a stand-in — the watched minutes while on the
   VPN. Bad minutes counted the same way. Unconfirmed watch minutes are
   listed with the reason they were not counted.
2. **Not enough data** below `REC_MIN_DIRECT_MINUTES` (120) of exposure or
   `REC_MIN_SESSIONS` (3) sessions with it: one evening can be all calm or
   all bad, and the answer depends on how often bad evenings come.
3. **VPN servers** with at least 10 judged minutes are ranked by bad-minute
   fraction, then loss, then RTT. The RTT cost against the direct path says
   how many seconds of direct traffic it rests on, and that it is too few
   below ten minutes' worth.
4. Verdict, with `frac` = bad direct minutes / exposure:
   - `frac` < `REC_RARE` (2 %): **stay direct** — a VPN costs latency every
     minute to spare a few;
   - no ranked server: the direct path's rate, no server to name;
   - best server's bad fraction at least half of `frac`: **the VPN does not
     help**;
   - `frac` ≥ `REC_OFTEN` (10 %): **use the VPN** (best server named);
   - in between: **use the VPN only when the direct path is losing** — by
     the tray's hints if ping is confirmed, by "when it stutters" if not.

`vpnct report` ends with the same recommendation over the sessions it was
given.

## 11. Failure modes

| Symptom | Meaning |
|---|---|
| `NOT captured` next to a watched connection | its path is `gone(...)`, or its interface's pipeline is down — see the `capture-*` events |
| `capture-stop ... dropped N` with N > 0 | the kernel dropped packets before dumpcap; that minute's loss is undercounted |
| `probe-error ... -I <direct iface>` while a VPN is up | the VPN's kill switch blocks traffic outside the tunnel; the direct path cannot be probed in parallel |
| high ping loss over a VPN path, no retransmissions in `losses.csv` for the same path | ICMP limited by the VPN server; trust the TCP numbers. Check that nothing else pings through the tunnel at the same time |
| `trace-error ... interrupted by SIGINT` | the recorder was stopped with Ctrl+C while a trace ran (the signal reaches the whole process group) |
| `counters-reset` | a socket was replaced between two samples on the same 4-tuple; rare, harmless |

## 12. Tests

`python3 -m unittest` in the repository root. Parsers are tested on recorded
output shapes with documentation addresses. `tests/test_capture.py` runs the
shipped tshark command on a generated header-only TCP stream with one
missing and one retransmitted segment, and has dumpcap compile a generated
filter; both are skipped where those programs are absent. The tracker tests
use a public resolver address as the remote end, because documentation
ranges are not global and would — correctly — be filtered out.
