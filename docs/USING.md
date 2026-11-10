# Using vpn-connection-test

This guide explains what the program shows, how it reaches its advice, and
how to use it to find out whether a VPN is worth it for you. Installing is
in [INSTALL.md](INSTALL.md).

## The idea

A game stutters when packets get lost on the way: the connection holds
everything back until the lost packet is sent again. Such loss usually
happens on one stretch of the internet route, comes in bad periods of a
few minutes, and goes away again. A VPN takes a different route. It helps
only if that route avoids the bad stretch, and it always adds a little
latency.

So the program watches two things at once:

- **the program's own connection** — on whichever path it uses right now
  (your normal connection, or a VPN server), it counts lost packets and
  measures the round trip, minute by minute;
- **your normal connection, all the time** — once a second it pings the
  same server through your normal connection, even while the game goes
  through the VPN. That is how it knows whether the VPN spared you
  something in these very minutes, rather than comparing a calm evening on
  one path with a bad evening on the other.

When the normal connection starts losing pings, it traces the route right
away to see where the loss begins: at a router somewhere along the way
(real trouble on the route), only at the server, or only at a single router
that simply answers pings sparingly (a false alarm).

Everything it says comes from these measurements, and it never switches
anything itself: dropping a VPN under a running game can freeze it. It
tells you, and you switch at a safe moment — for a game, at character
select or before logging in.

## Quick start

1. Start **VPN connection test** from the menu. It starts recording at once.
2. Play as usual on your normal connection for a while.
3. Next time, play through the VPN. Try other VPN servers on other days.
4. Open the window from the tray icon and read the cards and the
   recommendation.

The more sessions on each path, the firmer the answer: a single evening can
be all calm or all bad.

## The tray icon

| Icon | Meaning (the last minute of the busiest connection) |
|---|---|
| green | no packet lost |
| yellow | some packets lost |
| red | 2 % or more of the packets lost |
| grey | nothing measured yet |

Hovering shows the path in use, the round trip and the last minute's
numbers. Clicking opens the window. The right-click menu has
**It stutters now** and **Quit**. Closing the window only hides it;
recording goes on until **Quit**.

When the advice changes to "switch to the VPN" or "you can go back", a
desktop notification says so, once per change.

## The window

```
┌─ VPN connection test ────────────────────────────────────────────┐
│ AION2.exe :13328                     [It stutters now] [Advanced]│
├──────────────────────────────────────────────────────────────────┤
│ Direct path is losing packets — switch to the VPN at the next    │
│ safe moment.              Now on: direct:eth0   ping 32 ms       │
├──────────────────────────────────────────────────────────────────┤
│ Recently                            [15 min] [1 h] [3 h]         │
│  direct      40 min, packets lost in 3, ping jumped in 0 of 40   │
│  The direct path lost packets in 3 of 40 minutes — switch to the │
│  VPN (VPN · NO).                                                 │
├──────────────────────────────────────────────────────────────────┤
│ Tested paths                        [This session] [All sessions]│
│ ┌ Direct ──────────┐ ┌ VPN · NO ★ Best ──┐ ┌ VPN · NL ────────┐  │
│ │ Ping     32 ms   │ │ Ping     43 ms    │ │ Ping     45 ms   │  │
│ │ Spikes   3 ms    │ │ Spikes   7 ms     │ │ Spikes   9 ms    │  │
│ │ Steady ping 99 % │ │ Steady ping 92 %  │ │ Steady ping 71 % │  │
│ │ Stability 90 %   │ │ Stability 100 %   │ │ Stability 100 %  │  │
│ │ Loss     0.40 %  │ │ Loss     0.00 %   │ │ Loss     0.01 %  │  │
│ └──────────────────┘ └───────────────────┘ └──────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│ [ chart: ping and lost packets, path in use shaded behind it ]   │
├──────────────────────────────────────────────────────────────────┤
│ Use the VPN only when the direct path is losing: …               │
└──────────────────────────────────────────────────────────────────┘
```

The window opens on the **overview** for one connection. When several
programs are watched, it picks the busiest one with enough data; the
drop-down list at the top switches between them.

### The banner

What is happening now and what to do: switch to the VPN, stay where you
are, or go back. Under it, the path in use and its ping.

### Recently

What each path did over the last 15 minutes, hour or three hours of this
session, ending in one conclusion: in how many minutes packets were lost,
and in how many the ping jumped. While you play through a VPN it also
says whether your normal connection was losing packets meanwhile, and if a
route trace ran, where on the route the loss started — or that it was only
a router answering pings sparingly.

The **Tunnel** line says where a VPN's ping jumps come from. The program
pings the VPN server twice: through the tunnel, and directly at the
server's public address, outside the tunnel. If the pings jump outside the
tunnel too, the jumps start on the way to the VPN server; if they jump only
inside, the VPN server itself adds them — busy free servers do. If neither
jumps, the jumps you see come from further on, between the VPN server and
the game. Typical conclusions:

| Conclusion | What it means |
|---|---|
| … — the VPN spared you this. | the normal route was really losing (the line says from which hop); the VPN was worth it |
| … — the VPN is not needed right now (+11 ms). | your normal connection stayed clean; going back saves the latency |
| … the direct path itself looked fine. | the pings were lost at one router only, not along the route |
| … — try another server or the direct path. | the VPN server you are on is losing packets |
| … — switch to the VPN. | your normal connection is losing packets now |
| The direct path was stable in the last … | nothing to do |

### The cards

One card per path you have used: your normal connection, and each VPN
server family — all the servers whose names differ only in their number,
such as every "NL-FREE#…" server, share one card. That is what you can
choose between; a single numbered server often cannot be picked again, and
alone it gathers few minutes. Hover over the line under the title to see
which servers a card includes; **Advanced** keeps each server apart.

| Number | What it tells you |
|---|---|
| **Ping** | the usual round trip of the connection, in milliseconds |
| **Spikes** | how far the ping jumps above its usual value at its worst moments (the worst 5 %) |
| **Steady ping** | the share of minutes in which the ping did not jump; like Stability, more is better |
| **Stability** | the share of minutes in which no noticeable packet loss happened |
| **Loss** | lost packets out of all packets received |

**★ Best** goes to the most stable path. Among equally stable paths the
one with the steadier ping wins (Steady ping green from 95 %, amber from
80 %, red below), then the one with the lowest ping, because small loss
below the noticeable level is not felt, while latency is felt all the time. The star appears
only once at least two paths have enough data; a path without enough says
"Little data".

The cards count all your recordings by default. **This session** shows
only the current one.

A minute counts as having loss when at least half a percent of its packets
were lost. For the background ping of your normal connection the bar is
3 % of the pings, because a few lost pings are normal.

A minute counts as **jumpy** when, within that minute, the ping rose
clearly above its own usual level: for the slowest few seconds 10 ms or
more, or for a single second 30 ms or more. A ping that sits higher for a
whole stretch is not a jump; it shows as a higher **Ping**. **Steady ping**
is the share of the other minutes: about 99 % on your normal connection,
66–86 % on the free VPN servers measured so far.

Jumps are shown everywhere and help pick the best path, but they never ask
you to switch by themselves; only lost packets do, since a switch means
going back to character select.

### The recommendation

At the bottom, drawn from all your recordings. It names a VPN server
family, and says in how many minutes its ping was steady, next to your
normal connection's:

| Recommendation | When |
|---|---|
| Stay on the direct path | your normal connection rarely has bad minutes; a VPN would cost latency every minute to spare a few |
| Use the VPN | bad minutes on the normal connection are frequent, and the named VPN server family avoids them |
| Use the VPN only when the direct path is losing | bad periods come now and then; follow the banner's hints |
| The VPN does not help | the VPN servers tried lose about as often as the normal connection |
| … no VPN server has enough data | your normal connection has bad minutes, but no VPN server has been used long enough to compare |

Until there are two hours of data about your normal connection, from
three sessions, it says how much is still missing instead of guessing.

The background ping of your normal connection counts towards those two
hours. Whether this ping really tracks the game's own losses is checked
from the minutes you play on the normal connection; until enough bad
minutes have been seen to tell, a recommendation that relies on it is
marked **Provisional**. Pings that a route trace showed to be a false
alarm do not count against your normal connection.

### Advanced

**Advanced** shows everything behind the overview: the full comparison
table, how reliable the background ping has proven, the reasoning behind
the recommendation, the last probes and events, **Compare sessions…** to
add older recordings, and **Session folder** with the log files.

## When it stutters

Press **It stutters now** (in the window or the tray menu). The moment is
noted in the log and the route is traced at once, so the recording shows
what the route looked like right then.

## Choosing what to watch

Without settings the program watches the busiest internet connections by
itself. To watch one program, or connections to one server port, create
`~/.config/vpn-connection-test/config.toml`:

```toml
programs = ["AION2.exe"]     # every connection of these programs
ports = [13328]              # and/or connections to these server ports
targets = ["8.8.8.8"]        # extra ping targets (default 8.8.8.8 and 1.1.1.1)
```

Program names are matched without regard to upper and lower case; for a
Windows game under Wine or Proton, use the name of its `.exe`. Restart the
program after changing the file. If the file cannot be read, a message says
why and the program does not start, rather than quietly ignoring it.

Only one recording runs at a time. Starting a second one says so.

## Switching paths

Switch between the normal connection and the VPN, or between VPN servers,
whenever it suits the program you use. The recorder notices the change by
itself within a second or two and keeps each path's numbers apart. A
connection whose VPN disappeared under it shows as "gone" until it
reconnects.

## From a terminal

The same recorder without a window, stopped with Ctrl+C:

| Command | What it does |
|---|---|
| `vpnct record --program AION2.exe` | record every connection of that program |
| `vpnct record --port 13328` | record connections to that server port |
| `vpnct record` | record the busiest internet connections |
| `vpnct mark` | "it stutters now", from another terminal |
| `vpnct sessions` | list the recordings |
| `vpnct report` | summary of the latest recording |
| `vpnct report 2026-11-08_230446 ...` | one or several recordings, combined |
| `vpnct recommend` | the recommendation from all recordings |

Each recording is a folder under
`~/.local/share/vpn-connection-test/sessions/` with plain CSV files and an
event log. What every column means is in
[ARCHITECTURE.md](ARCHITECTURE.md#7-session-files).

## What can go wrong

| Symptom | Likely cause | What to do |
|---|---|---|
| Every card says "Little data" for a long time, and Advanced lists `capture` errors | packet capture is not allowed | join the `wireshark` group and log in again — see [INSTALL.md](INSTALL.md#allowing-capture) |
| "Nothing captured yet" in the tray tooltip | the watched program has no lasting connection yet, or the name in `config.toml` does not match | check the program name in `config.toml` |
| Very high ping loss through the VPN, but the cards show no loss on it | some VPN servers (Proton's free ones among them) limit ping; the program pings one target at a time there, but anything else pinging through the tunnel adds to it | trust the cards; they count the program's own packets |
| Errors about the direct interface while the VPN is on | the VPN's kill switch blocks traffic outside the tunnel | the normal connection cannot be watched in parallel with this VPN; compare sessions on each path instead |
| "A recorder is already running" when starting | a recording is already active (perhaps from a terminal) | use the running one, or stop it first |
| No tray icon | the desktop has no system tray | the window opens at start instead; on GNOME, install the AppIndicator extension |

## Questions

**Do I need sessions without the VPN at all?**
Yes, some. The background ping covers your normal connection while you
play through the VPN, but whether that ping can be trusted is learned only
from minutes you play directly. Until then its findings stay provisional.

**Why is the ping in "Recently" lower than on the cards?**
They measure different things. The cards show the round trip of the
program's own connection, which includes the server's delay in answering;
the background ping is a bare echo. The latency cost of a VPN is therefore
always taken from the cards, comparing like with like.

**Does it slow the game down?**
No noticeable amount: one ping a second to the game's server, a short
burst of pings each minute, and a route trace now and then.

**Does it switch the VPN for me?**
No. Switching under a running game can freeze it, so the choice of moment
stays with you.
