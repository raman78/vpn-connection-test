# vpn-connection-test — context for Claude

What this repository answers: does a VPN make a connection more stable than the
direct route, measured per interface and per route (loss, RTT, where on the
path packets are lost), and is the added latency worth it. Generic tooling;
the first case is the AION 2 game connection through Proton VPN.
Split out of A2Qlinux on 2026-11-08 (`~/Shared/PycharmProjects/A2Qlinux`,
which runs Questlog and since 0.3.0 captures through a VPN too); not part of it.

**Before answering**, read the matching document whole:

| Question | Document |
|---|---|
| what the repository is for, rules the tools follow | `README.md` |
| how the recorder works, every log column, failure modes, tests | `docs/ARCHITECTURE.md` |
| test plan, everything already known, what a session must not do | `notes/07-vpn-test-polaczenia-plan.md` (private, Polish, not in git) |
| measuring method and the 17 Oct 2026 loss findings (where packets are lost) | `notes/06-siec-diagnostyka.md` (private, Polish, not in git) |

Code: package `vpnct/` (commands `vpnct`, `vpnct-gui`); the recorder is
standard library only, PyQt6 only in `vpnct/gui.py`. Installed here with
`pipx install --editable .`; menu entry by `vpnct install-desktop`.
Test the window offscreen (`QT_QPA_PLATFORM=offscreen`, `XDG_DATA_HOME` in
a temporary directory) so it takes no focus and leaves no real session.
Tests: `python3 -m unittest` in the repository root. A change to the code is
not finished until `docs/ARCHITECTURE.md` (and `README.md` where users see
it) match it, in the same commit.

Rules:
- Everything committed is in English. Only the conversation with Raman and
  `notes/` are in Polish.
- `notes/` is private and stays out of git; never quote it into committed
  files (it holds personal network details: addresses, route, provider).
- Keep the tools generic: interfaces, target hosts and ports are inputs, not
  constants tied to one game.
- Never run anything with `sudo`; capture works through the `wireshark` group.
- Captures can contain private content (game chat): delete each one as soon as
  it is counted.
- AION 2 case: switching the VPN off while in game freezes the game (its
  connection stays on the vanished VPN address). Switch only at character
  select / login.
