# Installing vpn-connection-test

This guide gets the program onto a Linux machine: the system tools it
measures with, the one-time permission for packet capture, the program
itself and its menu entry. Updating and removing are at the end.

## The idea

The program does not measure the network by itself. It asks tools your
system already has: the kernel's socket statistics, `ping`, the route
tracer, NetworkManager for VPN server names, and Wireshark's capture tool
for counting lost packets. So most of the installation is making sure those
tools are there.

Counting lost packets means looking at packets on the wire, which normally
needs administrator rights. Linux distributions solve this with a group
called `wireshark`: its members may run Wireshark's capture tool, and
nothing else gets those rights. You add yourself to that group once, and
the program never needs `sudo`.

## The steps at a glance

```
[ system packages ] ──► [ join the wireshark group ] ──► [ log in again ]
                                                               │
       [ start from the menu ] ◄── [ vpnct install-desktop ] ◄─┤
                                                               │
                                     [ pipx install ... ] ◄────┘
```

## What you need before you start

- Linux with Python 3.11 or newer (`python3 --version`).
- A desktop with a system tray (KDE Plasma, Xfce, Cinnamon, GNOME with the
  AppIndicator extension, and most others). Without a tray the window
  opens at start instead.
- NetworkManager, if you want VPN servers shown by name. Without it the
  VPN is still recognised, only shown by its interface name.

## Installing the packages

| Distribution | Command |
|---|---|
| Arch, CachyOS | `sudo pacman -S --needed iproute2 iputils wireshark-cli python-pipx` |
| Debian, Ubuntu | `sudo apt install iproute2 iputils-ping iputils-tracepath tshark pipx` |
| Fedora | `sudo dnf install iproute iputils wireshark-cli pipx` |

The program has been tested on CachyOS. The other rows name the packages
that hold the same tools.

On Debian and Ubuntu, installing `tshark` asks "Should non-superusers be
able to capture packets?". Answer **Yes**. If you answered No, run
`sudo dpkg-reconfigure wireshark-common` and choose Yes.

| Package | What it is for |
|---|---|
| iproute2 / iproute | reads the connections, their statistics and the network interfaces |
| iputils | `ping` and `tracepath`, for the probes and the route traces |
| Wireshark's command-line part | counts lost packets (`dumpcap` and `tshark`) |
| pipx | installs the program in a folder of its own |

## Allowing capture

1. Add yourself to the group:
   ```
   sudo usermod -aG wireshark $USER
   ```
2. Log out of your desktop and log in again. Group membership is read at
   login, so until then nothing changes.
3. Check it: `groups` should list `wireshark`.

Tip: if capture is not allowed, the program still runs and still shows
ping, but no lost packets can be counted, so every path card keeps saying
"Little data". See "What can go wrong" in
[Using the program](USING.md#what-can-go-wrong).

## Installing the program

1. Install it:
   ```
   pipx install vpn-connection-test
   ```
2. If pipx says the folder with its commands is not on your PATH, run
   `pipx ensurepath` and open a new terminal.
3. Add it to the application menu:
   ```
   vpnct install-desktop
   ```
4. Start **VPN connection test** from the menu. An icon appears in the
   tray; click it for the window.

To watch one program rather than letting it pick the busiest connections,
see "Choosing what to watch" in [Using the program](USING.md#choosing-what-to-watch).

## Updating

```
pipx upgrade vpn-connection-test
```

Quit the program from its tray menu first (**Quit**), and start it again
after the update. Your recordings stay where they are.

## Removing

1. Quit the program from its tray menu.
2. `pipx uninstall vpn-connection-test`
3. Delete the menu entry:
   `~/.local/share/applications/vpn-connection-test.desktop`.
4. If you want your recordings and settings gone too, delete
   `~/.local/share/vpn-connection-test/` and
   `~/.config/vpn-connection-test/`.
