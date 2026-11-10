"""Tray program: records in the background, shows what it measures.

The recorder (`Engine`) runs in this process on its own threads; the window
only displays. Closing the window hides it to the tray; recording stops
with Quit in the tray menu.

- Tray icon: colour from the last captured minute of the busiest service —
  green no loss, yellow some, red LOSS_RED_PCT or more, grey nothing
  captured. Tooltip: path, RTT, retransmissions in the last minute.
- Window: current state; a chart of RTT (per second) and retransmissions
  (per minute) with the path shaded behind; the comparison of paths, which
  is `report.summarise` run on the session files — the same numbers as
  `vpnct report`, not a second calculation; last probe round; recent events.

Settings: command-line options as for `vpnct record`, else
`config.toml` (`vpnct/config.py`).
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from PyQt6.QtCore import QObject, QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (QAction, QBrush, QColor, QFont, QIcon, QPainter, QPainterPath,
                         QPen, QPixmap)
from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QComboBox, QDialog,
                             QDialogButtonBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
                             QLabel, QListWidget, QMainWindow, QMenu, QMessageBox, QPushButton,
                             QScrollArea, QSizePolicy, QSplitter, QStackedWidget, QSystemTrayIcon,
                             QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import advice, config, report
from .cli import MARK_SIGNAL, claim_pidfile, release_pidfile
from .engine import Engine, MinutePoint, ProbePoint, RouteResult, SecondPoint
from .monitor import MonitorMinute
from .session import sessions_root
from .tracker import Selection

APP_NAME = "vpn-connection-test"
SUMMARY_PERIOD_MS = 15_000
RECOMMEND_PERIOD_MS = 60_000
HISTORY_S = 3 * 3600
LOSS_RED_PCT = 2.0
SPANS = [("10 min", 600), ("30 min", 1800), ("1 h", 3600), ("3 h", 3 * 3600)]

GREEN, YELLOW, RED, GREY = "#22c55e", "#f59e0b", "#ef4444", "#64748b"

# One dark theme, set explicitly so the window looks the same on any desktop.
THEME = {
    "bg": "#0b1120", "card": "#151d2e", "border": "#243049", "grid": "#1e293b",
    "text": "#e2e8f0", "muted": "#8b9ab3", "accent": "#3b82f6", "accent_hover": "#60a5fa",
    "on_accent": "#ffffff", "raised": "#1e293b",
    "good": GREEN, "warn": YELLOW, "bad": RED, "idle": GREY,
    "good_bg": "#0f2a1d", "warn_bg": "#2e2210", "bad_bg": "#321317", "info_bg": "#11233f",
    "idle_bg": "#151d2e",
}
DIRECT_SHADE = QColor(148, 163, 184, 30)
VPN_SHADES = [QColor(59, 130, 246, 44), QColor(168, 85, 247, 44), QColor(20, 184, 166, 44),
              QColor(249, 115, 22, 44)]

STYLE = f"""
QMainWindow, QWidget#page {{ background: {THEME['bg']}; }}
QWidget {{ color: {THEME['text']}; }}
QFrame#card {{ background: {THEME['card']}; border: 1px solid {THEME['border']}; border-radius: 14px; }}
QFrame#card[best="true"] {{ border: 2px solid {THEME['accent']}; }}
QFrame#banner {{ border-radius: 14px; border: 1px solid {THEME['border']}; }}
QLabel {{ background: transparent; }}
QLabel#muted, QLabel#subtitle {{ color: {THEME['muted']}; }}
QLabel#h1 {{ font-size: 15pt; font-weight: 600; }}
QLabel#h2 {{ font-size: 11pt; font-weight: 600; }}
QLabel#big {{ font-size: 17pt; font-weight: 600; }}
QLabel#badge {{ background: {THEME['accent']}; color: {THEME['on_accent']}; border-radius: 9px;
               padding: 2px 9px; font-weight: 600; }}
QLabel#badge[kind="muted"] {{ background: {THEME['raised']}; color: {THEME['muted']}; }}
QLabel#pill {{ background: {THEME['card']}; border: 1px solid {THEME['border']}; border-radius: 11px;
              padding: 3px 11px; color: {THEME['muted']}; }}
QPushButton {{ background: {THEME['raised']}; border: 1px solid {THEME['border']}; border-radius: 9px;
              padding: 6px 14px; color: {THEME['text']}; }}
QPushButton:hover {{ border-color: {THEME['accent']}; }}
QPushButton:checked {{ background: {THEME['accent']}; color: {THEME['on_accent']}; border-color: {THEME['accent']}; }}
QPushButton:checked:hover {{ background: {THEME['accent_hover']}; }}
QComboBox {{ background: {THEME['raised']}; border: 1px solid {THEME['border']}; border-radius: 9px;
            padding: 5px 10px; min-width: 220px; font-weight: 600; color: {THEME['text']}; }}
QComboBox QAbstractItemView {{ background: {THEME['card']}; color: {THEME['text']};
                              selection-background-color: {THEME['accent']}; }}
QTableWidget, QListWidget {{ background: {THEME['card']}; border: 1px solid {THEME['border']};
                            border-radius: 10px; gridline-color: {THEME['grid']}; color: {THEME['text']}; }}
QTableWidget QTableCornerButton::section {{ background: {THEME['raised']}; border: none; }}
QHeaderView::section {{ background: {THEME['raised']}; border: none;
                        border-bottom: 1px solid {THEME['border']}; padding: 4px; color: {THEME['muted']}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QScrollBar:horizontal, QScrollBar:vertical {{ background: {THEME['bg']}; border: none; }}
QScrollBar::handle {{ background: {THEME['border']}; border-radius: 4px; min-width: 24px; min-height: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QSplitter::handle {{ background: transparent; }}
QToolTip {{ background: {THEME['raised']}; color: {THEME['text']}; border: 1px solid {THEME['border']}; }}
QDialog {{ background: {THEME['bg']}; }}
"""


def dot_icon(colour: str) -> QIcon:
    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(QColor("#202020"), 3))
    p.setBrush(QColor(colour))
    p.drawEllipse(6, 6, 52, 52)
    p.setPen(QPen(QColor("white"), 5))
    path = QPainterPath()                    # a small "pulse" line
    path.moveTo(14, 34)
    path.lineTo(24, 34)
    path.lineTo(30, 20)
    path.lineTo(36, 46)
    path.lineTo(41, 32)
    path.lineTo(50, 32)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(path)
    p.end()
    return QIcon(pm)


class Store:
    """Chart history per service (program, remote port), kept in memory."""

    def __init__(self) -> None:
        self.seconds: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=HISTORY_S * 4))
        self.minutes: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=HISTORY_S // 60 * 10))
        self.traffic: dict[tuple, int] = defaultdict(int)
        self.monitor: deque = deque(maxlen=HISTORY_S // 60 * 8)
        self.hosts: dict[tuple, set] = defaultdict(set)
        self.routes: deque = deque(maxlen=500)
        self.probes: deque = deque(maxlen=HISTORY_S // 60 * 20)

    def add(self, points: list) -> None:
        for pt in points:
            if isinstance(pt, MonitorMinute):
                self.monitor.append(pt)
                continue
            if isinstance(pt, RouteResult):
                self.routes.append(pt)
                continue
            if isinstance(pt, ProbePoint):
                self.probes.append(pt)
                continue
            key = (pt.program, pt.port)
            if isinstance(pt, SecondPoint):
                self.seconds[key].append(pt)
                self.traffic[key] += pt.d_data_segs_in
            elif isinstance(pt, MinutePoint):
                self.minutes[key].append(pt)
                self.hosts[key].add(pt.host)

    def routes_for(self, key: tuple) -> list[RouteResult]:
        hosts = self.hosts.get(key, set())
        return [r for r in self.routes if r.target in hosts]

    def monitor_for(self, key: tuple) -> list[MonitorMinute]:
        hosts = self.hosts.get(key, set())
        return [m for m in self.monitor if m.target in hosts]

    def on_vpn_now(self, key: tuple) -> bool | None:
        """Path of the service's newest second with traffic, if recent."""
        for pt in reversed(self.seconds.get(key, ())):
            if time.time() - pt.time > 10:
                return None
            if pt.d_data_segs_in > 0:
                return pt.is_vpn
        return None

    def services(self) -> list[tuple]:
        return sorted(self.seconds, key=lambda k: self.traffic[k], reverse=True)

    def last_minute(self, key: tuple) -> tuple[int, int, str | None]:
        """(retrans, data_pkts, path) over the newest minute of a service."""
        rows = self.minutes.get(key)
        if not rows:
            return 0, 0, None
        newest = rows[-1].minute
        sel = [r for r in rows if r.minute == newest]
        return (sum(r.retrans for r in sel), sum(r.data_pkts for r in sel), sel[-1].path)


class Chart(QWidget):
    """RTT line (top) and retransmissions per minute (bottom) over time,
    the path in use shaded behind both."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumHeight(220)
        self.seconds: list[SecondPoint] = []
        self.minutes: list[MinutePoint] = []
        self.span = SPANS[1][1]
        self.colours: dict[str, QColor] = {}

    def set_data(self, seconds, minutes) -> None:
        self.seconds, self.minutes = list(seconds), list(minutes)
        self.update()

    def colour(self, path: str, is_vpn: bool) -> QColor:
        if path not in self.colours:
            n = sum(1 for p in self.colours if p.startswith("vpn:"))
            self.colours[path] = VPN_SHADES[n % len(VPN_SHADES)] if is_vpn else DIRECT_SHADE
        return self.colours[path]

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        left, right, top, bottom = 44, 8, 26, 22
        plot = QRectF(left, top, w - left - right, h - top - bottom)
        split = plot.top() + plot.height() * 0.66
        rtt_area = QRectF(plot.left(), plot.top(), plot.width(), split - plot.top() - 8)
        loss_area = QRectF(plot.left(), split + 8, plot.width(), plot.bottom() - split - 8)
        text, muted, grid = QColor(THEME["text"]), QColor(THEME["muted"]), QColor(THEME["grid"])
        now = time.time()
        t0 = now - self.span
        x = lambda t: plot.left() + (t - t0) / self.span * plot.width()
        secs = [s for s in self.seconds if s.time >= t0]
        mins = [m for m in self.minutes if m.minute + 60 >= t0]
        small = QFont(self.font())
        small.setPointSizeF(small.pointSizeF() * 0.85)
        p.setFont(small)

        # path bands, with a line where the path changes
        legend: dict[str, QColor] = {}
        run_start, run_path = None, None
        for s in secs + [None]:
            if s is None or s.path != run_path:
                if run_path is not None:
                    c = self.colour(run_path, run_path.startswith("vpn:"))
                    legend[run_path] = c
                    end = s.time if s is not None else now
                    p.fillRect(QRectF(x(run_start), plot.top(), max(1.0, x(end) - x(run_start)),
                                      plot.height()), c)
                    if s is not None:
                        p.setPen(QPen(muted, 1, Qt.PenStyle.DashLine))
                        p.drawLine(QPointF(x(end), plot.top()), QPointF(x(end), plot.bottom()))
                if s is not None:
                    run_start, run_path = s.time, s.path

        # ping: median across the service's connections per second, data seconds only
        per_second: dict[int, list[float]] = defaultdict(list)
        for s in secs:
            if s.rtt_ms is not None and s.d_data_segs_in > 0:
                per_second[int(s.time)].append(s.rtt_ms)
        pts = sorted((t, sorted(v)[len(v) // 2]) for t, v in per_second.items())
        rtt_max = max([v for _, v in pts] + [10.0]) * 1.15
        p.setPen(QPen(grid, 1))
        for frac in (0.0, 0.5, 1.0):
            y = rtt_area.bottom() - frac * rtt_area.height()
            p.drawLine(QPointF(rtt_area.left(), y), QPointF(rtt_area.right(), y))
        p.setPen(muted)
        for frac in (0.0, 0.5, 1.0):
            y = rtt_area.bottom() - frac * rtt_area.height()
            p.drawText(QRectF(0, y - 8, left - 6, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       f"{rtt_max * frac:.0f}")
        p.drawText(QRectF(plot.left() + 4, rtt_area.top() + 2, 300, 16), Qt.AlignmentFlag.AlignLeft,
                   "Ping [ms]")
        if pts:
            path = QPainterPath()
            for i, (t, v) in enumerate(pts):
                pt = QPointF(x(t), rtt_area.bottom() - v / rtt_max * rtt_area.height())
                path.moveTo(pt) if i == 0 or t - pts[i - 1][0] > 5 else path.lineTo(pt)
            p.setPen(QPen(QColor(THEME["accent"]), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                          Qt.PenJoinStyle.RoundJoin))
            p.drawPath(path)

        # lost packets (server retransmissions) per minute
        per_min: dict[float, list[int]] = defaultdict(lambda: [0, 0, 0])
        for m in mins:
            agg = per_min[m.minute]
            agg[0] += m.retrans
            agg[1] += m.data_pkts
            agg[2] = max(agg[2], int(m.covered_s))
        loss_max = max([a[0] for a in per_min.values()] + [5])
        p.setPen(QPen(grid, 1))
        p.drawLine(QPointF(loss_area.left(), loss_area.bottom()), QPointF(loss_area.right(), loss_area.bottom()))
        p.setPen(muted)
        p.drawText(QRectF(0, loss_area.top() - 8, left - 6, 16),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, f"{loss_max}")
        p.drawText(QRectF(plot.left() + 4, loss_area.top(), plot.width() - 8, 16), Qt.AlignmentFlag.AlignLeft,
                   "Lost packets / min")
        for minute, (rtx, data, covered) in per_min.items():
            x0, x1 = x(max(minute, t0)), x(minute + 60)
            bh = max(rtx / loss_max * loss_area.height(), 2.0)
            rect = QRectF(x0 + 1.5, loss_area.bottom() - bh, max(1.0, x1 - x0 - 3), bh)
            colour = QColor(THEME["bad"] if data and 100 * rtx / data >= LOSS_RED_PCT
                            else THEME["warn"] if rtx else THEME["good"])
            if covered < 55:
                colour.setAlpha(110)          # minute not fully captured
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(colour)
            p.drawRoundedRect(rect, 1.5, 1.5)

        # time axis and legend
        p.setPen(muted)
        for i in range(7):
            t = t0 + i * self.span / 6
            lx0 = min(max(x(t) - 25, 0.0), w - 50.0)      # keep the end labels inside
            p.drawText(QRectF(lx0, plot.bottom() + 4, 50, 16), Qt.AlignmentFlag.AlignCenter,
                       time.strftime("%H:%M", time.localtime(t)))
        lx = plot.left()
        for name, c in legend.items():
            title, _sub = advice.path_title(name) if ":" in name else (name, "")
            solid = QColor(c)
            solid.setAlpha(255)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(solid)
            p.drawRoundedRect(QRectF(lx, 6, 10, 10), 3, 3)
            p.setPen(text)
            p.drawText(QRectF(lx + 15, 2, 400, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, title)
            lx += 30 + p.fontMetrics().horizontalAdvance(title)
        if not secs:
            p.setPen(muted)
            p.drawText(plot, Qt.AlignmentFlag.AlignCenter, "No traffic on this service in the chosen span yet")
        p.end()


class Signals(QObject):
    summary = pyqtSignal(object)
    recommendation = pyqtSignal(object)


class SessionPicker(QDialog):
    def __init__(self, parent, current: str, chosen: set[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Compare sessions")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Sessions to include in the comparison (the current one is always included):"))
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        root = sessions_root()
        for d in sorted((p for p in root.iterdir() if p.is_dir()), reverse=True) if root.exists() else []:
            if d.name == current:
                continue
            self.list.addItem(d.name)
            if d.name in chosen:
                self.list.item(self.list.count() - 1).setSelected(True)
        lay.addWidget(self.list)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def chosen(self) -> set[str]:
        return {i.text() for i in self.list.selectedItems()}


def label(text: str = "", name: str | None = None, wrap: bool = False) -> QLabel:
    lb = QLabel(text)
    if name:
        lb.setObjectName(name)
    lb.setWordWrap(wrap)
    return lb


def card() -> tuple[QFrame, QVBoxLayout]:
    fr = QFrame()
    fr.setObjectName("card")
    lay = QVBoxLayout(fr)
    lay.setContentsMargins(18, 14, 18, 14)
    lay.setSpacing(6)
    return fr, lay


def restyle(w: QWidget) -> None:
    """Re-apply the stylesheet after a dynamic property changed."""
    w.style().unpolish(w)
    w.style().polish(w)


LEVEL_COLOURS = {"good": THEME["good"], "fair": THEME["warn"], "poor": THEME["bad"],
                 "unknown": THEME["muted"]}


class PathCardWidget(QFrame):
    """One tested path: ping, spikes, jumpy minutes, stability, loss, how much data."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("card")
        self.setMinimumWidth(230)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(4)
        head = QHBoxLayout()
        self.title = label("", "h2")
        head.addWidget(self.title, 1)
        self.badge = label("", "badge")
        head.addWidget(self.badge)
        lay.addLayout(head)
        self.subtitle = label("", "subtitle")
        lay.addWidget(self.subtitle)
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(2)
        self.values: dict[str, QLabel] = {}
        tips = {
            "Ping": "Median round-trip time to the server over the seconds with traffic.",
            "Spikes": "How far the ping jumps above its usual value: 95th percentile minus median.",
            "Steady ping": "Share of minutes in which the ping did not jump. A minute jumps when, within "
                           f"it, the 95th percentile is {report.SPIKE_SPREAD_MS:.0f} ms or one second "
                           f"{report.SPIKE_MAX_MS:.0f} ms over its median. Nothing need be lost in such a "
                           "minute; it is counted apart from Stability.",
            "Stability": "Share of measured minutes without packet loss (a minute is lost-free below "
                         f"{report.CAL_TCP_BAD_PCT} % retransmitted).",
            "Loss": "Packets the server had to send again, of all it sent.",
        }
        for i, name in enumerate(("Ping", "Spikes", "Steady ping", "Stability", "Loss")):
            cap = label(name, "muted")
            cap.setToolTip(tips[name])
            val = label("–", "big")
            val.setToolTip(tips[name])
            grid.addWidget(cap, (i // 2) * 2, i % 2)
            grid.addWidget(val, (i // 2) * 2 + 1, i % 2)
            self.values[name] = val
        lay.addSpacing(6)
        lay.addLayout(grid)
        lay.addSpacing(4)
        self.footer = label("", "muted", wrap=True)
        lay.addWidget(self.footer)

    def show_card(self, c: "advice.PathCard", now_on: bool) -> None:
        self.title.setText(c.title)
        servers = (f" · {len(c.servers)} server{'s' if len(c.servers) != 1 else ''}" if c.servers else "")
        self.subtitle.setText(f"{c.subtitle}{servers}" + (" · in use now" if now_on else ""))
        self.subtitle.setToolTip(", ".join(c.servers))
        ms = lambda v, f="{:.0f} ms": "–" if v is None else f.format(v)
        self.values["Ping"].setText(ms(c.ping_ms))
        self.values["Spikes"].setText(ms(c.spikes_ms, "+{:.0f} ms"))
        self.values["Steady ping"].setText(ms(c.steady_pct, "{:.0f} %"))
        self.values["Steady ping"].setStyleSheet(f"color: {LEVEL_COLOURS[c.jumpy_level]}")
        self.values["Stability"].setText(ms(c.stability_pct, "{:.0f} %"))
        self.values["Loss"].setText(ms(c.loss_pct, "{:.2f} %"))
        self.values["Stability"].setStyleSheet(f"color: {LEVEL_COLOURS[c.stability_level]}")
        loss_level = ("unknown" if c.loss_pct is None else "good" if c.loss_pct < 0.1
                      else "fair" if c.loss_pct < report.CAL_TCP_BAD_PCT else "poor")
        self.values["Loss"].setStyleSheet(f"color: {LEVEL_COLOURS[loss_level]}")
        sessions = f" · {c.sessions} session{'s' if c.sessions != 1 else ''}"
        if c.enough:
            self.footer.setText(f"{c.judged_minutes} min measured{sessions}")
        else:
            self.footer.setText(f"{c.judged_minutes} of {advice.REC_MIN_SERVER_MINUTES} min needed "
                                f"to compare{sessions}")
        if c.best:
            self.badge.setText(f"★ Best — {c.best_reason}")
            self.badge.setProperty("kind", "best")
        elif not c.enough:
            self.badge.setText("Little data")
            self.badge.setProperty("kind", "muted")
        else:
            self.badge.setText("")
        self.badge.setVisible(bool(self.badge.text()))
        restyle(self.badge)
        self.setProperty("best", c.best)
        restyle(self)


class Window(QMainWindow):
    METRICS = [
        ("time observed", lambda g: f"{g.seconds / 60:.1f} min"),
        ("connections", lambda g: f"{len(g.connections)}"),
        ("RTT median", lambda g: report._n(report.percentile(g.rtts, .5), "{:.0f} ms")),
        ("RTT p95", lambda g: report._n(report.percentile(g.rtts, .95), "{:.0f} ms")),
        ("captured", lambda g: f"{g.covered_s / 60:.1f} min"),
        ("judged minutes", lambda g: f"{g.judged_minutes}"),
        ("bad minutes", lambda g: f"{g.bad_minutes}"),
        ("data packets", lambda g: f"{g.data_pkts}"),
        ("retransmissions", lambda g: f"{g.retrans}"),
        ("loss", lambda g: report._n(report.loss_pct(g), "{:.2f} %")),
        ("retrans / min", lambda g: report._n(g.retrans / (g.covered_s / 60) if g.covered_s else None, "{:.2f}")),
        ("loss gaps", lambda g: f"{g.lost_gaps}"),
        ("worst minute", lambda g: f"{g.worst_minute_pct:.1f} %"),
        ("jumpy minutes", lambda g: f"{g.spiky_minutes} of {g.ping_minutes}"),
    ]
    BANNER = {  # level -> (background, accent, title)
        "switch": (THEME["bad_bg"], THEME["bad"], "Losing packets — switch to the VPN"),
        "return": (THEME["info_bg"], THEME["accent"], "You can switch back"),
        "stay": (THEME["warn_bg"], THEME["warn"], "Keep the current path"),
        "ok": (THEME["good_bg"], THEME["good"], "Connection is stable"),
        "unknown": (THEME["idle_bg"], THEME["idle"], "Waiting for data"),
    }

    def __init__(self, engine: Engine, store: Store, cfg_note: str) -> None:
        super().__init__()
        self.engine, self.store = engine, store
        self.parent_app = None       # the App sets itself here after construction
        self.extra_sessions: set[str] = set()
        self.summary = None          # this session (plus picked ones), every 15 s
        self.all_summary = None      # all sessions, every minute
        self.setWindowTitle("VPN connection test")
        self.resize(1080, 860)
        page = QWidget()
        page.setObjectName("page")
        root = QVBoxLayout(page)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        # header: service, recording pill, actions
        head = QHBoxLayout()
        head.addWidget(label("Connection to", "muted"))
        self.service = QComboBox()
        self.service.currentIndexChanged.connect(self.on_service_changed)
        head.addWidget(self.service)
        head.addStretch(1)
        self.pill = label("", "pill")
        head.addWidget(self.pill)
        self.mark_btn = QPushButton("It stutters now")
        self.mark_btn.setToolTip("Note this moment and probe the route at once")
        self.mark_btn.clicked.connect(lambda: self.engine.mark("marked in the window"))
        head.addWidget(self.mark_btn)
        self.adv_btn = QPushButton("Advanced")
        self.adv_btn.setCheckable(True)
        self.adv_btn.toggled.connect(lambda on: self.stack.setCurrentIndex(1 if on else 0))
        head.addWidget(self.adv_btn)
        root.addLayout(head)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_overview(cfg_note))
        self.stack.addWidget(self._build_advanced(cfg_note))
        root.addWidget(self.stack, 1)
        self.setCentralWidget(page)

    # ---- overview ----------------------------------------------------------

    def _build_overview(self, cfg_note: str) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        self.banner = QFrame()
        self.banner.setObjectName("banner")
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(18, 14, 18, 14)
        self.banner_dot = QLabel()
        self.banner_dot.setFixedSize(14, 14)
        bl.addWidget(self.banner_dot, 0, Qt.AlignmentFlag.AlignTop)
        bt = QVBoxLayout()
        bt.setSpacing(2)
        self.banner_title = label("Waiting for data", "h1")
        self.banner_now = label("", "muted")
        self.banner_text = label("", wrap=True)
        bt.addWidget(self.banner_title)
        bt.addWidget(self.banner_now)
        bt.addWidget(self.banner_text)
        bl.addLayout(bt, 1)
        lay.addWidget(self.banner)

        recent, rl = card()
        rh = QHBoxLayout()
        rh.addWidget(label("Recently", "h2"))
        rh.addWidget(label("this session", "muted"))
        rh.addStretch(1)
        self.recent_group = QButtonGroup(self)
        for i, (name, _secs) in enumerate(advice.RECENT_WINDOWS):
            b = QPushButton(name)
            b.setCheckable(True)
            b.setChecked(i == 1)
            self.recent_group.addButton(b, i)
            rh.addWidget(b)
        self.recent_group.idToggled.connect(lambda _i, on: on and self.parent_app and self.parent_app.tick_view())
        rl.addLayout(rh)
        self.recent_lines = QVBoxLayout()
        self.recent_lines.setSpacing(3)
        rl.addLayout(self.recent_lines)
        self.recent_rows: list[tuple[QLabel, QLabel, QLabel]] = []
        self.recent_conclusion = label("", wrap=True)
        self.recent_conclusion.setStyleSheet("font-weight: 600;")
        rl.addWidget(self.recent_conclusion)
        lay.addWidget(recent)

        row = QHBoxLayout()
        row.addWidget(label("Tested paths", "h2"))
        row.addStretch(1)
        self.scope_session = QPushButton("This session")
        self.scope_all = QPushButton("All sessions")
        self.scope = QButtonGroup(self)
        for b in (self.scope_session, self.scope_all):
            b.setCheckable(True)
            self.scope.addButton(b)
            row.addWidget(b)
        self.scope_all.setChecked(True)
        self.scope.buttonToggled.connect(lambda *_: self.refresh_cards())
        lay.addLayout(row)

        self.cards_box = QWidget()
        self.cards_lay = QHBoxLayout(self.cards_box)
        self.cards_lay.setContentsMargins(0, 0, 0, 0)
        self.cards_lay.setSpacing(12)
        self.cards: list[PathCardWidget] = []
        self.cards_empty = label("No path measured for this connection yet — keep the program "
                                 "running while you play.", "muted", wrap=True)
        self.cards_lay.addWidget(self.cards_empty)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self.cards_box)
        self.cards_scroll = scroll
        lay.addWidget(scroll)

        chart_card, cl = card()
        ch = QHBoxLayout()
        ch.addWidget(label("Ping and lost packets", "h2"))
        ch.addStretch(1)
        self.span_group = QButtonGroup(self)
        for i, (name, _secs) in enumerate(SPANS):
            b = QPushButton(name)
            b.setCheckable(True)
            b.setChecked(i == 1)
            self.span_group.addButton(b, i)
            ch.addWidget(b)
        self.span_group.idToggled.connect(lambda i, on: on and self.set_span(i))
        cl.addLayout(ch)
        self.chart = Chart()
        cl.addWidget(self.chart, 1)
        lay.addWidget(chart_card, 1)

        rec_card, rl = card()
        rh = QHBoxLayout()
        rh.addWidget(label("Recommendation", "h2"))
        rh.addWidget(label("from all recordings", "muted"))
        rh.addStretch(1)
        rl.addLayout(rh)
        self.rec_headline = label("Calculating…", wrap=True)
        self.rec_headline.setStyleSheet("font-size: 12pt; font-weight: 600;")
        rl.addWidget(self.rec_headline)
        self.rec_sub = label("", "muted", wrap=True)
        rl.addWidget(self.rec_sub)
        lay.addWidget(rec_card)
        return w

    # ---- advanced -----------------------------------------------------------

    def _build_advanced(self, cfg_note: str) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        top, tl = card()
        self.hint = label("", wrap=True)
        self.hint.setTextFormat(Qt.TextFormat.RichText)
        tl.addWidget(self.hint)
        self.status = label("", wrap=True)
        self.status.setTextFormat(Qt.TextFormat.RichText)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        tl.addWidget(self.status)
        self.note = label(cfg_note, "muted", wrap=True)
        tl.addWidget(self.note)
        bar = QHBoxLayout()
        bar.addStretch(1)
        sessions_btn = QPushButton("Compare sessions…")
        sessions_btn.clicked.connect(self.pick_sessions)
        bar.addWidget(sessions_btn)
        folder_btn = QPushButton("Session folder")
        folder_btn.clicked.connect(lambda: subprocess.Popen(["xdg-open", str(self.engine.session.dir)]))
        bar.addWidget(folder_btn)
        self.rec_btn = QPushButton("Recalculate")
        bar.addWidget(self.rec_btn)
        tl.addLayout(bar)
        lay.addWidget(top)

        split = QSplitter(Qt.Orientation.Vertical)
        cmp_box, cl = card()
        self.cmp_title = label("<b>Comparison of paths</b>")
        cl.addWidget(self.cmp_title)
        self.table = QTableWidget()
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        cl.addWidget(self.table, 1)
        self.verdict = label("", wrap=True)
        self.verdict.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cl.addWidget(self.verdict)
        cl.addWidget(label("<b>Recommendation</b> (all sessions)"))
        self.recommendation = label("calculating…", wrap=True)
        self.recommendation.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cl.addWidget(self.recommendation)
        split.addWidget(cmp_box)

        low = QSplitter(Qt.Orientation.Horizontal)
        probe_box, pl = card()
        pl.addWidget(label("<b>Last probe round</b> (ping; bound = sent through that interface)"))
        self.probes = QTableWidget(0, 6)
        self.probes.setHorizontalHeaderLabels(["target", "role", "path", "bound", "loss", "RTT"])
        self.probes.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.probes.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.probes.horizontalHeader().setStretchLastSection(True)
        self.probes.verticalHeader().setVisible(False)
        pl.addWidget(self.probes)
        low.addWidget(probe_box)
        ev_box, el = card()
        el.addWidget(label("<b>Events</b>"))
        self.events = QListWidget()
        el.addWidget(self.events)
        low.addWidget(ev_box)
        split.addWidget(low)
        split.setSizes([430, 260])
        lay.addWidget(split, 1)
        return w

    # ---- periodic --------------------------------------------------------

    def set_span(self, i: int) -> None:
        self.chart.span = SPANS[i][1]
        self.chart.update()

    def current_service(self) -> tuple | None:
        return self.service.currentData()

    def on_service_changed(self) -> None:
        self.refresh_chart()
        self.refresh_table()
        self.refresh_cards()
        if self.all_summary is not None:
            self.show_recommendation(self.all_summary)

    def refresh_services(self) -> None:
        """Main services (enough judged minutes in the recordings) first,
        then live ones; the busiest main service is chosen at first."""
        known = [self.service.itemData(i) for i in range(self.service.count())]
        main = []
        if isinstance(self.all_summary, dict):
            main = [(prog, int(port)) for prog, port in advice.main_services(self.all_summary)[0]]
        for key in main + self.store.services():
            if key not in known:
                self.service.addItem(f"{key[0]} · port {key[1]}", key)
                known.append(key)
        if self.service.currentIndex() < 0 and self.service.count():
            self.service.setCurrentIndex(0)

    def refresh_chart(self) -> None:
        key = self.current_service()
        if key is None:
            self.chart.set_data([], [])
            return
        self.chart.set_data(self.store.seconds.get(key, []), self.store.minutes.get(key, []))

    def path_now(self, snap) -> tuple[str | None, float | None]:
        """(path, RTT) of the chosen service's busiest live connection."""
        key = self.current_service()
        if key is None:
            return None, None
        conns = [c for c in snap.connections if (c.program, int(c.remote.rpartition(":")[2])) == key]
        if not conns:
            return None, None
        busiest = max(conns, key=lambda c: c.segs_per_min)
        return busiest.path, busiest.rtt_ms

    def refresh_overview(self, snap, hint: "advice.Hint") -> None:
        up = int(time.time() - snap.started)
        self.pill.setText(f"● Recording {up // 3600} h {up % 3600 // 60:02d} min" if up >= 3600
                          else f"● Recording {up // 60} min")
        bg, accent, title = self.BANNER[hint.level]
        self.banner.setStyleSheet(f"QFrame#banner {{ background: {bg}; border-color: {accent}; }}")
        self.banner_dot.setStyleSheet(f"background: {accent}; border-radius: 7px;")
        self.banner_title.setText(title)
        path, rtt = self.path_now(snap)
        if path:
            name, itf = advice.path_title(path) if ":" in path else (path, "")
            rtx, data, _ = self.store.last_minute(self.current_service())
            last = f" · last minute {rtx} lost of {data}" if data else ""
            self.banner_now.setText(f"Now on {name}" + (f" · ping {rtt:.0f} ms" if rtt is not None else "") + last)
        else:
            self.banner_now.setText("No live connection on this service right now")
        self.banner_text.setText(hint.text)

    def recent_window_s(self) -> float:
        return advice.RECENT_WINDOWS[max(0, self.recent_group.checkedId())][1]

    def show_recent(self, view: "advice.RecentView") -> None:
        while len(self.recent_rows) < len(view.lines):
            row = QHBoxLayout()
            dot, title, text = QLabel(), label("", "h2"), label("", wrap=True)
            dot.setFixedSize(10, 10)
            title.setMinimumWidth(240)
            row.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(title)
            row.addWidget(text, 1)
            self.recent_lines.addLayout(row)
            self.recent_rows.append((dot, title, text))
        for (dot, title, text), line in zip(self.recent_rows, view.lines):
            dot.setStyleSheet(f"background: {LEVEL_COLOURS[line.level]}; border-radius: 5px;")
            title.setText(line.title)
            text.setText(line.text)
            for wdg in (dot, title, text):
                wdg.show()
        for row in self.recent_rows[len(view.lines):]:
            for wdg in row:
                wdg.hide()
        colour = self.HINT_COLOURS[view.conclusion.level]
        self.recent_conclusion.setText(view.conclusion.text)
        self.recent_conclusion.setStyleSheet(f"font-weight: 600; color: {colour};")

    def comparison_from_cards(self) -> tuple[float | None, str | None]:
        """(VPN minus direct RTT of the connection, best VPN's title) from the
        cards' all-time numbers; ping RTT is not comparable with TCP RTT."""
        cards = getattr(self, "_cards", [])
        direct = next((c for c in cards if not c.is_vpn and c.ping_ms is not None), None)
        vpns = sorted((c for c in cards if c.is_vpn and c.enough),
                      key=lambda c: (-(c.stability_pct or 0), advice._LEVEL_RANK[c.jumpy_level],
                                     c.ping_ms or 1e9))
        best = vpns[0] if vpns else None
        cost = (best.ping_ms - direct.ping_ms
                if best and direct and best.ping_ms is not None else None)
        return cost, best.title if best else None

    def refresh_cards(self) -> None:
        key = self.current_service()
        summary = self.all_summary if self.scope_all.isChecked() else self.summary
        cards = []
        if key is not None and isinstance(summary, dict):
            paths = report.by_service(summary["groups"]).get((key[0], str(key[1])), {})
            cards = advice.path_cards(paths)
        self._cards = cards
        while len(self.cards) < len(cards):
            wdg = PathCardWidget()
            self.cards.append(wdg)
            self.cards_lay.addWidget(wdg)
        now_path = getattr(self, "_now_path", None)
        for wdg, c in zip(self.cards, cards):
            wdg.show_card(c, now_path is not None and c.path == report.path_family(now_path))
            wdg.show()
        for wdg in self.cards[len(cards):]:
            wdg.hide()
        self.cards_empty.setVisible(not cards)
        # The row is as tall as a card, plus room for a horizontal scroll bar.
        bar = self.cards_scroll.horizontalScrollBar().sizeHint().height()
        self.cards_scroll.setFixedHeight(self.cards_box.sizeHint().height() + bar + 4)

    def refresh_status(self, snap) -> None:
        up = time.time() - snap.started
        lines = [f"<b>Recording</b> {up / 60:.0f} min · {snap.selection} · "
                 f"{len(snap.connections)} watched, {sum(c.captured for c in snap.connections)} captured, "
                 f"{snap.unwatched} other internet connection(s), {snap.skipped_local} local/LAN skipped"]
        key = self.current_service()
        if key is not None:
            rtx, data, path = self.store.last_minute(key)
            conns = [c for c in snap.connections if (c.program, int(c.remote.rpartition(":")[2])) == key]
            if conns:
                busiest = max(conns, key=lambda c: c.segs_per_min)
                rtt = f"{busiest.rtt_ms:.0f} ms" if busiest.rtt_ms is not None else "-"
                lines.append(f"Now: <b>{busiest.path}</b> · {key[0]} {busiest.remote} · RTT {rtt}"
                             f" (min {busiest.minrtt_ms or 0:.0f}) · last minute {rtx} retransmissions"
                             f" of {data} packets")
            else:
                lines.append(f"{key[0]} :{key[1]}: no live connection right now")
        for m in snap.last_monitor:
            loss = f"{m.loss_pct:.0f} %" if m.loss_pct is not None else "-"
            rtt = f"{m.rtt_p50:.0f} ms" if m.rtt_p50 is not None else "-"
            lines.append(f"Direct path watch: ping {m.target} via {m.interface} — last minute "
                         f"{loss} lost of {m.sent}, RTT {rtt}")
        self.status.setText("<br>".join(lines))

    def refresh_probes(self, snap) -> None:
        rows = snap.last_probes
        self.probes.setRowCount(len(rows))
        for i, r in enumerate(rows):
            loss = (r["error"] if r["error"] else
                    "no reply" if r["received"] == 0 else f"{r['loss_pct']:.0f} %")
            rtt = f"{r['rtt_avg']:.1f} ms" if r["rtt_avg"] is not None else "-"
            for j, v in enumerate([r["target"], r["role"], r["path"], r["bound"], loss, rtt]):
                self.probes.setItem(i, j, QTableWidgetItem(str(v)))

    def refresh_events(self, snap) -> None:
        shown = [self.events.item(i).text() for i in range(self.events.count())]
        if shown == snap.recent_events:
            return
        self.events.clear()
        for line in snap.recent_events:
            self.events.addItem(line)
        self.events.scrollToBottom()

    def refresh_table(self) -> None:
        key = self.current_service()
        s = self.summary
        if key is None or s is None:
            self.table.clear()
            self.verdict.setText("comparison appears after the first captured minutes")
            return
        paths = report.by_service(s["groups"]).get((key[0], str(key[1])), {})
        names = sorted(paths)
        self.table.setColumnCount(len(names))
        self.table.setRowCount(len(self.METRICS))
        self.table.setHorizontalHeaderLabels(names)
        self.table.setVerticalHeaderLabels([m for m, _ in self.METRICS])
        for j, name in enumerate(names):
            for i, (_, fn) in enumerate(self.METRICS):
                self.table.setItem(i, j, QTableWidgetItem(fn(paths[name])))
        sessions = 1 + len(self.extra_sessions)
        self.cmp_title.setText(f"<b>Comparison of paths</b> — {key[0]} :{key[1]}, "
                               f"{sessions} session(s), same numbers as <tt>vpnct report</tt>")
        lines = report.compare_paths(paths) if paths else ["no data yet"]
        lines.append("Ping as a stand-in for TCP loss: " + s["calibration"].describe())
        self.verdict.setText("<br>".join(lines))

    HINT_COLOURS = {"switch": RED, "return": THEME["accent"], "stay": YELLOW, "ok": GREEN, "unknown": GREY}

    def show_hint(self, h: "advice.Hint") -> None:
        self.hint.setText(f"<span style='color:{self.HINT_COLOURS[h.level]}'><b>{h.text}</b></span>")

    def show_recommendation(self, summary) -> None:
        key = self.current_service()
        if isinstance(summary, Exception):
            self.recommendation.setText(f"recommendation failed: {summary!r}")
            self.rec_headline.setText("Recommendation could not be calculated")
            self.rec_sub.setText(repr(summary))
            return
        main, _rest = advice.main_services(summary)
        services = [k for k in main if key is None or k == (key[0], str(key[1]))] or main
        if not services:
            self.recommendation.setText("no service has enough judged minutes in any session yet")
            self.rec_headline.setText("Not enough data yet")
            self.rec_sub.setText(f"A connection needs {advice.REC_MIN_SERVER_MINUTES} measured "
                                 f"minutes before it can be compared.")
            return
        rec = advice.recommend(summary, services[0])
        body = "<br>".join("· " + d for d in rec.details)
        self.recommendation.setText(f"<b>{services[0][0]} :{services[0][1]} — {rec.headline}</b><br>{body}")
        self.rec_headline.setText(rec.headline)
        if rec.ranking:
            best = rec.ranking[0]
            name, _itf = advice.path_title(best.path)
            rtt = f", ping {best.rtt_p50:.0f} ms" if best.rtt_p50 is not None else ""
            jumpy = f", ping steady in {best.steady_pct:.0f} % of minutes" if best.steady_pct is not None else ""
            self.rec_sub.setText(f"Best VPN measured so far: {name} — {100 - 100 * best.bad_fraction:.0f} % "
                                 f"stable{rtt}{jumpy}, {best.minutes} min. Full reasoning under Advanced.")
        else:
            self.rec_sub.setText("Full reasoning under Advanced.")

    def pick_sessions(self) -> None:
        dlg = SessionPicker(self, self.engine.session.dir.name, self.extra_sessions)
        if dlg.exec():
            self.extra_sessions = dlg.chosen()
            self.parent_app.request_summary()

    def closeEvent(self, event) -> None:
        event.ignore()
        self.hide()


class App:
    def __init__(self, qapp: QApplication, engine: Engine, cfg_note: str) -> None:
        self.qapp, self.engine = qapp, engine
        self.store = Store()
        self.signals = Signals()
        self.signals.summary.connect(self.on_summary)
        self.window = Window(engine, self.store, cfg_note)
        self.window.parent_app = self
        self.tray = QSystemTrayIcon(dot_icon(GREY))
        menu = QMenu()
        show = QAction("Show window", menu)
        show.triggered.connect(self.show_window)
        mark = QAction("It stutters now", menu)
        mark.triggered.connect(lambda: engine.mark("marked from the tray"))
        quit_ = QAction("Quit (stop recording)", menu)
        quit_.triggered.connect(self.quit)
        menu.addAction(show)
        menu.addAction(mark)
        menu.addSeparator()
        menu.addAction(quit_)
        self.menu = menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.on_activated)
        self.tray.setToolTip(APP_NAME)
        self.tray.show()
        self._summary_busy = False
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)
        self.summary_timer = QTimer()
        self.summary_timer.timeout.connect(self.request_summary)
        self.summary_timer.start(SUMMARY_PERIOD_MS)
        self.signals.recommendation.connect(self.on_recommendation)
        self.window.rec_btn.clicked.connect(self.request_recommendation)
        self._rec_busy = False
        self._rec_summary = None
        self.rec_timer = QTimer()
        self.rec_timer.timeout.connect(self.request_recommendation)
        self.rec_timer.start(RECOMMEND_PERIOD_MS)
        QTimer.singleShot(2000, self.request_recommendation)
        self._last_hint_level = None
        self._window_shown = False

    def on_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.window.isVisible():
                self.window.hide()
            else:
                self.show_window()

    def show_window(self) -> None:
        # Maximized the first time; after that Qt keeps whatever size the
        # person gave it between hiding and showing.
        if self._window_shown:
            self.window.show()
        else:
            self.window.showMaximized()
            self._window_shown = True
        self.window.raise_()
        self.window.activateWindow()

    def hint_for(self, key: tuple | None) -> "advice.Hint":
        if key is None:
            return advice.Hint("unknown", "nothing recorded yet")
        cal = self.window.summary["calibration"].status if self.window.summary else "unconfirmed"
        cost = self.rtt_cost(key)
        return advice.live_hint(self.store.minutes.get(key, []), self.store.monitor_for(key),
                                self.store.on_vpn_now(key), cal, cost, self.store.seconds.get(key, []))

    def rtt_cost(self, key: tuple) -> float | None:
        """VPN minus direct RTT median for the service in this session, when
        both paths have at least a few minutes of data seconds."""
        s = self.window.summary
        if not s:
            return None
        paths = report.by_service(s["groups"]).get((key[0], str(key[1])), {})
        d = [x for p, g in paths.items() if p.startswith("direct:") for x in g.rtts]
        v = [x for p, g in paths.items() if p.startswith("vpn:") for x in g.rtts]
        if len(d) < 300 or len(v) < 300:
            return None
        return report.percentile(v, .5) - report.percentile(d, .5)

    def tick(self) -> None:
        self.store.add(self.engine.drain_updates())
        snap = self.engine.snapshot()
        self.update_tray(snap)
        services = self.store.services()
        busiest = services[0] if services else None
        hint = self.hint_for(busiest)
        if hint.level in ("switch", "return") and hint.level != self._last_hint_level:
            self.tray.showMessage(f"{busiest[0]} :{busiest[1]}", hint.text,
                                  QSystemTrayIcon.MessageIcon.Information, 15000)
        self._last_hint_level = hint.level
        self.window.refresh_services()
        if self.window.isVisible():
            shown = self.window.current_service()
            h = hint if shown == busiest else self.hint_for(shown)
            now_path, _ = self.window.path_now(snap)
            if now_path != getattr(self.window, "_now_path", None):
                self.window._now_path = now_path
                self.window.refresh_cards()
            self.window.show_hint(h)
            self.window.refresh_overview(snap, h)
            self.tick_view()
            self.window.refresh_chart()
            if self.window.stack.currentIndex() == 1:
                self.window.refresh_status(snap)
                self.window.refresh_probes(snap)
                self.window.refresh_events(snap)

    def tick_view(self) -> None:
        """Recompute the 'Recently' panel for the chosen service and window."""
        key = self.window.current_service()
        if key is None:
            return
        cost, best = self.window.comparison_from_cards()
        view = advice.recent_view(self.store.minutes.get(key, []), self.store.seconds.get(key, []),
                                  self.store.monitor_for(key), self.store.routes_for(key),
                                  self.store.on_vpn_now(key), self.window.recent_window_s(),
                                  time.time(), cost, best, list(self.store.probes))
        self.window.show_recent(view)

    def update_tray(self, snap) -> None:
        services = self.store.services()
        if not services or not any(c.captured for c in snap.connections):
            self.tray.setIcon(dot_icon(GREY))
            self.tray.setToolTip(f"{APP_NAME}: nothing captured yet ({snap.selection})")
            return
        key = services[0]
        rtx, data, path = self.store.last_minute(key)
        colour = (GREY if data == 0 else RED if 100 * rtx / data >= LOSS_RED_PCT
                  else YELLOW if rtx else GREEN)
        self.tray.setIcon(dot_icon(colour))
        conns = [c for c in snap.connections if c.program == key[0] and c.remote.endswith(f":{key[1]}")]
        busiest = max(conns, key=lambda c: c.segs_per_min) if conns else None
        rtt = f"{busiest.rtt_ms:.0f} ms" if busiest and busiest.rtt_ms is not None else "-"
        now_path = busiest.path if busiest else (path or "?")
        self.tray.setToolTip(f"{key[0]} :{key[1]}\n{now_path}\nRTT {rtt} · last minute "
                             f"{rtx} retransmissions / {data} packets")

    def request_summary(self) -> None:
        if self._summary_busy:
            return
        self._summary_busy = True
        dirs = [self.engine.session.dir] + [sessions_root() / n for n in sorted(self.window.extra_sessions)]

        def work():
            try:
                result = report.summarise(dirs)
            except Exception as exc:        # shown, not swallowed
                result = exc
            self.signals.summary.emit(result)

        threading.Thread(target=work, daemon=True).start()

    def request_recommendation(self) -> None:
        if self._rec_busy:
            return
        self._rec_busy = True
        from .cli import all_session_dirs

        def work():
            try:
                result = report.summarise(all_session_dirs())
            except Exception as exc:        # shown, not swallowed
                result = exc
            self.signals.recommendation.emit(result)

        threading.Thread(target=work, daemon=True).start()

    def on_recommendation(self, result) -> None:
        self._rec_busy = False
        self._rec_summary = result
        self.window.all_summary = result
        self.window.refresh_services()
        self.window.refresh_cards()
        self.window.show_recommendation(result)

    def on_summary(self, result) -> None:
        self._summary_busy = False
        if isinstance(result, Exception):
            self.window.verdict.setText(f"comparison failed: {result!r}")
            return
        self.window.summary = result
        self.window.refresh_table()
        self.window.refresh_cards()

    def quit(self) -> None:
        """Stop recording in the background (the session is closed
        properly, which takes a few seconds), then leave."""
        if getattr(self, "_stopping", None) is not None:
            return
        self.timer.stop()
        self.summary_timer.stop()
        self.tray.setToolTip(f"{APP_NAME}: stopping, closing the session…")
        self.window.status.setText("<b>Stopping</b> — closing the session…")
        self.window.banner_title.setText("Stopping — closing the session…")
        self._stopping = threading.Thread(target=self.engine.stop, daemon=True)
        self._stopping.start()
        self._wait = QTimer()
        self._wait.timeout.connect(self._finish_quit)
        self._wait.start(200)

    def _finish_quit(self) -> None:
        if self._stopping.is_alive():
            return
        self._wait.stop()
        release_pidfile()
        self.tray.hide()
        self.qapp.quit()


def apply_theme(qapp: QApplication) -> None:
    """Dark theme for every desktop: Fusion style, palette and stylesheet."""
    qapp.setStyle("Fusion")
    pal = QPalette()
    for role, colour in ((QPalette.ColorRole.Window, THEME["bg"]), (QPalette.ColorRole.Base, THEME["card"]),
                         (QPalette.ColorRole.AlternateBase, THEME["idle_bg"]),
                         (QPalette.ColorRole.Text, THEME["text"]), (QPalette.ColorRole.WindowText, THEME["text"]),
                         (QPalette.ColorRole.Button, THEME["raised"]), (QPalette.ColorRole.ButtonText, THEME["text"]),
                         (QPalette.ColorRole.Highlight, THEME["accent"]),
                         (QPalette.ColorRole.HighlightedText, THEME["on_accent"]),
                         (QPalette.ColorRole.ToolTipBase, THEME["raised"]),
                         (QPalette.ColorRole.ToolTipText, THEME["text"]),
                         (QPalette.ColorRole.PlaceholderText, THEME["muted"])):
        pal.setColor(role, QColor(colour))
    qapp.setPalette(pal)
    qapp.setStyleSheet(STYLE)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vpnct-gui", description="Record in the tray and show the comparison.")
    ap.add_argument("--program", action="append", default=[])
    ap.add_argument("--port", action="append", type=int, default=[])
    ap.add_argument("--target", action="append", default=[])
    ap.add_argument("--show", action="store_true", help="open the window at start")
    args = ap.parse_args(argv)

    qapp = QApplication(sys.argv[:1])
    qapp.setApplicationName(APP_NAME)
    qapp.setDesktopFileName(APP_NAME)
    qapp.setQuitOnLastWindowClosed(False)
    apply_theme(qapp)

    if args.program or args.port or args.target:
        programs, ports, targets = args.program, args.port, args.target or None
        note = "settings: command-line options"
    else:
        try:
            cfg = config.load()
        except config.ConfigError as exc:
            QMessageBox.critical(None, APP_NAME, f"Cannot read the settings:\n{exc}")
            return 2
        programs, ports, targets = cfg.programs, cfg.ports, cfg.targets
        note = f"settings: {cfg.source}"
    try:
        claim_pidfile()
    except SystemExit as exc:
        QMessageBox.warning(None, APP_NAME, str(exc))
        return 1
    if not QSystemTrayIcon.isSystemTrayAvailable():
        args.show = True                     # no tray: the window is the only way in
        note += " · no system tray found; closing the window hides it, use Quit… from the taskbar"

    engine = Engine(Selection(programs, ports), extra_targets=targets, echo=lambda _l: None)
    signal.signal(MARK_SIGNAL, lambda *_: engine.mark("mark requested from the command line"))
    app = App(qapp, engine, note)
    engine.start()
    # Let Ctrl+C in a terminal stop cleanly: Python handles signals only when
    # it runs, so a short timer gives it the chance.
    signal.signal(signal.SIGINT, lambda *_: app.quit())
    signal.signal(signal.SIGTERM, lambda *_: app.quit())
    keepalive = QTimer()
    keepalive.timeout.connect(lambda: None)
    keepalive.start(250)
    if args.show:
        app.show_window()
    return qapp.exec()


if __name__ == "__main__":
    raise SystemExit(main())
