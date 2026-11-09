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
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog,
                             QDialogButtonBox, QHBoxLayout, QHeaderView, QLabel,
                             QListWidget, QMainWindow, QMenu, QMessageBox, QPushButton,
                             QSplitter, QSystemTrayIcon, QTableWidget, QTableWidgetItem,
                             QVBoxLayout, QWidget)

from . import config, report
from .cli import MARK_SIGNAL, claim_pidfile, release_pidfile
from .engine import Engine, MinutePoint, SecondPoint
from .session import sessions_root
from .tracker import Selection

APP_NAME = "vpn-connection-test"
SUMMARY_PERIOD_MS = 15_000
HISTORY_S = 3 * 3600
LOSS_RED_PCT = 2.0
SPANS = [("10 min", 600), ("30 min", 1800), ("1 h", 3600), ("3 h", 3 * 3600)]

GREEN, YELLOW, RED, GREY = "#2e9d4a", "#d9a400", "#d0342c", "#8a8a8a"
DIRECT_SHADE = QColor(120, 140, 160, 45)
VPN_SHADES = [QColor(70, 130, 220, 55), QColor(160, 90, 210, 55), QColor(40, 170, 160, 55),
              QColor(220, 120, 60, 55)]


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

    def add(self, points: list) -> None:
        for pt in points:
            key = (pt.program, pt.port)
            if isinstance(pt, SecondPoint):
                self.seconds[key].append(pt)
                self.traffic[key] += pt.d_data_segs_in
            elif isinstance(pt, MinutePoint):
                self.minutes[key].append(pt)

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
        self.setMinimumHeight(240)
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
        left, right, top, bottom = 48, 10, 22, 22
        plot = QRectF(left, top, w - left - right, h - top - bottom)
        split = plot.top() + plot.height() * 0.62
        rtt_area = QRectF(plot.left(), plot.top(), plot.width(), split - plot.top() - 6)
        loss_area = QRectF(plot.left(), split + 6, plot.width(), plot.bottom() - split - 6)
        p.fillRect(self.rect(), self.palette().base())
        now = time.time()
        t0 = now - self.span
        x = lambda t: plot.left() + (t - t0) / self.span * plot.width()
        secs = [s for s in self.seconds if s.time >= t0]
        mins = [m for m in self.minutes if m.minute + 60 >= t0]

        # path bands, with a vertical line where the path changes
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
                        p.setPen(QPen(QColor(80, 80, 80, 160), 1, Qt.PenStyle.DashLine))
                        p.drawLine(QPointF(x(end), plot.top()), QPointF(x(end), plot.bottom()))
                if s is not None:
                    run_start, run_path = s.time, s.path

        # RTT: median across the service's connections per second, data seconds only
        per_second: dict[int, list[float]] = defaultdict(list)
        for s in secs:
            if s.rtt_ms is not None and s.d_data_segs_in > 0:
                per_second[int(s.time)].append(s.rtt_ms)
        pts = sorted((t, sorted(v)[len(v) // 2]) for t, v in per_second.items())
        rtt_max = max([v for _, v in pts] + [10.0]) * 1.15
        p.setPen(QPen(self.palette().text().color(), 1))
        p.drawText(QRectF(0, rtt_area.top() - 4, left - 6, 14), Qt.AlignmentFlag.AlignRight,
                   f"{rtt_max:.0f}")
        p.drawText(QRectF(0, rtt_area.bottom() - 10, left - 6, 14), Qt.AlignmentFlag.AlignRight, "0")
        p.drawText(QRectF(plot.left() + 4, rtt_area.top(), 200, 14), Qt.AlignmentFlag.AlignLeft,
                   "RTT [ms]")
        if pts:
            path = QPainterPath()
            for i, (t, v) in enumerate(pts):
                pt = QPointF(x(t), rtt_area.bottom() - v / rtt_max * rtt_area.height())
                path.moveTo(pt) if i == 0 or t - pts[i - 1][0] > 5 else path.lineTo(pt)
            p.setPen(QPen(QColor("#1f5fbf"), 1.6))
            p.drawPath(path)

        # retransmissions per minute (sum over the service's captured connections)
        per_min: dict[float, list[int]] = defaultdict(lambda: [0, 0, 0])
        for m in mins:
            agg = per_min[m.minute]
            agg[0] += m.retrans
            agg[1] += m.data_pkts
            agg[2] = max(agg[2], int(m.covered_s))
        loss_max = max([a[0] for a in per_min.values()] + [5])
        p.setPen(QPen(self.palette().text().color(), 1))
        p.drawText(QRectF(0, loss_area.top() - 4, left - 6, 14), Qt.AlignmentFlag.AlignRight,
                   f"{loss_max}")
        p.drawText(QRectF(plot.left() + 4, loss_area.top(), plot.width() - 8, 14), Qt.AlignmentFlag.AlignLeft,
                   "retransmissions / min (hatched: minute not fully captured)")
        for minute, (rtx, data, covered) in per_min.items():
            x0, x1 = x(max(minute, t0)), x(minute + 60)
            bh = rtx / loss_max * loss_area.height()
            rect = QRectF(x0 + 1, loss_area.bottom() - max(bh, 1.5), max(1.0, x1 - x0 - 2), max(bh, 1.5))
            colour = QColor(RED if data and 100 * rtx / data >= LOSS_RED_PCT
                            else YELLOW if rtx else GREEN)
            p.fillRect(rect, QBrush(colour, Qt.BrushStyle.SolidPattern if covered >= 55
                                    else Qt.BrushStyle.BDiagPattern))

        # axes, time labels, legend
        p.setPen(QPen(self.palette().mid().color(), 1))
        p.drawRect(plot)
        p.drawLine(QPointF(plot.left(), split), QPointF(plot.right(), split))
        p.setPen(QPen(self.palette().text().color(), 1))
        step = self.span / 6
        for i in range(7):
            t = t0 + i * step
            label = time.strftime("%H:%M", time.localtime(t))
            p.drawText(QRectF(x(t) - 25, plot.bottom() + 3, 50, 16), Qt.AlignmentFlag.AlignCenter, label)
        lx = plot.left()
        f = QFont(self.font())
        f.setPointSizeF(f.pointSizeF() * 0.9)
        p.setFont(f)
        for name, c in legend.items():
            solid = QColor(c)
            solid.setAlpha(200)
            p.fillRect(QRectF(lx, 4, 12, 12), solid)
            p.drawText(QRectF(lx + 16, 2, 400, 16), Qt.AlignmentFlag.AlignLeft, name)
            lx += 26 + p.fontMetrics().horizontalAdvance(name)
        if not secs:
            p.drawText(plot, Qt.AlignmentFlag.AlignCenter, "no data for this service in the chosen span yet")
        p.end()


class Signals(QObject):
    summary = pyqtSignal(object)


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


class Window(QMainWindow):
    METRICS = [
        ("time observed", lambda g: f"{g.seconds / 60:.1f} min"),
        ("connections", lambda g: f"{len(g.connections)}"),
        ("RTT median", lambda g: report._n(report.percentile(g.rtts, .5), "{:.0f} ms")),
        ("RTT p95", lambda g: report._n(report.percentile(g.rtts, .95), "{:.0f} ms")),
        ("captured", lambda g: f"{g.covered_s / 60:.1f} min"),
        ("data packets", lambda g: f"{g.data_pkts}"),
        ("retransmissions", lambda g: f"{g.retrans}"),
        ("loss", lambda g: report._n(report.loss_pct(g), "{:.2f} %")),
        ("retrans / min", lambda g: report._n(g.retrans / (g.covered_s / 60) if g.covered_s else None, "{:.2f}")),
        ("loss gaps", lambda g: f"{g.lost_gaps}"),
        ("worst minute", lambda g: f"{g.worst_minute_pct:.1f} %"),
    ]

    def __init__(self, engine: Engine, store: Store, cfg_note: str) -> None:
        super().__init__()
        self.engine, self.store = engine, store
        self.extra_sessions: set[str] = set()
        self.summary = None
        self.setWindowTitle(APP_NAME)
        self.resize(1000, 820)
        central = QWidget()
        lay = QVBoxLayout(central)

        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.RichText)
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.note = QLabel(cfg_note)
        self.note.setStyleSheet("color: gray")
        lay.addWidget(self.note)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Service:"))
        self.service = QComboBox()
        self.service.setMinimumWidth(240)
        self.service.currentIndexChanged.connect(self.refresh_chart)
        self.service.currentIndexChanged.connect(self.refresh_table)
        bar.addWidget(self.service)
        bar.addWidget(QLabel("Span:"))
        self.span = QComboBox()
        for name, _ in SPANS:
            self.span.addItem(name)
        self.span.setCurrentIndex(1)
        self.span.currentIndexChanged.connect(self.set_span)
        bar.addWidget(self.span)
        bar.addStretch(1)
        self.mark_btn = QPushButton("It stutters now")
        self.mark_btn.clicked.connect(lambda: self.engine.mark("marked in the window"))
        bar.addWidget(self.mark_btn)
        sessions_btn = QPushButton("Compare sessions…")
        sessions_btn.clicked.connect(self.pick_sessions)
        bar.addWidget(sessions_btn)
        folder_btn = QPushButton("Session folder")
        folder_btn.clicked.connect(lambda: subprocess.Popen(["xdg-open", str(self.engine.session.dir)]))
        bar.addWidget(folder_btn)
        lay.addLayout(bar)

        split = QSplitter(Qt.Orientation.Vertical)
        self.chart = Chart()
        split.addWidget(self.chart)

        cmp_box = QWidget()
        cl = QVBoxLayout(cmp_box)
        cl.setContentsMargins(0, 0, 0, 0)
        self.cmp_title = QLabel("<b>Comparison of paths</b>")
        cl.addWidget(self.cmp_title)
        self.table = QTableWidget()
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        cl.addWidget(self.table)
        self.verdict = QLabel()
        self.verdict.setWordWrap(True)
        cl.addWidget(self.verdict)
        split.addWidget(cmp_box)

        low = QSplitter(Qt.Orientation.Horizontal)
        probe_box = QWidget()
        pl = QVBoxLayout(probe_box)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.addWidget(QLabel("<b>Last probe round</b> (ping; bound = sent through that interface)"))
        self.probes = QTableWidget(0, 6)
        self.probes.setHorizontalHeaderLabels(["target", "role", "path", "bound", "loss", "RTT"])
        self.probes.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.probes.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.probes.horizontalHeader().setStretchLastSection(True)
        self.probes.verticalHeader().setVisible(False)
        pl.addWidget(self.probes)
        low.addWidget(probe_box)
        ev_box = QWidget()
        el = QVBoxLayout(ev_box)
        el.setContentsMargins(0, 0, 0, 0)
        el.addWidget(QLabel("<b>Events</b>"))
        self.events = QListWidget()
        el.addWidget(self.events)
        low.addWidget(ev_box)
        split.addWidget(low)
        split.setSizes([300, 280, 220])
        lay.addWidget(split, 1)
        self.setCentralWidget(central)

    # ---- periodic --------------------------------------------------------

    def set_span(self, i: int) -> None:
        self.chart.span = SPANS[i][1]
        self.chart.update()

    def current_service(self) -> tuple | None:
        return self.service.currentData()

    def refresh_services(self) -> None:
        known = [self.service.itemData(i) for i in range(self.service.count())]
        for key in self.store.services():
            if key not in known:
                self.service.addItem(f"{key[0]} :{key[1]}", key)
        if self.service.currentIndex() < 0 and self.service.count():
            self.service.setCurrentIndex(0)

    def refresh_chart(self) -> None:
        key = self.current_service()
        if key is None:
            self.chart.set_data([], [])
            return
        self.chart.set_data(self.store.seconds.get(key, []), self.store.minutes.get(key, []))

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

    def on_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.window.isVisible():
                self.window.hide()
            else:
                self.show_window()

    def show_window(self) -> None:
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def tick(self) -> None:
        self.store.add(self.engine.drain_updates())
        snap = self.engine.snapshot()
        self.update_tray(snap)
        if self.window.isVisible():
            self.window.refresh_services()
            self.window.refresh_status(snap)
            self.window.refresh_chart()
            self.window.refresh_probes(snap)
            self.window.refresh_events(snap)
        else:
            self.window.refresh_services()

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

    def on_summary(self, result) -> None:
        self._summary_busy = False
        if isinstance(result, Exception):
            self.window.verdict.setText(f"comparison failed: {result!r}")
            return
        self.window.summary = result
        self.window.refresh_table()

    def quit(self) -> None:
        """Stop recording in the background (the session is closed
        properly, which takes a few seconds), then leave."""
        if getattr(self, "_stopping", None) is not None:
            return
        self.timer.stop()
        self.summary_timer.stop()
        self.tray.setToolTip(f"{APP_NAME}: stopping, closing the session…")
        self.window.status.setText("<b>Stopping</b> — closing the session…")
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
