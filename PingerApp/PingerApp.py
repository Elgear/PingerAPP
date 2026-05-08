# PingerApp.py

# §1 ─────────────────────────────────────────────────────────────────────────────
# Imports
import sys
import socket
import subprocess
import platform
import re
import urllib.request
import ping3
import math
import json
import os
import shutil

from collections import deque
from datetime import datetime
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt, QPointF, QRectF, QSize
from PyQt5.QtGui import QPainter, QPen, QFont, QColor
from PyQt5.QtWidgets import (
    QApplication, QWidget,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QGroupBox, QSlider, QTextEdit,
    QSizePolicy, QGridLayout
)
from matplotlib.backends.backend_qt5agg import (
    FigureCanvasQTAgg as FigureCanvas,
    NavigationToolbar2QT as NavigationToolbar
)
from matplotlib.figure import Figure
from matplotlib.ticker import MultipleLocator, NullFormatter, Locator, NullLocator



# §1.B ───────────────────────────────────────────────────────────────────────────
# Helper functions
def get_public_ip(timeout=2):
    """Return public IPv4 via api.ipify.org."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as r:
            return r.read().decode()
    except:
        return "N/A"

def get_default_gateway():
    """Return LAN gateway by parsing system route tables."""
    try:
        if platform.system()=="Windows":
            out = subprocess.check_output(["route","print","-4"], text=True)
            for line in out.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts)>=3:
                        return parts[2]
        else:
            out = subprocess.check_output(["ip","route"], text=True)
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    return parts[parts.index("via")+1]
    except:
        pass
    return "N/A"

def get_local_ip():
    """Return local LAN IP (not loopback)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8",80))
        return s.getsockname()[0]
    except:
        return "N/A"
    finally:
        s.close()


# §2 ─────────────────────────────────────────────────────────────────────────────
class TracerouteWorker(QThread):
    """Runs tracert/traceroute in background and emits each line."""
    line_ready = pyqtSignal(str)

    def __init__(self, host: str):
        super().__init__()
        self.host = host

    def run(self):
        cmd = ["tracert", self.host] if platform.system()=="Windows" else ["traceroute", self.host]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            self.line_ready.emit(line.rstrip())
        proc.wait()


# §3 ─────────────────────────────────────────────────────────────────────────────
class HostInfoWorker(QThread):
    """Fetches local network details without blocking the UI thread."""
    info_ready = pyqtSignal(str, str, str)

    def run(self):
        self.info_ready.emit(get_local_ip(), get_default_gateway(), get_public_ip())


class DnsLookupWorker(QThread):
    """Resolves a hostname or reverse-resolves an IP address in the background."""
    result_ready = pyqtSignal(str)
    error_ready = pyqtSignal(str)

    def __init__(self, query: str):
        super().__init__()
        self.query = query

    def run(self):
        try:
            socket.inet_aton(self.query)
            try:
                self.result_ready.emit(socket.gethostbyaddr(self.query)[0])
            except socket.herror:
                self.error_ready.emit(f"Cannot reverse-resolve {self.query}")
            return
        except OSError:
            pass

        try:
            _, __, ips = socket.gethostbyname_ex(self.query)
            self.result_ready.emit("\n".join(ips))
        except socket.gaierror:
            self.error_ready.emit(f"Cannot resolve {self.query}")


class StartResolveWorker(QThread):
    """Resolves the ping target before the ping timer starts."""
    resolved = pyqtSignal(str, str)
    error_ready = pyqtSignal(str)

    def __init__(self, host: str):
        super().__init__()
        self.host = host

    def run(self):
        try:
            ip = socket.gethostbyname(self.host)
        except socket.gaierror:
            self.error_ready.emit(f"Cannot resolve {self.host}")
            return

        rd = "Host Not Found"
        try:
            rd = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            pass
        self.resolved.emit(ip, rd)


class SpeedTestWorker(QThread):
    """Runs LibreSpeed CLI in the background and returns parsed JSON."""
    result_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def __init__(self, executable: str):
        super().__init__()
        self.executable = executable

    def run(self):
        cmd = [self.executable, "--json", "--telemetry-level", "disabled", "--no-icmp"]
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 180,
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except FileNotFoundError:
            self.error_ready.emit("LibreSpeed CLI executable was not found.")
            return
        except subprocess.TimeoutExpired:
            self.error_ready.emit("Speed test timed out after 180 seconds.")
            return
        except OSError as e:
            self.error_ready.emit(f"Could not run LibreSpeed CLI: {e}")
            return

        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "LibreSpeed CLI failed.").strip()
            self.error_ready.emit(message)
            return

        output = completed.stdout.strip()
        object_start = output.find("{")
        array_start = output.find("[")
        starts = [pos for pos in (object_start, array_start) if pos != -1]
        start = min(starts) if starts else -1
        end = output.rfind("]" if start == array_start else "}")
        if start == -1 or end == -1 or end <= start:
            self.error_ready.emit("LibreSpeed CLI did not return JSON output.")
            return

        try:
            parsed = json.loads(output[start:end+1])
        except json.JSONDecodeError as e:
            self.error_ready.emit(f"Could not parse LibreSpeed JSON: {e}")
            return

        if isinstance(parsed, list):
            if not parsed:
                self.error_ready.emit("LibreSpeed CLI returned an empty result list.")
                return
            parsed = parsed[0]

        if not isinstance(parsed, dict):
            self.error_ready.emit("LibreSpeed CLI returned an unsupported JSON shape.")
            return

        self.result_ready.emit(parsed)


class PingerApp(QWidget):
    """§3 Main application window for Home Pinger."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Home Pinger")
        self.move(100,100)
        self.resize(1460, 900)
        self.setMinimumSize(1440, 940)

        # §3.A Initialization ────────────────────────────────────────────────────

        # §3.A.0 Create and inject one raw ICMP socket into ping3
        self._ping_sock = None
        self.host_info_worker = None
        self.dns_worker = None
        self.start_worker = None
        self.speedtest_worker = None

        # §3.A.a Host input & Start/Pause controls
        self.host_input = QLineEdit("8.8.8.8")
        self.host_input.setToolTip("Enter IP or hostname to ping")
        self.host_input.setAlignment(Qt.AlignCenter)

        self.start_btn = QPushButton("Start")
        self.start_btn.setFixedSize(100,30)
        self.start_btn.setToolTip("Start/Stop ping loop")
        self.start_btn.clicked.connect(self.toggle_ping)

        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setFixedSize(100,30)
        self.pause_btn.setCheckable(True)
        self.pause_btn.setToolTip("Pause/Resume ping loop")
        self.pause_btn.clicked.connect(self.toggle_pause)

        # §3.A.b One-off DNS lookup
        self.dns_input      = QLineEdit()
        self.dns_input.setPlaceholderText("example.com or 1.2.3.4")
        self.dns_btn        = QPushButton("Lookup")
        self.dns_btn.setToolTip("Resolve hostname/IP")
        self.dns_btn.clicked.connect(self.do_dns_lookup)
        self.dns_result_box = QTextEdit()
        self.dns_result_box.setReadOnly(True)
        self.dns_result_box.setFixedHeight(60)

        # §3.A.c Live displays: latency, elapsed time, reverse DNS
        self.live_latency    = QLineEdit("Idle")
        self.live_latency.setReadOnly(True)
        self.live_latency.setAlignment(Qt.AlignCenter)
        self.live_latency.setFixedSize(100,30)

        self.live_jitter = QLineEdit("Idle")
        self.live_jitter.setReadOnly(True)
        self.live_jitter.setAlignment(Qt.AlignCenter)
        self.live_jitter.setFixedSize(100,30)

        self.elapsed_display = QLineEdit("00:00")
        self.elapsed_display.setReadOnly(True)
        self.elapsed_display.setAlignment(Qt.AlignCenter)
        self.elapsed_display.setFixedSize(100,30)
        self.elapsed_seconds = 0
        self.elapsed_timer   = QTimer(self)
        self.elapsed_timer.setInterval(1000)
        self.elapsed_timer.timeout.connect(self._on_elapsed_tick)

        self.reverse_dns_disp = QLineEdit("")
        self.reverse_dns_disp.setReadOnly(True)
        self.reverse_dns_disp.setAlignment(Qt.AlignCenter)
        self.reverse_dns_disp.setFixedSize(100,30)

        # §3.A.d Thresholds & sliders
        self.lat_thresh_input  = QLineEdit("30")
        self.lat_thresh_input.setFixedWidth(60)
        self.lat_thresh_input.setToolTip("0-300 ms. Alert when ping latency exceeds this value.")
        self.loss_thresh_input = QLineEdit("10")
        self.loss_thresh_input.setFixedWidth(60)
        self.loss_thresh_input.setToolTip("0-100%. Alert when packet loss exceeds this percentage.")
        
        # Jitter threshold input
        self.jit_thresh_input  = QLineEdit("5")
        self.jit_thresh_input.setFixedWidth(60)
        self.jit_thresh_input.setToolTip("0-100 ms. Alert when ping-to-ping variation exceeds this value.")

        self.history_input = QLineEdit("30")
        self.history_input.setFixedWidth(60)
        self.history_input.setToolTip("10-100 pings. Number of recent pings shown in the graphs.")

        self.lat_default_btn = self._make_default_button("Reset latency alert to 30 ms.")
        self.loss_default_btn = self._make_default_button("Reset loss alert to 10%.")
        self.jit_default_btn = self._make_default_button("Reset jitter alert to 5 ms.")
        self.history_default_btn = self._make_default_button("Reset history length to 30 pings.")

        self.lat_slider = QSlider(Qt.Horizontal)
        self.lat_slider.setRange(0,300); self.lat_slider.setValue(30)
        self.lat_slider.setMinimumWidth(360)
        self.lat_slider.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.lat_slider.setToolTip("Latency alert threshold, 0-300 ms.")
        self.lat_slider.valueChanged.connect(self.on_lat_slider_change)

        self.loss_slider = QSlider(Qt.Horizontal)
        self.loss_slider.setRange(0,100); self.loss_slider.setValue(10)
        self.loss_slider.setMinimumWidth(360)
        self.loss_slider.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.loss_slider.setToolTip("Packet loss alert threshold, 0-100%.")
        self.loss_slider.valueChanged.connect(self.on_loss_slider_change)

        self.jit_slider = QSlider(Qt.Horizontal)
        self.jit_slider.setRange(0,100); self.jit_slider.setValue(5)
        self.jit_slider.setMinimumWidth(360)
        self.jit_slider.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.jit_slider.setToolTip("Jitter alert threshold, 0-100 ms.")
        self.jit_slider.valueChanged.connect(self.on_jit_slider_change)

        self.history_slider = QSlider(Qt.Horizontal)
        self.history_slider.setRange(10,100); self.history_slider.setValue(30)
        self.history_slider.setTickInterval(10)
        self.history_slider.setTickPosition(QSlider.TicksBelow)
        self.history_slider.setMinimumWidth(360)
        self.history_slider.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.history_slider.setToolTip("History length, 10-100 pings.")
        self.history_slider.valueChanged.connect(self.on_history_slider_change)

        self.lat_thresh_input.editingFinished.connect(self.on_lat_input_change)
        self.loss_thresh_input.editingFinished.connect(self.on_loss_input_change)
        self.jit_thresh_input.editingFinished.connect(self.on_jit_input_change)
        self.history_input.editingFinished.connect(self.on_history_input_change)
        self.lat_default_btn.clicked.connect(lambda: self.set_threshold_default(self.lat_thresh_input, self.lat_slider, 30))
        self.loss_default_btn.clicked.connect(lambda: self.set_threshold_default(self.loss_thresh_input, self.loss_slider, 10))
        self.jit_default_btn.clicked.connect(lambda: self.set_threshold_default(self.jit_thresh_input, self.jit_slider, 5))
        self.history_default_btn.clicked.connect(lambda: self.set_threshold_default(self.history_input, self.history_slider, 30))

        # §3.A.e Auto-scale toggle
        self.auto_btn = QPushButton("Auto-scale: ON")
        self.auto_btn.setCheckable(True); self.auto_btn.setChecked(True)
        self.auto_btn.clicked.connect(self.toggle_autoscale)

        # §3.A.f Alert toggles & Reset
        self.lat_toggle_btn  = QPushButton("Latency Alerts: ON")
        self.lat_toggle_btn.setCheckable(True); self.lat_toggle_btn.setChecked(True)
        self.lat_toggle_btn.toggled.connect(self.toggle_latency_alerts)

        self.loss_toggle_btn = QPushButton("Loss Alerts: ON")
        self.loss_toggle_btn.setCheckable(True); self.loss_toggle_btn.setChecked(True)
        self.loss_toggle_btn.toggled.connect(self.toggle_loss_alerts)

        self.jit_toggle_btn  = QPushButton("Jitter Alerts: ON")
        self.jit_toggle_btn.setCheckable(True); self.jit_toggle_btn.setChecked(True)
        self.jit_toggle_btn.toggled.connect(self.toggle_jitter_alerts)

        self.reset_btn = QPushButton("Reset Stats")
        self.reset_btn.setMinimumWidth(145)
        self.reset_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.reset_btn.clicked.connect(self.reset_all_counts)

        self._set_toggle_widths(
            (self.lat_toggle_btn,  "Latency Alerts"),
            (self.loss_toggle_btn, "Loss Alerts"),
            (self.jit_toggle_btn,  "Jitter Alerts")
        )

        # §3.A.g Avg-line toggles
        self.best_avg_btn     = QPushButton("Best Avg: ON")
        self.best_avg_btn.setCheckable(True); self.best_avg_btn.setChecked(True)
        self.worst_avg_btn    = QPushButton("Worst Avg: ON")
        self.worst_avg_btn.setCheckable(True); self.worst_avg_btn.setChecked(True)
        self.combined_avg_btn = QPushButton("Comb Avg: ON")
        self.combined_avg_btn.setCheckable(True); self.combined_avg_btn.setChecked(True)
        self.best_avg_btn.toggled.connect(self.toggle_best_avg)
        self.worst_avg_btn.toggled.connect(self.toggle_worst_avg)
        self.combined_avg_btn.toggled.connect(self.toggle_combined_avg)
        self._set_toggle_widths(
            (self.best_avg_btn,  "Best Avg"),
            (self.worst_avg_btn, "Worst Avg"),
            (self.combined_avg_btn, "Comb Avg")
        )

        # §3.A.h Jitter-stat toggles & labels
        self.jit_min_btn = QPushButton("Min: ON")
        self.jit_min_btn.setCheckable(True); self.jit_min_btn.setChecked(True)
        self.jit_max_btn = QPushButton("Max: ON")
        self.jit_max_btn.setCheckable(True); self.jit_max_btn.setChecked(True)
        self.jit_avg_btn = QPushButton("Avg: ON")
        self.jit_avg_btn.setCheckable(True); self.jit_avg_btn.setChecked(True)
        self.jit_min_btn.toggled.connect(self.toggle_jit_min)
        self.jit_max_btn.toggled.connect(self.toggle_jit_max)
        self.jit_avg_btn.toggled.connect(self.toggle_jit_avg)
        self._set_toggle_widths(
            (self.jit_min_btn, "Min"),
            (self.jit_max_btn, "Max"),
            (self.jit_avg_btn, "Avg")
        )

        self.jit_low_label  = QLabel("0.0 ms")
        self.jit_high_label = QLabel("0.0 ms")
        self.jit_avg_label  = QLabel("0.0 ms")

        # §3.A.i Two-axis Matplotlib setup (latency & jitter)
        self.fig = Figure(figsize=(6,6))
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setMinimumHeight(390)
        self.ax_lat = self.fig.add_subplot(2,1,1)
        self.ax_jit = self.fig.add_subplot(2,1,2, sharex=self.ax_lat)

        self._ping_line, = self.ax_lat.plot([],[],marker='o', label="Latency")
        self._jit_line,  = self.ax_jit.plot([],[],marker='x', label="Jitter")

        self.ax_lat.set_ylabel("Latency (ms)")
        self.ax_jit.set_ylabel("Jitter (ms)")
        self.ax_jit.set_xlabel("")
        self._set_empty_axes()
        self._apply_graph_layout()

        self.latencies    = deque(maxlen=self.history_slider.value())
        self.jitters      = deque(maxlen=self.history_slider.value())
        self.prev_latency = None
        self.top_n        = 10

        # §3.A.j Traceroute table
        self.tr_button = QPushButton("Run Traceroute")
        self.tr_button.clicked.connect(self.start_traceroute)
        self.tr_table  = QTableWidget(0,4)
        self.tr_table.setHorizontalHeaderLabels(["Hop","IP","Host","Latency"])
        self.tr_table.verticalHeader().setVisible(False)
        hdr = self.tr_table.horizontalHeader()
        hdr.setSectionResizeMode(0,QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1,QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2,QHeaderView.Stretch)
        hdr.setSectionResizeMode(3,QHeaderView.ResizeToContents)
        self.trace_target_label = QLabel()
        self.trace_target_label.setToolTip("Traceroute uses the current Host field from the Ping Panel.")
        self.host_input.textChanged.connect(self._update_trace_target_label)
        self._update_trace_target_label(self.host_input.text())

        self.alert_window = None
        self.alert_log_box = QTextEdit()
        self.alert_log_box.setReadOnly(True)
        self.alert_log_box.setPlaceholderText("Threshold alerts will appear here.")
        self.alerts_btn = QPushButton("Alerts")
        self.alerts_btn.setFixedSize(135, 30)
        self.alerts_btn.setToolTip("Open threshold alert log")
        self.alerts_btn.clicked.connect(self.show_alert_log)
        self.speedtest_window = None
        self.speedtest_labels = {}
        self.speedtest_status_label = None
        self.speedtest_run_btn = None
        self.speedtest_btn = QPushButton("Speed Test")
        self.speedtest_btn.setFixedSize(135, 30)
        self.speedtest_btn.setToolTip("Open internet speed test")
        self.speedtest_btn.clicked.connect(self.show_speedtest_window)

        # §3.A.k Host-info fields
        self.host_ip_label   = QLabel("Loading...")
        self.gateway_label   = QLabel("Loading...")
        self.public_ip_label = QLabel("Loading...")

        # §3.A.l Counters & labels
        self.lat_count_label   = QLabel("0")
        self.loss_count_label  = QLabel("0")
        self.loss_value_label  = QLabel("0.0%")
        self.rtt_health_label = QLabel("No data")
        self.rtt_health_label.setAlignment(Qt.AlignCenter)
        self.rtt_health_label.setFixedSize(90, 30)
        self.jitter_health_label = QLabel("No data")
        self.jitter_health_label.setAlignment(Qt.AlignCenter)
        self.jitter_health_label.setFixedSize(90, 30)
        self._set_status_label(self.rtt_health_label, "No data", "Start pinging to calculate RTT health.")
        self._set_status_label(self.jitter_health_label, "No data", "Start pinging to calculate jitter health.")
        self.avg_low_label     = QLabel("0.0 ms")
        self.avg_high_label    = QLabel("0.0 ms")
        self.avg_comb_label    = QLabel("0.0 ms")

        # ─── §3.B Layout assembly ────────────────────────────────────────────────
        left = QVBoxLayout()

        # §3.B.a Ping-Panel
        ping_row = QGroupBox("Ping Panel")
        ping_row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        ping_row.setFixedHeight(115)
        ping_h = QHBoxLayout()
        ping_h.setContentsMargins(8,8,8,8)
        ping_h.setSpacing(12)
        ping_h.setAlignment(Qt.AlignLeft)

        target_group = QGroupBox("Target")
        target_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        target_h = QHBoxLayout()
        target_h.setContentsMargins(8,8,8,8)
        target_h.setSpacing(6)
        target_cols = [
            ("Host",         self.host_input,       200,30),
            ("Reverse DNS",  self.reverse_dns_disp, 200,30),
            ("Start/Stop",   self.start_btn,         90,30),
            ("Pause/Resume", self.pause_btn,         90,30),
        ]
        for index, (lbl_text, wgt, w,h) in enumerate(target_cols):
            wgt.setFixedSize(w,h)
            v = QVBoxLayout(); v.setSpacing(2)
            v.addWidget(QLabel(lbl_text), 0, Qt.AlignCenter)
            v.addWidget(wgt)
            target_h.addLayout(v)
            if index == 1:
                target_h.addSpacing(26)
            elif index == 2:
                target_h.addSpacing(10)
        target_group.setLayout(target_h)

        live_group = QGroupBox("Live Status")
        live_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        live_group.setFixedWidth(430)
        live_h = QHBoxLayout()
        live_h.setContentsMargins(8,8,8,8)
        live_h.setSpacing(12)
        live_cols = [
            ("Live Latency", self.live_latency,        100,30),
            ("RTT Health",   self.rtt_health_label,     90,30),
            ("Live Jitter",  self.live_jitter,         100,30),
            ("Jitter Health", self.jitter_health_label, 90,30),
        ]
        for lbl_text, wgt, w,h in live_cols:
            wgt.setFixedSize(w,h)
            v = QVBoxLayout(); v.setSpacing(2)
            v.addWidget(QLabel(lbl_text), 0, Qt.AlignCenter)
            v.addWidget(wgt)
            live_h.addLayout(v)
        live_group.setLayout(live_h)

        elapsed_group = QGroupBox("Session")
        elapsed_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        elapsed_h = QHBoxLayout()
        elapsed_h.setContentsMargins(8,8,8,8)
        v = QVBoxLayout(); v.setSpacing(2)
        v.addWidget(QLabel("Elapsed Time"), 0, Qt.AlignCenter)
        v.addWidget(self.elapsed_display)
        elapsed_h.addLayout(v)
        elapsed_group.setLayout(elapsed_h)

        speedtest_group = QGroupBox("Speed Test")
        speedtest_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        stg = QHBoxLayout()
        stg.setContentsMargins(8,8,8,8)
        stg.addWidget(self.speedtest_btn, 0, Qt.AlignCenter)
        speedtest_group.setLayout(stg)

        ping_h.addWidget(target_group)
        ping_h.addWidget(live_group)
        ping_h.addStretch(1)
        ping_h.addWidget(elapsed_group)
        ping_h.addWidget(speedtest_group)
        ping_row.setLayout(ping_h)

        
        
        # §3.B.b Thresholds & sliders
        monitoring_group = QGroupBox("Monitoring")
        monitoring_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        monitoring_layout = QVBoxLayout()
        monitoring_layout.setContentsMargins(6,6,6,6)
        monitoring_layout.setSpacing(6)

        threshold_group = QGroupBox("Alert Thresholds")
        threshold_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        threshold_group.setMinimumWidth(835)
        threshold_group.setFixedHeight(150)
        form = QFormLayout()
        form.setContentsMargins(8,8,8,8)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(6)

        form.addRow(
            "Latency Alert (ms):",
            self._build_control_row(self.lat_thresh_input, self.lat_slider, self.lat_toggle_btn, self.lat_default_btn)
        )
        form.addRow(
            "Loss Alert (%):",
            self._build_control_row(self.loss_thresh_input, self.loss_slider, self.loss_toggle_btn, self.loss_default_btn)
        )
        form.addRow(
            "Jitter Alert (ms):",
            self._build_control_row(self.jit_thresh_input, self.jit_slider, self.jit_toggle_btn, self.jit_default_btn)
        )
        form.addRow(
            "History (pings):",
            self._build_control_row(self.history_input, self.history_slider, default_button=self.history_default_btn)
        )
        threshold_group.setLayout(form)
        monitoring_layout.addWidget(threshold_group)
                
        # §3.B.c Alert-Counts panel
        alert_group = QGroupBox("Alert Counts")
        alert_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        alert_group.setMinimumSize(165,120)
        ag = QGridLayout(); ag.setContentsMargins(8,8,8,8)
        ag.setHorizontalSpacing(8); ag.setVerticalSpacing(6)
        ag.setColumnStretch(0, 1)
        ag.setColumnStretch(1, 1)
        ag.addWidget(QLabel("Latency breaches:"), 0,0)
        ag.addWidget(self.lat_count_label,        0,1)
        ag.addWidget(QLabel("Loss breaches:"),    1,0)
        ag.addWidget(self.loss_count_label,       1,1)
        ag.addWidget(QLabel("Packet Loss (%):"),  2,0)
        ag.addWidget(self.loss_value_label,       2,1)
        ag.addWidget(self.reset_btn,              3,0,1,2)
        alert_group.setLayout(ag)

        # §3.B.d Latency-Stats panel
        stats_group = QGroupBox("Latency Stats")
        stats_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        stats_group.setMinimumSize(235,120)
        sg = QGridLayout(); sg.setContentsMargins(8,8,8,8)
        sg.setHorizontalSpacing(12); sg.setVerticalSpacing(6)
        sg.addWidget(QLabel("Avg best 10:"),  0,0)
        sg.addWidget(self.avg_low_label,      0,1)
        sg.addWidget(self.best_avg_btn,       0,2)
        sg.addWidget(QLabel("Avg worst 10:"), 1,0)
        sg.addWidget(self.avg_high_label,     1,1)
        sg.addWidget(self.worst_avg_btn,      1,2)
        sg.addWidget(QLabel("Avg combined:"), 2,0)
        sg.addWidget(self.avg_comb_label,     2,1)
        sg.addWidget(self.combined_avg_btn,   2,2)
        stats_group.setLayout(sg)

        # §3.B.e Jitter-Stats panel
        jit_group = QGroupBox("Jitter Stats")
        jit_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        jit_group.setMinimumSize(215,120)
        jl = QGridLayout(); jl.setContentsMargins(8,8,8,8)
        jl.setHorizontalSpacing(12); jl.setVerticalSpacing(6)
        jl.addWidget(QLabel("Min jitter:"),   0,0)
        jl.addWidget(self.jit_low_label,      0,1)
        jl.addWidget(self.jit_min_btn,        0,2)
        jl.addWidget(QLabel("Max jitter:"),   1,0)
        jl.addWidget(self.jit_high_label,     1,1)
        jl.addWidget(self.jit_max_btn,        1,2)
        jl.addWidget(QLabel("Avg jitter:"),   2,0)
        jl.addWidget(self.jit_avg_label,      2,1)
        jl.addWidget(self.jit_avg_btn,        2,2)
        jit_group.setLayout(jl)

        # §3.B.f Host-Info panel
        host_info_group = QGroupBox("Host Info")
        host_info_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        host_info_group.setMinimumSize(190,120)
        hi = QGridLayout(); hi.setContentsMargins(8,8,8,8)
        hi.setHorizontalSpacing(8); hi.setVerticalSpacing(6)
        hi.addWidget(QLabel("Local Host IP:"),     0,0)
        hi.addWidget(self.host_ip_label,           0,1)
        hi.addWidget(QLabel("1st Hop/Gateway:"),   1,0)
        hi.addWidget(self.gateway_label,           1,1)
        hi.addWidget(QLabel("Public IP:"),         2,0)
        hi.addWidget(self.public_ip_label,         2,1)
        host_info_group.setLayout(hi)

        # combine panels
        panel_h = QHBoxLayout(); panel_h.setAlignment(Qt.AlignLeft)
        panel_h.addWidget(alert_group, 1)
        panel_h.addWidget(stats_group, 2)
        panel_h.addWidget(jit_group, 2)
        panel_h.addWidget(host_info_group, 2)
        monitoring_layout.addLayout(panel_h)
        monitoring_group.setLayout(monitoring_layout)
        left.addWidget(monitoring_group)

        # §3.B.g Toolbar + Canvas
        graph_group = QGroupBox("Graphs")
        graph_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        graph_layout = QVBoxLayout()
        graph_layout.setContentsMargins(8,8,8,8)
        graph_layout.setSpacing(6)
        tb = QHBoxLayout()
        tb.addWidget(NavigationToolbar(self.canvas, self))
        tb.addStretch()
        tb.addWidget(self.auto_btn)
        graph_layout.addLayout(tb)
        graph_layout.addWidget(self.canvas, 1)
        graph_group.setLayout(graph_layout)
        left.addWidget(graph_group, 1)

        # §3.B.h Right pane: DNS & Traceroute
        right = QVBoxLayout()
        dns_group = QGroupBox("DNS Lookup")
        dns_group.setSizePolicy(QSizePolicy.Fixed,QSizePolicy.Fixed)
        dns_group.setFixedWidth(360)
        dv = QVBoxLayout(); dh = QHBoxLayout()
        self.dns_input.setFixedSize(260,30); dh.addWidget(self.dns_input)
        self.dns_btn.setFixedSize(70,30);      dh.addWidget(self.dns_btn)
        dv.addLayout(dh); dv.addWidget(self.dns_result_box)
        dns_group.setLayout(dv)
        right.addWidget(dns_group)

        trace_group = QGroupBox("Traceroute")
        trace_group.setSizePolicy(QSizePolicy.Fixed,QSizePolicy.Expanding)
        trace_group.setFixedWidth(360)
        tv = QVBoxLayout()
        tv.addWidget(self.tr_button)
        tv.addWidget(self.trace_target_label)
        tv.addWidget(self.tr_table)
        trace_group.setLayout(tv)
        right.addWidget(trace_group, 1)

        alerts_group = QGroupBox("Alert Log")
        alerts_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        alerts_group.setFixedWidth(360)
        alerts_h = QHBoxLayout()
        alerts_h.setContentsMargins(8,8,8,8)
        alerts_h.addWidget(self.alerts_btn, 0, Qt.AlignCenter)
        alerts_group.setLayout(alerts_h)
        right.addWidget(alerts_group)

        content = QHBoxLayout()
        content.addLayout(left, 1)
        content.addLayout(right, 0)

        main = QVBoxLayout()
        main.addWidget(ping_row)
        main.addLayout(content, 1)
        self.setLayout(main)

        # §3.C Timer & state
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.do_ping)
        self.pinging          = False
        self.paused           = False
        self.ping_count       = 0
        self.timeouts         = 0
        self.alerted_latency  = False
        self.alerted_loss     = False
        self.alerted_jitter   = False
        self.lat_exceed_count = 0
        self.loss_exceed_count= 0
        self.prev_loss_pct    = 0.0
        self.refresh_host_info()


    # §3.D Slots & helpers ─────────────────────────────────────────────────────

    def _open_ping_socket(self):
        """Create the ICMP socket only when pinging starts."""
        if self._ping_sock is not None:
            return True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError as e:
            QMessageBox.critical(
                self,
                "Ping Error",
                "Cannot create a raw ICMP socket.\n\n"
                "Run the app with the required network privileges or use a ping backend "
                f"that does not require raw sockets.\n\n{e}"
            )
            return False

        self._ping_sock = sock
        ping3._socket = sock
        return True

    def _close_ping_socket(self):
        sock = self._ping_sock
        self._ping_sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if getattr(ping3, "_socket", None) is sock:
            ping3._socket = None

    def refresh_host_info(self):
        """Refresh network labels without freezing the window."""
        if self.host_info_worker is not None and self.host_info_worker.isRunning():
            return
        self.host_info_worker = HostInfoWorker()
        self.host_info_worker.info_ready.connect(self._set_host_info)
        self.host_info_worker.finished.connect(self.host_info_worker.deleteLater)
        self.host_info_worker.finished.connect(lambda: setattr(self, "host_info_worker", None))
        self.host_info_worker.start()

    def _set_host_info(self, local_ip: str, gateway: str, public_ip: str):
        self.host_ip_label.setText(local_ip)
        self.gateway_label.setText(gateway)
        self.public_ip_label.setText(public_ip)

    def _update_trace_target_label(self, host: str):
        target = host.strip() or "No target"
        self.trace_target_label.setText(f"Target: {target}")

    def _valid_values(self, values):
        return [v for v in values if v is not None]

    def _set_status_label(self, label: QLabel, status: str, detail: str):
        styles = {
            "Healthy": ("#e6f4ea", "#137333", "#8abf9a"),
            "Watch": ("#fff4ce", "#8a5a00", "#d8b756"),
            "Poor": ("#fce8e6", "#a50e0e", "#d28b82"),
            "Collecting": ("#eef2f7", "#3c4043", "#b7c0cc"),
            "No data": ("#eef2f7", "#3c4043", "#b7c0cc"),
        }
        bg, fg, border = styles.get(status, styles["No data"])
        label.setText(status)
        label.setToolTip(detail)
        label.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {fg}; border: 1px solid {border}; border-radius: 3px; padding: 2px 4px; }}"
        )

    def _log_alert(self, title: str, message: str):
        """Append a timestamped monitoring alert without blocking the UI."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.alert_log_box.append(f"[{timestamp}] {title}: {message}")
        self.alerts_btn.setText("Alerts *")

    def show_alert_log(self):
        """Open the non-modal alert log window."""
        if self.alert_window is None:
            self.alert_window = QWidget(None, Qt.Window)
            self.alert_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.alert_window.setWindowTitle("Alert Log")
            self.alert_window.resize(520, 320)
            layout = QVBoxLayout()
            layout.addWidget(self.alert_log_box)
            self.alert_window.setLayout(layout)

        self.alerts_btn.setText("Alerts")
        self.alert_window.show()
        self.alert_window.raise_()
        self.alert_window.activateWindow()

    def show_speedtest_window(self):
        """Open the non-modal speed test window."""
        if self.speedtest_window is None:
            self.speedtest_window = QWidget(None, Qt.Window)
            self.speedtest_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.speedtest_window.setWindowTitle("Speed Test")
            self.speedtest_window.setMinimumSize(460, 430)
            self.speedtest_window.resize(460, 430)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            self.speedtest_status_label = QLabel("Ready")
            self.speedtest_status_label.setWordWrap(True)
            self.speedtest_status_label.setAlignment(Qt.AlignCenter)
            self.speedtest_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.speedtest_status_label)

            self.speedtest_run_btn = QPushButton("Run Speed Test")
            self.speedtest_run_btn.setMinimumHeight(34)
            self.speedtest_run_btn.clicked.connect(self.start_speed_test)
            layout.addWidget(self.speedtest_run_btn)

            def add_result_section(title, fields):
                group = QGroupBox(title)
                grid = QGridLayout()
                grid.setContentsMargins(10,10,10,10)
                grid.setHorizontalSpacing(14)
                grid.setVerticalSpacing(8)
                for row, (key, text) in enumerate(fields):
                    name = QLabel(text)
                    name.setStyleSheet("QLabel { color: #333333; }")
                    value = QLabel("N/A")
                    value.setMinimumWidth(340)
                    value.setMinimumHeight(26)
                    value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                    value.setWordWrap(True)
                    value.setStyleSheet(
                        "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                        "border-radius: 3px; padding: 4px 6px; }"
                    )
                    self.speedtest_labels[key] = value
                    grid.addWidget(name, row, 0)
                    grid.addWidget(value, row, 1)
                grid.setColumnStretch(1, 1)
                group.setLayout(grid)
                layout.addWidget(group)

            add_result_section("Throughput", [
                ("download", "Download"),
                ("upload", "Upload"),
            ])
            add_result_section("Quality", [
                ("latency", "Latency"),
                ("jitter", "Jitter"),
                ("loss", "Packet Loss"),
            ])
            add_result_section("Endpoint", [
                ("server", "Server"),
                ("isp", "ISP"),
                ("result", "Result URL"),
            ])
            self.speedtest_window.setLayout(layout)

        self.speedtest_window.layout().activate()
        self.speedtest_window.adjustSize()
        if self.speedtest_window.width() < 460 or self.speedtest_window.height() < 430:
            self.speedtest_window.resize(max(self.speedtest_window.width(), 460), max(self.speedtest_window.height(), 430))
        self.speedtest_window.show()
        self.speedtest_window.raise_()
        self.speedtest_window.activateWindow()

    def _speedtest_candidate_roots(self):
        roots = []
        if getattr(sys, "frozen", False):
            roots.append(os.path.dirname(sys.executable))
            bundle_root = getattr(sys, "_MEIPASS", None)
            if bundle_root:
                roots.append(bundle_root)

        module_dir = os.path.dirname(os.path.abspath(__file__))
        roots.append(module_dir)
        roots.append(os.path.abspath(os.path.join(module_dir, os.pardir)))
        return roots

    def _find_speedtest_executable(self):
        exe_name = "librespeed-cli.exe" if platform.system() == "Windows" else "librespeed-cli"
        for root in self._speedtest_candidate_roots():
            for rel in (
                os.path.join("tools", "librespeed", exe_name),
                os.path.join("bin", exe_name),
                exe_name,
            ):
                candidate = os.path.join(root, rel)
                if os.path.isfile(candidate):
                    return candidate
        return shutil.which("librespeed-cli")

    def start_speed_test(self):
        """Run a manual LibreSpeed CLI test in the background."""
        if self.speedtest_worker is not None and self.speedtest_worker.isRunning():
            return

        executable = self._find_speedtest_executable()
        if not executable:
            self._set_speedtest_status(
                "LibreSpeed CLI not found. Put librespeed-cli.exe in tools/librespeed "
                "or install librespeed-cli so it is available on PATH."
            )
            return

        self._set_speedtest_status("Running speed test. This may use significant bandwidth...")
        self.speedtest_run_btn.setEnabled(False)
        self.speedtest_worker = SpeedTestWorker(executable)
        self.speedtest_worker.result_ready.connect(self._set_speedtest_result)
        self.speedtest_worker.error_ready.connect(self._set_speedtest_error)
        self.speedtest_worker.finished.connect(self._finish_speedtest)
        self.speedtest_worker.finished.connect(self.speedtest_worker.deleteLater)
        self.speedtest_worker.finished.connect(lambda: setattr(self, "speedtest_worker", None))
        self.speedtest_worker.start()

    def _set_speedtest_status(self, message: str):
        if self.speedtest_status_label is not None:
            self.speedtest_status_label.setText(message)
            if message.startswith("Speed test failed") or message.startswith("LibreSpeed CLI not found"):
                style = (
                    "QLabel { background: #fce8e6; color: #a50e0e; border: 1px solid #d28b82; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            elif message.startswith("Running"):
                style = (
                    "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            elif message.startswith("Speed test completed"):
                style = (
                    "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            else:
                style = (
                    "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            self.speedtest_status_label.setStyleSheet(style)

    def _format_mbps(self, value):
        if value is None:
            return "N/A"
        return f"{float(value):.2f} Mbps"

    def _dict_get_any(self, data: dict, *keys):
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return data[key]
        return None

    def _set_speedtest_result(self, data: dict):
        server = data.get("server", {}) or {}
        client = data.get("client", {}) or {}

        server_parts = [
            self._dict_get_any(server, "name", "Name"),
            self._dict_get_any(server, "sponsorName", "sponsor", "Sponsor"),
            self._dict_get_any(server, "server", "url", "URL"),
        ]
        server_text = ", ".join(part for part in server_parts if part) or "N/A"
        isp = (
            self._dict_get_any(client, "isp", "ISP", "org", "Org")
            or self._dict_get_any(client, "ip", "IP")
            or "N/A"
        )

        values = {
            "download": self._format_mbps(data.get("download")),
            "upload": self._format_mbps(data.get("upload")),
            "latency": "N/A" if data.get("ping") is None else f"{float(data.get('ping')):.1f} ms",
            "jitter": "N/A" if data.get("jitter") is None else f"{float(data.get('jitter')):.1f} ms",
            "loss": "N/A (not reported by LibreSpeed)",
            "server": server_text,
            "isp": isp,
            "result": data.get("share") or "N/A",
        }

        for key, value in values.items():
            self.speedtest_labels[key].setText(value)
        self._set_speedtest_status("Speed test completed.")

    def _set_speedtest_error(self, message: str):
        self._set_speedtest_status(f"Speed test failed: {message}")

    def _finish_speedtest(self):
        if self.speedtest_run_btn is not None:
            self.speedtest_run_btn.setEnabled(True)

    def _refresh_health_status(self):
        """Update rolling RTT and jitter health guidance."""
        raw_latencies = list(self.latencies)
        if not raw_latencies:
            self._set_status_label(self.rtt_health_label, "No data", "Start pinging to calculate RTT health.")
            self._set_status_label(self.jitter_health_label, "No data", "Start pinging to calculate jitter health.")
            return

        if len(raw_latencies) < 3:
            self._set_status_label(self.rtt_health_label, "Collecting", "Collecting at least 3 ping samples before rating RTT health.")
            self._set_status_label(self.jitter_health_label, "Collecting", "Collecting at least 3 ping samples before rating jitter health.")
            return

        valid_latencies = self._valid_values(raw_latencies)
        window_loss_pct = (raw_latencies.count(None) / len(raw_latencies)) * 100
        valid_jitters = self._valid_values(self.jitters)

        if not valid_latencies:
            self._set_status_label(self.rtt_health_label, "Poor", f"Rolling loss is {window_loss_pct:.1f}% with no successful replies.")
            self._set_status_label(self.jitter_health_label, "No data", "No successful replies for jitter calculation.")
            return

        avg_rtt = sum(valid_latencies) / len(valid_latencies)
        avg_jitter = sum(valid_jitters) / len(valid_jitters) if valid_jitters else 0.0

        if window_loss_pct >= 2.0 or avg_rtt >= 150:
            rtt_status = "Poor"
        elif window_loss_pct > 0 or avg_rtt >= 80:
            rtt_status = "Watch"
        else:
            rtt_status = "Healthy"

        if avg_jitter >= 30:
            jitter_status = "Poor"
        elif avg_jitter >= 10:
            jitter_status = "Watch"
        else:
            jitter_status = "Healthy"

        self._set_status_label(
            self.rtt_health_label,
            rtt_status,
            f"Rolling {len(raw_latencies)} pings: avg RTT {avg_rtt:.1f} ms, loss {window_loss_pct:.1f}%."
        )
        self._set_status_label(
            self.jitter_health_label,
            jitter_status,
            f"Rolling {len(raw_latencies)} pings: avg jitter {avg_jitter:.1f} ms."
        )

    def _set_toggle_widths(self, *button_specs):
        """Give related toggle buttons enough width for both ON and OFF labels."""
        widths = []
        for button, label in button_specs:
            original = button.text()
            for state in ("ON", "OFF"):
                button.setText(f"{label}: {state}")
                widths.append(button.sizeHint().width())
            button.setText(original)

        width = max(widths) + 8
        for button, _ in button_specs:
            button.setFixedWidth(width)

    def _make_default_button(self, tooltip: str):
        button = QPushButton("Default")
        button.setFixedWidth(58)
        button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        button.setToolTip(tooltip)
        return button

    def _build_control_row(self, value_input, slider, toggle_button=None, default_button=None):
        row = QHBoxLayout()
        row.setAlignment(Qt.AlignLeft)
        row.setSpacing(8)
        row.addWidget(value_input)
        row.addWidget(slider, 1)
        if toggle_button is not None:
            row.addWidget(toggle_button)
        if default_button is not None:
            row.addWidget(default_button)
        return row

    def _sync_input_to_slider(self, value_input, slider, fallback):
        try:
            value = int(float(value_input.text()))
        except ValueError:
            value = fallback
        value = max(slider.minimum(), min(slider.maximum(), value))
        value_input.setText(str(value))
        if slider.value() != value:
            slider.setValue(value)
        return value

    def set_threshold_default(self, value_input, slider, default):
        value_input.setText(str(default))
        slider.setValue(default)
        self.update_graph()

    def _set_empty_axes(self):
        """Use readable graph ranges before any ping samples exist."""
        self.ax_lat.set_title("Ping Latency over Time")
        self.ax_lat.set_ylabel("Latency (ms)")
        self.ax_lat.set_xlabel("")
        self.ax_lat.set_xlim(0, 10)
        self.ax_lat.set_ylim(0, 100)

        self.ax_jit.set_title("Ping Jitter over Time")
        self.ax_jit.set_ylabel("Jitter (ms)")
        self.ax_jit.set_xlabel("")
        self.ax_jit.set_xlim(0, 10)
        self.ax_jit.set_ylim(0, 10)

    def _apply_graph_layout(self):
        """Keep the two shared-x plots separated enough for labels and titles."""
        self.fig.tight_layout(h_pad=2.6)
        self.fig.subplots_adjust(hspace=0.55, bottom=0.12, top=0.92)

    def _apply_ping_axis_ticks(self, sample_count: int):
        """Label every ping on the shared x-axis."""
        x_max = max(sample_count, 10)
        self.ax_lat.set_xlim(0, x_max)
        self.ax_jit.set_xlim(0, x_max)
        for axis in (self.ax_lat, self.ax_jit):
            axis.xaxis.set_major_locator(MultipleLocator(1))
            axis.xaxis.set_minor_locator(NullLocator())
            axis.xaxis.grid(True, which='major', linewidth=0.2)

    def do_dns_lookup(self):
        """Resolve input as IP (reverse) or hostname (forward)."""
        hostname = self.dns_input.text().strip()
        if not hostname:
            return
        if self.dns_worker is not None and self.dns_worker.isRunning():
            return

        self.dns_btn.setEnabled(False)
        self.dns_result_box.setPlainText("Resolving...")
        self.dns_worker = DnsLookupWorker(hostname)
        self.dns_worker.result_ready.connect(self._set_dns_result)
        self.dns_worker.error_ready.connect(self._show_dns_error)
        self.dns_worker.finished.connect(lambda: self.dns_btn.setEnabled(True))
        self.dns_worker.finished.connect(self.dns_worker.deleteLater)
        self.dns_worker.finished.connect(lambda: setattr(self, "dns_worker", None))
        self.dns_worker.start()

    def _set_dns_result(self, result: str):
        self.dns_result_box.setPlainText(result)

    def _show_dns_error(self, message: str):
        self.dns_result_box.clear()
        QMessageBox.warning(self, "DNS Error", message)

    def on_lat_slider_change(self, val: int):
        """Sync latency threshold textbox & redraw."""
        self.lat_thresh_input.setText(str(val))
        self.update_graph()

    def on_loss_slider_change(self, val: int):
        """Sync packet loss threshold textbox."""
        self.loss_thresh_input.setText(str(val))

    def on_jit_slider_change(self, val: int):
        """Sync jitter threshold textbox & redraw."""
        self.jit_thresh_input.setText(str(val))
        self.update_graph()

    def on_history_slider_change(self, val: int):
        """Resize history & jitter deques preserving recent data."""
        self.history_input.setText(str(val))
        old_lat = list(self.latencies)
        old_jit = list(self.jitters)
        self.latencies = deque(old_lat[-val:], maxlen=val)
        self.jitters   = deque(old_jit[-val:], maxlen=val)
        self.update_graph()

    def on_lat_input_change(self):
        self._sync_input_to_slider(self.lat_thresh_input, self.lat_slider, 30)
        self.update_graph()

    def on_loss_input_change(self):
        self._sync_input_to_slider(self.loss_thresh_input, self.loss_slider, 10)

    def on_jit_input_change(self):
        self._sync_input_to_slider(self.jit_thresh_input, self.jit_slider, 5)
        self.update_graph()

    def on_history_input_change(self):
        self._sync_input_to_slider(self.history_input, self.history_slider, 30)

    def toggle_autoscale(self, checked: bool):
        """Toggle automatic Y-axis scaling on/off."""
        self.auto_btn.setText("Auto-scale: ON" if checked else "Auto-scale: OFF")
        self.update_graph()

    def toggle_pause(self):
        """Pause/resume ping loop (and elapsed clock)."""
        if not self.pinging:
            return
        if not self.paused:
            self.timer.stop()
            self.elapsed_timer.stop()
            self.pause_btn.setText("Resume")
            self.paused = True
        else:
            self.timer.start()
            self.elapsed_timer.start()
            self.pause_btn.setText("Pause")
            self.paused = False

    def reset_all_counts(self):
        """Zero out all breach counters, stats, and clear alerts."""
        self.latencies.clear()
        self.jitters.clear()
        self.ping_count        = 0
        self.timeouts          = 0
        self.prev_latency      = None
        self.lat_exceed_count   = 0
        self.loss_exceed_count  = 0
        self.prev_loss_pct      = 0.0
        self.alerted_latency    = False
        self.alerted_loss       = False
        self.alerted_jitter     = False
        # reset labels
        for lbl in (self.lat_count_label, self.loss_count_label):
            lbl.setText("0")
        for lbl in (self.avg_low_label, self.avg_high_label, self.avg_comb_label):
            lbl.setText("0.0 ms")
        self.loss_value_label.setText("0.0%")
        for lbl in (self.jit_low_label, self.jit_high_label, self.jit_avg_label):
            lbl.setText("0.0 ms")
        self._refresh_health_status()
        self.update_graph()

    def toggle_ping(self):
        """Start or stop the ping loop (with forward/reverse DNS)."""
        if not self.pinging:
            host = self.host_input.text().strip()
            if not host or (self.start_worker is not None and self.start_worker.isRunning()):
                return
            self.start_btn.setEnabled(False)
            self.start_btn.setText("Wait")
            self.start_worker = StartResolveWorker(host)
            self.start_worker.resolved.connect(self._begin_ping_session)
            self.start_worker.error_ready.connect(self._show_start_error)
            self.start_worker.finished.connect(self._finish_start_resolution)
            self.start_worker.finished.connect(self.start_worker.deleteLater)
            self.start_worker.finished.connect(lambda: setattr(self, "start_worker", None))
            self.start_worker.start()
        else:
            # stop
            self.timer.stop()
            self.elapsed_timer.stop()
            self.pinging = False
            self.start_btn.setText("Start")
            self.pause_btn.setChecked(False)
            self.pause_btn.setText("Pause")
            self.paused = False
            self.live_latency.setText("Idle")
            self.live_jitter.setText("Idle")
            self.reverse_dns_disp.clear()
            self.elapsed_seconds = 0
            self.elapsed_display.setText("00:00")
            self._close_ping_socket()

    def _begin_ping_session(self, ip: str, reverse_dns: str):
        """Reset state and start the ping timers after target resolution succeeds."""
        if not self._open_ping_socket():
            return

        self.host_input.setText(ip)
        self.reverse_dns_disp.setText(reverse_dns)
        self.refresh_host_info()

        self.latencies.clear()
        self.jitters.clear()
        self.ping_count = self.timeouts = 0
        self.prev_latency = None
        self.alerted_latency = self.alerted_loss = self.alerted_jitter = False
        self.lat_exceed_count = self.loss_exceed_count = 0
        self.prev_loss_pct = 0.0
        self._refresh_health_status()

        self.start_btn.setText("Stop")
        self.start_btn.setEnabled(True)
        self.pinging = True
        self.elapsed_seconds = 0
        self.elapsed_display.setText("00:00")
        self.timer.start()
        self.elapsed_timer.start()

    def _show_start_error(self, message: str):
        QMessageBox.warning(self, "DNS Error", message)

    def _finish_start_resolution(self):
        if not self.pinging:
            self.start_btn.setText("Start")
            self.start_btn.setEnabled(True)

    def do_ping(self):
        """Perform a single ping, update metrics, compute jitter, redraw."""
        host = self.host_input.text().strip()
        try:
            latency = ping3.ping(host, unit="ms")
        except OSError as e:
            print(f"[do_ping] socket error: {e}")
            return

        self.ping_count += 1
        if latency is None:
            display, value = "Timeout", None
            self.timeouts += 1
        else:
            display, value = f"{latency:.1f} ms", latency

        loss_pct = (self.timeouts / self.ping_count) * 100
        self.live_latency.setText(display)
        self.loss_value_label.setText(f"{loss_pct:.1f}%")

        # latency alert
        try: lt = float(self.lat_thresh_input.text())
        except ValueError: lt = None
        latency_alert_active = self.lat_toggle_btn.isChecked()
        if (
            latency_alert_active
            and lt is not None
            and value is not None
            and value > lt
        ):
            self._log_alert("Latency", f"{display} > {lt} ms")
            self.alerted_latency = True
        elif (
            not latency_alert_active
            or lt is None
            or value is None
            or value <= lt
        ):
            self.alerted_latency = False

        # loss alert
        try: lp = float(self.loss_thresh_input.text())
        except ValueError: lp = None
        loss_alert_active = self.loss_toggle_btn.isChecked()
        if loss_alert_active and lp is not None and loss_pct > lp:
            self._log_alert("Packet Loss", f"{loss_pct:.1f}% > {lp}%")
            self.alerted_loss = True
        elif not loss_alert_active or lp is None or loss_pct <= lp:
            self.alerted_loss = False

        # count breaches
        if latency_alert_active and lt is not None and value is not None and value > lt:
            self.lat_exceed_count += 1
            self.lat_count_label.setText(str(self.lat_exceed_count))
        if loss_alert_active and lp is not None and loss_pct > lp and self.prev_loss_pct <= lp:
            self.loss_exceed_count += 1
            self.loss_count_label.setText(str(self.loss_exceed_count))
        self.prev_loss_pct = loss_pct

        # record latency
        self.latencies.append(value)

        # compute jitter
        if value is None:
            j = None
            self.prev_latency = None
        elif self.prev_latency is not None:
            j = abs(value - self.prev_latency)
            self.prev_latency = value
        else:
            j = 0.0
            self.prev_latency = value
        self.jitters.append(j)
        self.live_jitter.setText("Timeout" if j is None else f"{j:.1f} ms")

        valid_jitters = self._valid_values(self.jitters)
        if valid_jitters:
            s = sorted(valid_jitters)
            self.jit_low  = s[0]
            self.jit_high = s[-1]
            self.jit_avg  = sum(s)/len(s)
        else:
            self.jit_low = self.jit_high = self.jit_avg = 0.0

        try:
            jt = float(self.jit_thresh_input.text())
        except ValueError:
            jt = None
        if (
            self.jit_toggle_btn.isChecked()
            and jt is not None
            and j is not None
            and j > jt
        ):
            self._log_alert("Jitter", f"{j:.1f} ms > {jt} ms")
            self.alerted_jitter = True
        elif (
            not self.jit_toggle_btn.isChecked()
            or jt is None
            or j is None
            or j <= jt
        ):
            self.alerted_jitter = False

        self.jit_low_label.setText(f"{self.jit_low:.1f} ms")
        self.jit_high_label.setText(f"{self.jit_high:.1f} ms")
        self.jit_avg_label.setText(f"{self.jit_avg:.1f} ms")
        self._refresh_health_status()


        # redraw plot
        self.update_graph()

    def update_graph(self):
        """§3.D.h Redraw both latency and jitter axes with all toggles."""
        from math import ceil

        # 1) Prepare data
        raw_y  = list(self.latencies)
        raw_yj = list(self.jitters)
        x   = list(range(1, len(raw_y) + 1))
        xj  = list(range(1, len(raw_yj) + 1))
        y   = [math.nan if v is None else v for v in raw_y]
        yj  = [math.nan if v is None else v for v in raw_yj]
        valid_y  = self._valid_values(raw_y)
        valid_yj = self._valid_values(raw_yj)

        # 2) If autoscale OFF → just update existing line objects
        if not self.auto_btn.isChecked():
            self._ping_line.set_data(x, y)
            self._jit_line .set_data(xj, yj)
            self.canvas.draw()
            return

        # 3) Clear both axes, replot series
        self.ax_lat.clear()
        self.ax_jit.clear()
        self._ping_line, = self.ax_lat.plot(x, y,  marker='o', label="Latency")
        self._jit_line,  = self.ax_jit.plot(xj, yj, marker='x', label="Jitter")

        # 4) Latency autoscale + adaptive ticks & grid
        if valid_y:
            mn, mx = min(valid_y), max(valid_y)
            span   = max(mx-mn,1)
            pad    = max(span*0.2, 0.75)
            self.ax_lat.set_ylim(max(0, mn-pad), mx+pad)
        else:
            self._set_empty_axes()

        ymin, ymax = self.ax_lat.get_ylim(); span = ymax - ymin
        if   span<=5:    major = 0.5
        elif span<=10:   major = 1
        elif span<=20:   major = 2
        elif span<=50:   major = 5
        elif span<=100:  major = 10
        elif span<=200:  major = 20
        else:            major = 50

        self.ax_lat.yaxis.set_major_locator(MultipleLocator(major))
        minor = major/5
        if span/minor <= Locator.MAXTICKS:
            self.ax_lat.yaxis.set_minor_locator(MultipleLocator(minor))
            self.ax_lat.yaxis.set_minor_formatter(NullFormatter())
        else:
            self.ax_lat.yaxis.set_minor_locator(NullLocator())

        self.ax_lat.yaxis.grid(True,which='major',linewidth=0.2)
        self.ax_lat.yaxis.grid(True,which='minor',linestyle='--',linewidth=0.2)
        self._apply_ping_axis_ticks(max(len(raw_y), len(raw_yj), 10))

        # thick 5-ms gridlines
        top5 = ceil(self.ax_lat.get_ylim()[1]/5)*5
        for y0 in range(0, top5+1, 5):
            self.ax_lat.axhline(y0, color='gray',linewidth=1.0, zorder=0)

        # 5) Latency averages & threshold
        if valid_y:
            s = sorted(valid_y); N = min(self.top_n, len(valid_y))
            avg_low  = sum(s[:N])/N
            avg_high = sum(s[-N:])/N
        else:
            avg_low = avg_high = 0.0
        avg_comb = (avg_low + avg_high)/2

        self.avg_low_label .setText(f"{avg_low:.1f} ms")
        self.avg_high_label.setText(f"{avg_high:.1f} ms")
        self.avg_comb_label.setText(f"{avg_comb:.1f} ms")

        if self.best_avg_btn.isChecked():
            self.ax_lat.axhline(avg_low, color='blue', linestyle='--',linewidth=1.2,
                                label=f"Avg best {self.top_n}")
        if self.worst_avg_btn.isChecked():
            self.ax_lat.axhline(avg_high, color='green',linestyle='--',linewidth=1.2,
                                label=f"Avg worst {self.top_n}")
        if self.combined_avg_btn.isChecked():
            self.ax_lat.axhline(avg_comb, color='purple',linestyle='--',linewidth=1.2,
                                label="Avg combined")

        try: lt = float(self.lat_thresh_input.text())
        except: lt=None
        if lt is not None and self.lat_toggle_btn.isChecked():
            self.ax_lat.axhline(lt, color='red',linestyle='--',linewidth=1.5,
                                label=f"Threshold {lt} ms")
            for i, v in enumerate(raw_y):
                if v is not None and v>lt:
                    self.ax_lat.plot(x[i], v, marker='s',markersize=5, color='red')

        self.ax_lat.legend(loc='upper right', fontsize='small')
        self.ax_lat.set_title("Ping Latency over Time")
        self.ax_lat.set_ylabel("Latency (ms)")
        self.ax_lat.set_xlabel("")

        # 6) Jitter threshold & stat lines
        try:
            jt = float(self.jit_thresh_input.text())
        except:
            jt = None

        if jt is not None and self.jit_toggle_btn.isChecked():
            self.ax_jit.axhline(jt, color='orange', linestyle='--',linewidth=1.5,
                                label=f"Jitter TH {jt} ms")
            for i, v in enumerate(raw_yj):
                if v is not None and v>jt:
                    self.ax_jit.plot(xj[i], v, marker='D', markersize=4, color='orange')

        if hasattr(self, 'jit_low')  and self.jit_min_btn.isChecked():
            self.ax_jit.axhline(self.jit_low,  color='orange', linestyle='--',linewidth=1.2, label="Min jitter")
        if hasattr(self, 'jit_high') and self.jit_max_btn.isChecked():
            self.ax_jit.axhline(self.jit_high, color='red',    linestyle='--',linewidth=1.2, label="Max jitter")
        if hasattr(self, 'jit_avg')  and self.jit_avg_btn.isChecked():
            self.ax_jit.axhline(self.jit_avg,  color='magenta',linestyle='--',linewidth=1.2, label="Avg jitter")

        jitter_scale_values = list(valid_yj)
        if jt is not None and self.jit_toggle_btn.isChecked():
            jitter_scale_values.append(jt)
        if hasattr(self, 'jit_low') and self.jit_min_btn.isChecked():
            jitter_scale_values.append(self.jit_low)
        if hasattr(self, 'jit_high') and self.jit_max_btn.isChecked():
            jitter_scale_values.append(self.jit_high)
        if hasattr(self, 'jit_avg') and self.jit_avg_btn.isChecked():
            jitter_scale_values.append(self.jit_avg)

        if jitter_scale_values:
            jmn, jmx = min(jitter_scale_values), max(jitter_scale_values)
            jspan = max(jmx-jmn, 1)
            jpad = max(jspan*0.15, 0.25)
            self.ax_jit.set_ylim(max(0, jmn-jpad), jmx+jpad)

            jymin, jymax = self.ax_jit.get_ylim()
            jaxis_span = jymax - jymin
            if   jaxis_span<=2:   jmajor = 0.25
            elif jaxis_span<=5:   jmajor = 0.5
            elif jaxis_span<=10:  jmajor = 1
            elif jaxis_span<=20:  jmajor = 2
            else:                 jmajor = 5

            self.ax_jit.yaxis.set_major_locator(MultipleLocator(jmajor))
            jminor = jmajor/2
            if jaxis_span/jminor <= Locator.MAXTICKS:
                self.ax_jit.yaxis.set_minor_locator(MultipleLocator(jminor))
                self.ax_jit.yaxis.set_minor_formatter(NullFormatter())
            else:
                self.ax_jit.yaxis.set_minor_locator(NullLocator())

        self.ax_jit.yaxis.grid(True, which='major', linewidth=0.2)
        self.ax_jit.yaxis.grid(True, which='minor', linestyle='--', linewidth=0.2)

        self.ax_jit.legend(loc='upper right', fontsize='small')
        self.ax_jit.set_title("Ping Jitter over Time")
        self.ax_jit.set_ylabel("Jitter (ms)")
        self.ax_jit.set_xlabel("")

        self._apply_graph_layout()
        self.canvas.draw()

    def start_traceroute(self):
        """§3.D.i Kick off background traceroute."""
        host = self.host_input.text().strip()
        if not host:
            return
        self._update_trace_target_label(host)
        self.tr_button.setEnabled(False)
        self.tr_table.setRowCount(0)
        self.tr_worker = TracerouteWorker(host)
        self.tr_worker.line_ready.connect(self.handle_trace_line)
        self.tr_worker.finished.connect(lambda: self.tr_button.setEnabled(True))
        self.tr_worker.start()

    def handle_trace_line(self, line: str):
        """§3.D.i Append each traceroute hop to table."""
        m = re.match(r'\s*(\d+)', line)
        if not m:
            return
        hop = m.group(1)
        lat_m = re.search(r'(\d+(?:\.\d+)?)\s*ms', line)
        latency = f"{lat_m.group(1)} ms" if lat_m else ""
        ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        ip = ip_m.group(1) if ip_m else "*"
        parts = [tok for tok in line.split()[1:]
                 if not(tok.endswith("ms")
                        or re.fullmatch(r'\d+', tok)
                        or re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', tok))]
        hostnm = " ".join(parts) or (ip if ip!="*" else "")
        row = self.tr_table.rowCount()
        self.tr_table.insertRow(row)
        for col,val in enumerate((hop, ip, hostnm, latency)):
            self.tr_table.setItem(row, col, QTableWidgetItem(val))

    # §3.D.x Alert toggles
    def toggle_latency_alerts(self, checked: bool):
        self.lat_toggle_btn.setText(f"Latency Alerts: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_loss_alerts(self, checked: bool):
        self.loss_toggle_btn.setText(f"Loss Alerts: {'ON' if checked else 'OFF'}")

    def toggle_jitter_alerts(self, checked: bool):
        self.jit_toggle_btn.setText(f"Jitter Alerts: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_best_avg(self, checked: bool):
        self.best_avg_btn.setText(f"Best Avg: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_worst_avg(self, checked: bool):
        self.worst_avg_btn.setText(f"Worst Avg: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_combined_avg(self, checked: bool):
        self.combined_avg_btn.setText(f"Comb Avg: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_jit_min(self, checked: bool):
        self.jit_min_btn.setText(f"Min: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_jit_max(self, checked: bool):
        self.jit_max_btn.setText(f"Max: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def toggle_jit_avg(self, checked: bool):
        self.jit_avg_btn.setText(f"Avg: {'ON' if checked else 'OFF'}")
        self.update_graph()

    def closeEvent(self, event):
        self.timer.stop()
        self.elapsed_timer.stop()
        self._close_ping_socket()
        super().closeEvent(event)

    def _on_elapsed_tick(self):
        """§3.D.z Called every second while pinging."""
        self.elapsed_seconds += 1
        m, s = divmod(self.elapsed_seconds, 60)
        self.elapsed_display.setText(f"{m:02d}:{s:02d}")


# ─────────────────────────────────────────────────────────────────────────────
if __name__=="__main__":
    app = QApplication(sys.argv)
    win = PingerApp()
    win.show()
    sys.exit(app.exec_())
