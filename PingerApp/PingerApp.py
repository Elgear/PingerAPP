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
import time
import uuid

from collections import deque
from datetime import datetime
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt, QPointF, QRectF, QSize
from PyQt5.QtGui import QPainter, QPen, QFont, QColor, QBrush
from PyQt5.QtWidgets import (
    QApplication, QWidget,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QGroupBox, QSlider, QTextEdit,
    QSizePolicy, QGridLayout, QComboBox, QCheckBox, QSpinBox, QProgressBar
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

def get_public_ip_info(timeout=3):
    """Return public IP metadata for ISP/ASN display."""
    try:
        with urllib.request.urlopen("https://ipwho.is/", timeout=timeout) as r:
            data = json.loads(r.read().decode())
    except Exception:
        return {
            "ip": "N/A",
            "isp": "N/A",
            "asn": "N/A",
            "location": "N/A",
            "source": "ipwho.is",
        }

    connection = data.get("connection", {}) or {}
    parts = [data.get("city"), data.get("region"), data.get("country")]
    return {
        "ip": data.get("ip") or "N/A",
        "isp": connection.get("isp") or connection.get("org") or "N/A",
        "asn": connection.get("asn") or "N/A",
        "location": ", ".join(part for part in parts if part) or "N/A",
        "source": "ipwho.is",
    }

def get_primary_mac():
    """Return the host MAC address formatted for display."""
    value = uuid.getnode()
    if (value >> 40) % 2:
        return "N/A"
    return ":".join(f"{(value >> shift) & 0xff:02X}" for shift in range(40, -1, -8))

def first_available(*values):
    for value in values:
        if value not in (None, "", "N/A"):
            return value
    return "N/A"

def service_name(port):
    try:
        return socket.getservbyport(int(port), "tcp")
    except OSError:
        return "unknown"

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

    def __init__(self, host: str, max_hops=30, timeout_ms=4000):
        super().__init__()
        self.host = host
        self.max_hops = max_hops
        self.timeout_ms = timeout_ms

    def run(self):
        if platform.system() == "Windows":
            cmd = ["tracert", "-h", str(self.max_hops), "-w", str(self.timeout_ms), self.host]
        else:
            cmd = ["traceroute", "-m", str(self.max_hops), "-w", str(max(1, int(self.timeout_ms / 1000))), self.host]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            self.line_ready.emit(line.rstrip())
        proc.wait()


# §3 ─────────────────────────────────────────────────────────────────────────────
class HostInfoWorker(QThread):
    """Fetches local network details without blocking the UI thread."""
    info_ready = pyqtSignal(dict)

    def run(self):
        public_info = get_public_ip_info()
        self.info_ready.emit({
            "hostname": socket.gethostname(),
            "local_ip": get_local_ip(),
            "gateway": get_default_gateway(),
            "public_ip": first_available(public_info.get("ip"), get_public_ip()),
            "isp": first_available(public_info.get("isp")),
            "asn": first_available(public_info.get("asn")),
            "location": first_available(public_info.get("location")),
            "mac": get_primary_mac(),
            "source": first_available(public_info.get("source")),
        })


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


class DnsWhoisWorker(QThread):
    """Runs expanded DNS and IP ownership diagnostics in the background."""
    result_ready = pyqtSignal(str)
    error_ready = pyqtSignal(str)

    def __init__(self, query: str, record_type: str, include_ip_info=True):
        super().__init__()
        self.query = query
        self.record_type = record_type
        self.include_ip_info = include_ip_info

    def _is_ip(self):
        try:
            socket.inet_aton(self.query)
            return True
        except OSError:
            return False

    def _run_nslookup(self):
        cmd = ["nslookup", f"-type={self.record_type}", self.query]
        try:
            kwargs = {"capture_output": True, "text": True, "timeout": 20}
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"nslookup failed: {e}"

        output = (completed.stdout or completed.stderr or "").strip()
        return output or "No nslookup output."

    def _ip_info(self, ip):
        if not ip or ip == "N/A":
            return "N/A"
        try:
            with urllib.request.urlopen(f"https://ipwho.is/{ip}", timeout=5) as r:
                data = json.loads(r.read().decode())
        except Exception as e:
            return f"IP info lookup failed: {e}"

        connection = data.get("connection", {}) or {}
        lines = [
            f"IP: {data.get('ip', ip)}",
            f"ISP: {connection.get('isp') or connection.get('org') or 'N/A'}",
            f"ASN: {connection.get('asn') or 'N/A'}",
            f"Org: {connection.get('org') or 'N/A'}",
            f"Location: {', '.join(part for part in (data.get('city'), data.get('region'), data.get('country')) if part) or 'N/A'}",
            "Source: ipwho.is",
        ]
        return "\n".join(lines)

    def run(self):
        if not self.query:
            self.error_ready.emit("Enter a hostname or IP address.")
            return

        sections = [f"Query: {self.query}"]
        is_ip = self._is_ip()

        if is_ip:
            try:
                sections.append("Reverse DNS:\n" + socket.gethostbyaddr(self.query)[0])
            except socket.herror:
                sections.append("Reverse DNS:\nN/A")
            if self.include_ip_info:
                sections.append("IP / ASN / ISP:\n" + self._ip_info(self.query))
        else:
            try:
                _, aliases, ips = socket.gethostbyname_ex(self.query)
                forward_lines = [f"Aliases: {', '.join(aliases) if aliases else 'N/A'}", f"IPv4: {', '.join(ips) if ips else 'N/A'}"]
                try:
                    ipv6 = sorted({
                        item[4][0] for item in socket.getaddrinfo(self.query, None, socket.AF_INET6)
                    })
                    forward_lines.append(f"IPv6: {', '.join(ipv6) if ipv6 else 'N/A'}")
                except socket.gaierror:
                    forward_lines.append("IPv6: N/A")
                sections.append("Forward DNS:\n" + "\n".join(forward_lines))
                if self.include_ip_info and ips:
                    sections.append("Primary IP / ASN / ISP:\n" + self._ip_info(ips[0]))
            except socket.gaierror:
                sections.append("Forward DNS:\nN/A")

            sections.append(f"{self.record_type} Records:\n" + self._run_nslookup())

        self.result_ready.emit("\n\n".join(sections))


class PortCheckWorker(QThread):
    """Checks TCP connectivity for one or more ports without blocking the UI."""
    result_ready = pyqtSignal(dict)
    progress_ready = pyqtSignal(int, int)

    def __init__(self, host: str, ports: list, timeout_ms=3000):
        super().__init__()
        self.host = host
        self.ports = ports
        self.timeout_ms = timeout_ms

    def run(self):
        timeout_seconds = max(0.1, self.timeout_ms / 1000)
        for index, port in enumerate(self.ports, start=1):
            started = time.perf_counter()
            status = "Closed"
            error = ""
            latency = None
            try:
                with socket.create_connection((self.host, port), timeout=timeout_seconds):
                    latency = (time.perf_counter() - started) * 1000
                    status = "Open"
            except socket.timeout:
                error = "Timed out"
            except OSError as e:
                error = str(e)

            self.result_ready.emit({
                "host": self.host,
                "port": port,
                "service": service_name(port),
                "status": status,
                "latency": latency,
                "error": error,
            })
            self.progress_ready.emit(index, len(self.ports))


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

    def __init__(self, executable: str, server_id=None, duration=15, share=False):
        super().__init__()
        self.executable = executable
        self.server_id = server_id
        self.duration = duration
        self.share = share

    def run(self):
        cmd = [
            self.executable,
            "--json",
            "--no-icmp",
            "--duration", str(self.duration),
        ]
        if not self.share:
            cmd.extend(["--telemetry-level", "disabled"])
        if self.server_id:
            cmd.extend(["--server", str(self.server_id)])
        if self.share:
            cmd.append("--share")
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

        try:
            parsed = json.loads(completed.stdout.strip())
        except json.JSONDecodeError as e:
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
            except json.JSONDecodeError:
                self.error_ready.emit(f"Could not parse LibreSpeed JSON: {e}")
                return

        if parsed is None:
            self.error_ready.emit("LibreSpeed returned no result for the selected server. Try Auto or another server.")
            return

        if isinstance(parsed, list):
            if not parsed:
                self.error_ready.emit("LibreSpeed CLI returned an empty result list.")
                return
            parsed = parsed[0]

        if parsed is None:
            self.error_ready.emit("LibreSpeed returned no result for the selected server. Try Auto or another server.")
            return

        if not isinstance(parsed, dict):
            self.error_ready.emit("LibreSpeed CLI returned an unsupported JSON shape.")
            return

        self.result_ready.emit(parsed)


class SpeedTestServerListWorker(QThread):
    """Fetches the LibreSpeed public server list in the background."""
    servers_ready = pyqtSignal(list)
    error_ready = pyqtSignal(str)

    def __init__(self, executable: str):
        super().__init__()
        self.executable = executable

    def run(self):
        cmd = [self.executable, "--list"]
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 60,
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except FileNotFoundError:
            self.error_ready.emit("LibreSpeed CLI executable was not found.")
            return
        except subprocess.TimeoutExpired:
            self.error_ready.emit("LibreSpeed server list timed out after 60 seconds.")
            return
        except OSError as e:
            self.error_ready.emit(f"Could not list LibreSpeed servers: {e}")
            return

        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "LibreSpeed server list failed.").strip()
            self.error_ready.emit(message)
            return

        servers = []
        pattern = re.compile(r"^(\d+):\s+(.+)\s+\((https?://[^)]+)\)\s+\[Sponsor:\s+(.+?)\s+@\s+(.+?)\]$")
        for line in completed.stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            servers.append({
                "id": match.group(1),
                "name": match.group(2),
                "url": match.group(3),
                "sponsor": match.group(4),
                "sponsor_url": match.group(5),
            })

        if not servers:
            self.error_ready.emit("LibreSpeed CLI returned no parseable servers.")
            return

        self.servers_ready.emit(servers)


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
        self.dns_whois_worker = None
        self.start_worker = None
        self.tr_worker = None
        self.port_check_worker = None
        self.speedtest_worker = None
        self.speedtest_server_worker = None
        self.speedtest_progress_timer = None
        self.speedtest_progress_elapsed_ms = 0
        self.speedtest_progress_total_ms = 0
        self.speedtest_history_loaded = False

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
        self.dns_record_combo = None
        self.dns_ip_info_check = None
        self.dns_window = None
        self.dns_tool_btn = QPushButton("DNS / WHOIS")
        self.dns_tool_btn.setFixedSize(135, 30)
        self.dns_tool_btn.setToolTip("Open DNS, record, and IP ownership lookup")
        self.dns_tool_btn.clicked.connect(self.show_dns_window)
        self.port_window = None
        self.port_host_input = None
        self.port_ports_combo = None
        self.port_timeout_spin = None
        self.port_run_btn = None
        self.port_status_label = None
        self.port_table = None
        self.port_open_only_check = None
        self.port_progress_bar = None
        self.port_scan_result_count = 0
        self.port_scan_open_count = 0
        self.port_tool_btn = QPushButton("Port Scanner")
        self.port_tool_btn.setFixedSize(135, 30)
        self.port_tool_btn.setToolTip("Open TCP port connectivity checks")
        self.port_tool_btn.clicked.connect(self.show_port_check_window)

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
        self.trace_window = None
        self.trace_tool_btn = QPushButton("Traceroute")
        self.trace_tool_btn.setFixedSize(135, 30)
        self.trace_tool_btn.setToolTip("Open traceroute diagnostics")
        self.trace_tool_btn.clicked.connect(self.show_traceroute_window)
        self.trace_input = None
        self.trace_max_hops_spin = None
        self.trace_timeout_spin = None
        self.trace_raw_box = None
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
        self.speedtest_refresh_servers_btn = None
        self.speedtest_server_combo = None
        self.speedtest_duration_spin = None
        self.speedtest_share_check = None
        self.speedtest_progress_bar = None
        self.speedtest_history_table = None
        self.speedtest_btn = QPushButton("Speed Test")
        self.speedtest_btn.setFixedSize(135, 30)
        self.speedtest_btn.setToolTip("Open internet speed test")
        self.speedtest_btn.clicked.connect(self.show_speedtest_window)

        # §3.A.k Host-info fields
        self.hostname_label  = QLabel("Loading...")
        self.host_ip_label   = QLabel("Loading...")
        self.gateway_label   = QLabel("Loading...")
        self.public_ip_label = QLabel("Loading...")
        self.public_isp_label = QLabel("Loading...")
        self.host_mac_label = QLabel("Loading...")

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

        ping_h.addWidget(target_group)
        ping_h.addWidget(live_group)
        ping_h.addStretch(1)
        ping_h.addWidget(elapsed_group)
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
        host_info_group.setMinimumSize(260,120)
        hi = QGridLayout(); hi.setContentsMargins(8,8,8,8)
        hi.setHorizontalSpacing(8); hi.setVerticalSpacing(4)
        host_info_rows = [
            ("Host:", self.hostname_label),
            ("Local IP:", self.host_ip_label),
            ("Gateway:", self.gateway_label),
            ("Public IP:", self.public_ip_label),
            ("ISP:", self.public_isp_label),
            ("MAC:", self.host_mac_label),
        ]
        for row, (label_text, value_label) in enumerate(host_info_rows):
            value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value_label.setWordWrap(False)
            hi.addWidget(QLabel(label_text), row, 0)
            hi.addWidget(value_label, row, 1)
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
        tools_group = QGroupBox("Tools")
        tools_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        tools_group.setFixedWidth(360)
        tools_layout = QVBoxLayout()
        tools_layout.setContentsMargins(8,8,8,8)
        tools_layout.setSpacing(10)
        tools_layout.addWidget(self.speedtest_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.port_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.dns_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.trace_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.alerts_btn, 0, Qt.AlignCenter)
        tools_group.setLayout(tools_layout)
        right.addWidget(tools_group)

        right.addStretch(1)

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

    def _set_host_info(self, info: dict):
        values = {
            self.hostname_label: info.get("hostname", "N/A"),
            self.host_ip_label: info.get("local_ip", "N/A"),
            self.gateway_label: info.get("gateway", "N/A"),
            self.public_ip_label: info.get("public_ip", "N/A"),
            self.public_isp_label: info.get("isp", "N/A"),
            self.host_mac_label: info.get("mac", "N/A"),
        }
        for label, value in values.items():
            display = str(value or "N/A")
            label.setText(display)
            label.setToolTip(display)

        details = []
        if info.get("asn") not in (None, "", "N/A"):
            details.append(f"ASN: {info['asn']}")
        if info.get("location") not in (None, "", "N/A"):
            details.append(f"Location: {info['location']}")
        if info.get("source") not in (None, "", "N/A"):
            details.append(f"Source: {info['source']}")
        if details:
            self.public_isp_label.setToolTip("\n".join([self.public_isp_label.text(), *details]))

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

    def show_port_check_window(self):
        """Open the TCP Port Check diagnostic window."""
        if self.port_window is None:
            self.port_window = QWidget(None, Qt.Window)
            self.port_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.port_window.setWindowTitle("Port Scanner")
            self.port_window.setMinimumSize(760, 520)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.port_host_input = QLineEdit(self.host_input.text().strip())
            self.port_host_input.setMinimumWidth(300)
            self.port_ports_combo = QComboBox()
            self.port_ports_combo.setEditable(True)
            self.port_ports_combo.addItems([
                "Common web: 80,443,8080,8443",
                "Common remote: 22,23,3389,5900",
                "Common mail: 25,110,143,465,587,993,995",
                "Common network: 21,22,23,53,80,123,139,443,445,3389",
                "Top troubleshooting: 20-23,25,53,80,110,139,143,443,445,587,993,995,3389,5900,8080,8443",
                "443",
                "80",
                "1-1024",
            ])
            self.port_ports_combo.setMinimumWidth(300)
            self.port_timeout_spin = QSpinBox()
            self.port_timeout_spin.setRange(250, 30000)
            self.port_timeout_spin.setSingleStep(250)
            self.port_timeout_spin.setValue(3000)
            self.port_timeout_spin.setSuffix(" ms")
            self.port_run_btn = QPushButton("Run Scan")
            self.port_run_btn.clicked.connect(self.start_port_check)
            self.port_open_only_check = QCheckBox("Show open only")

            controls.addWidget(QLabel("Host"), 0, 0)
            controls.addWidget(self.port_host_input, 0, 1)
            controls.addWidget(QLabel("Port(s)"), 0, 2)
            controls.addWidget(self.port_ports_combo, 0, 3)
            controls.addWidget(QLabel("Timeout"), 1, 0)
            controls.addWidget(self.port_timeout_spin, 1, 1)
            controls.addWidget(self.port_open_only_check, 1, 2)
            controls.addWidget(self.port_run_btn, 1, 3)
            controls.setColumnStretch(1, 1)
            layout.addLayout(controls)

            self.port_status_label = QLabel("Ready")
            self.port_status_label.setAlignment(Qt.AlignCenter)
            self.port_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.port_status_label)

            self.port_progress_bar = QProgressBar()
            self.port_progress_bar.setRange(0, 100)
            self.port_progress_bar.setValue(0)
            self.port_progress_bar.setFormat("Ready")
            layout.addWidget(self.port_progress_bar)

            self.port_table = QTableWidget(0, 6)
            self.port_table.setHorizontalHeaderLabels(["Host", "Port", "Service", "Status", "Latency", "Error"])
            self.port_table.verticalHeader().setVisible(False)
            self.port_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.port_table.setSelectionBehavior(QTableWidget.SelectRows)
            ph = self.port_table.horizontalHeader()
            ph.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(3, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(4, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(5, QHeaderView.Stretch)
            layout.addWidget(self.port_table, 1)
            self.port_window.setLayout(layout)

        if self.port_host_input is not None and not self.port_host_input.text().strip():
            self.port_host_input.setText(self.host_input.text().strip())
        self.port_window.show()
        self.port_window.raise_()
        self.port_window.activateWindow()

    def _parse_port_list(self, text: str):
        if ":" in text:
            text = text.split(":", 1)[1]
        ports = []
        for part in re.split(r"[,;\s]+", text.strip()):
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))

        deduped = []
        for port in ports:
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}")
            if port not in deduped:
                deduped.append(port)
        if not deduped:
            raise ValueError("Enter at least one port.")
        return deduped[:1024]

    def start_port_check(self):
        """Run TCP connectivity checks in the Port Check window."""
        if self.port_check_worker is not None and self.port_check_worker.isRunning():
            return

        host = self.port_host_input.text().strip() if self.port_host_input is not None else self.host_input.text().strip()
        if not host:
            return

        try:
            ports = self._parse_port_list(self.port_ports_combo.currentText())
        except ValueError as e:
            QMessageBox.warning(self, "Port Check Error", str(e))
            return

        timeout_ms = self.port_timeout_spin.value() if self.port_timeout_spin is not None else 3000
        self.port_table.setRowCount(0)
        self.port_scan_result_count = 0
        self.port_scan_open_count = 0
        self.port_run_btn.setEnabled(False)
        if self.port_progress_bar is not None:
            self.port_progress_bar.setValue(0)
            self.port_progress_bar.setFormat("Scanning... 0%")
        self.port_status_label.setText(f"Scanning {len(ports)} TCP port(s) on {host}...")
        self.port_status_label.setStyleSheet(
            "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

        self.port_check_worker = PortCheckWorker(host, ports, timeout_ms=timeout_ms)
        self.port_check_worker.result_ready.connect(self._add_port_check_result)
        self.port_check_worker.progress_ready.connect(self._update_port_scan_progress)
        self.port_check_worker.finished.connect(self._finish_port_check)
        self.port_check_worker.finished.connect(self.port_check_worker.deleteLater)
        self.port_check_worker.finished.connect(lambda: setattr(self, "port_check_worker", None))
        self.port_check_worker.start()

    def _add_port_check_result(self, result: dict):
        if self.port_table is None:
            return
        self.port_scan_result_count += 1
        if result.get("status") == "Open":
            self.port_scan_open_count += 1
        if (
            self.port_open_only_check is not None
            and self.port_open_only_check.isChecked()
            and result.get("status") != "Open"
        ):
            return
        latency = "N/A" if result.get("latency") is None else f"{result['latency']:.1f} ms"
        row_values = [
            result.get("host", ""),
            str(result.get("port", "")),
            result.get("service", ""),
            result.get("status", ""),
            latency,
            result.get("error", ""),
        ]
        row = self.port_table.rowCount()
        self.port_table.insertRow(row)
        for col, value in enumerate(row_values):
            item = QTableWidgetItem(value)
            if col == 3:
                if value == "Open":
                    item.setBackground(QBrush(QColor("#e6f4ea")))
                else:
                    item.setBackground(QBrush(QColor("#fce8e6")))
            self.port_table.setItem(row, col, item)

    def _update_port_scan_progress(self, completed: int, total: int):
        if self.port_progress_bar is None:
            return
        pct = 100 if total <= 0 else int((completed / total) * 100)
        self.port_progress_bar.setValue(min(100, pct))
        self.port_progress_bar.setFormat(f"Scanned {completed}/{total} port(s)")

    def _finish_port_check(self):
        if self.port_run_btn is not None:
            self.port_run_btn.setEnabled(True)
        if self.port_status_label is not None:
            suffix = " (open-only view)" if self.port_open_only_check is not None and self.port_open_only_check.isChecked() else ""
            self.port_status_label.setText(
                f"Completed. {self.port_scan_open_count}/{self.port_scan_result_count} port(s) open{suffix}."
            )
            self.port_status_label.setStyleSheet(
                "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
        if self.port_progress_bar is not None:
            self.port_progress_bar.setValue(100)
            self.port_progress_bar.setFormat("Complete")

    def show_dns_window(self):
        """Open the DNS / WHOIS diagnostic window."""
        if self.dns_window is None:
            self.dns_window = QWidget(None, Qt.Window)
            self.dns_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.dns_window.setWindowTitle("DNS / WHOIS")
            self.dns_window.setMinimumSize(720, 520)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.dns_input.setMinimumWidth(360)
            if not self.dns_input.text().strip():
                self.dns_input.setText(self.host_input.text().strip())
            self.dns_btn.setText("Run Lookup")
            self.dns_btn.setMinimumHeight(30)
            self.dns_record_combo = QComboBox()
            self.dns_record_combo.addItems(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"])
            self.dns_ip_info_check = QCheckBox("Include IP / ASN / ISP")
            self.dns_ip_info_check.setChecked(True)

            controls.addWidget(QLabel("Query"), 0, 0)
            controls.addWidget(self.dns_input, 0, 1)
            controls.addWidget(QLabel("Record"), 0, 2)
            controls.addWidget(self.dns_record_combo, 0, 3)
            controls.addWidget(self.dns_btn, 0, 4)
            controls.addWidget(self.dns_ip_info_check, 1, 1, 1, 3)
            controls.setColumnStretch(1, 1)
            layout.addLayout(controls)

            self.dns_result_box.setMinimumHeight(390)
            self.dns_result_box.setPlaceholderText("DNS, record, and IP ownership results will appear here.")
            layout.addWidget(self.dns_result_box, 1)
            self.dns_window.setLayout(layout)

        self.dns_window.show()
        self.dns_window.raise_()
        self.dns_window.activateWindow()

    def show_traceroute_window(self):
        """Open the traceroute diagnostic window."""
        if self.trace_window is None:
            self.trace_window = QWidget(None, Qt.Window)
            self.trace_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.trace_window.setWindowTitle("Traceroute")
            self.trace_window.setMinimumSize(760, 560)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.trace_input = QLineEdit(self.host_input.text().strip())
            self.trace_input.setMinimumWidth(360)
            self.trace_max_hops_spin = QSpinBox()
            self.trace_max_hops_spin.setRange(1, 64)
            self.trace_max_hops_spin.setValue(30)
            self.trace_timeout_spin = QSpinBox()
            self.trace_timeout_spin.setRange(500, 10000)
            self.trace_timeout_spin.setSingleStep(500)
            self.trace_timeout_spin.setValue(4000)
            self.trace_timeout_spin.setSuffix(" ms")

            controls.addWidget(QLabel("Target"), 0, 0)
            controls.addWidget(self.trace_input, 0, 1)
            controls.addWidget(QLabel("Max hops"), 0, 2)
            controls.addWidget(self.trace_max_hops_spin, 0, 3)
            controls.addWidget(QLabel("Timeout"), 0, 4)
            controls.addWidget(self.trace_timeout_spin, 0, 5)
            controls.addWidget(self.tr_button, 0, 6)
            controls.setColumnStretch(1, 1)
            layout.addLayout(controls)

            layout.addWidget(self.trace_target_label)
            layout.addWidget(self.tr_table, 2)
            self.trace_raw_box = QTextEdit()
            self.trace_raw_box.setReadOnly(True)
            self.trace_raw_box.setMinimumHeight(120)
            self.trace_raw_box.setPlaceholderText("Raw traceroute output will appear here.")
            layout.addWidget(self.trace_raw_box, 1)
            self.trace_window.setLayout(layout)

        if self.trace_input is not None and not self.trace_input.text().strip():
            self.trace_input.setText(self.host_input.text().strip())
        self.trace_window.show()
        self.trace_window.raise_()
        self.trace_window.activateWindow()

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
            self.speedtest_window.setMinimumSize(560, 620)
            self.speedtest_window.resize(560, 620)

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

            options_group = QGroupBox("Options")
            options_grid = QGridLayout()
            options_grid.setContentsMargins(10,10,10,10)
            options_grid.setHorizontalSpacing(10)
            options_grid.setVerticalSpacing(8)

            self.speedtest_server_combo = QComboBox()
            self.speedtest_server_combo.addItem("Auto select nearest server", None)
            self.speedtest_server_combo.setMinimumWidth(360)
            self.speedtest_server_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)

            self.speedtest_refresh_servers_btn = QPushButton("Refresh Servers")
            self.speedtest_refresh_servers_btn.clicked.connect(self.refresh_speedtest_servers)

            self.speedtest_duration_spin = QSpinBox()
            self.speedtest_duration_spin.setRange(5, 60)
            self.speedtest_duration_spin.setValue(15)
            self.speedtest_duration_spin.setSuffix(" sec")

            self.speedtest_share_check = QCheckBox("Try share URL")
            self.speedtest_share_check.setToolTip("Disabled by default. Some LibreSpeed servers do not provide share URLs.")

            options_grid.addWidget(QLabel("Server"), 0, 0)
            options_grid.addWidget(self.speedtest_server_combo, 0, 1)
            options_grid.addWidget(self.speedtest_refresh_servers_btn, 0, 2)
            options_grid.addWidget(QLabel("Duration"), 1, 0)
            options_grid.addWidget(self.speedtest_duration_spin, 1, 1)
            options_grid.addWidget(self.speedtest_share_check, 1, 2)
            options_grid.setColumnStretch(1, 1)
            options_group.setLayout(options_grid)
            layout.addWidget(options_group)

            self.speedtest_run_btn = QPushButton("Run Speed Test")
            self.speedtest_run_btn.setMinimumHeight(34)
            self.speedtest_run_btn.clicked.connect(self.start_speed_test)
            layout.addWidget(self.speedtest_run_btn)

            self.speedtest_progress_bar = QProgressBar()
            self.speedtest_progress_bar.setRange(0, 100)
            self.speedtest_progress_bar.setValue(0)
            self.speedtest_progress_bar.setTextVisible(True)
            self.speedtest_progress_bar.setFormat("Ready")
            layout.addWidget(self.speedtest_progress_bar)

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
            ])
            add_result_section("Endpoint", [
                ("server", "Server"),
                ("server_url", "Server URL"),
                ("isp", "ISP"),
                ("result", "Result URL"),
            ])
            add_result_section("Details", [
                ("timestamp", "Test Time"),
                ("data_used", "Data Used"),
            ])

            history_group = QGroupBox("History")
            history_layout = QVBoxLayout()
            history_layout.setContentsMargins(10,10,10,10)
            self.speedtest_history_table = QTableWidget(0, 7)
            self.speedtest_history_table.setHorizontalHeaderLabels([
                "Time", "Down", "Up", "Latency", "Jitter", "Server", "Data"
            ])
            self.speedtest_history_table.verticalHeader().setVisible(False)
            self.speedtest_history_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.speedtest_history_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.speedtest_history_table.setMinimumHeight(150)
            self.speedtest_history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.speedtest_history_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
            history_layout.addWidget(self.speedtest_history_table)
            history_group.setLayout(history_layout)
            layout.addWidget(history_group)

            self.speedtest_window.setLayout(layout)
            self._load_speedtest_history()

        self.speedtest_window.layout().activate()
        self.speedtest_window.adjustSize()
        if self.speedtest_window.width() < 560 or self.speedtest_window.height() < 620:
            self.speedtest_window.resize(max(self.speedtest_window.width(), 560), max(self.speedtest_window.height(), 620))
        self.speedtest_window.show()
        self.speedtest_window.raise_()
        self.speedtest_window.activateWindow()
        if self.speedtest_server_combo is not None and self.speedtest_server_combo.count() == 1:
            QTimer.singleShot(0, self.refresh_speedtest_servers)

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

    def refresh_speedtest_servers(self):
        """Fetch the LibreSpeed server list for manual server selection."""
        if self.speedtest_server_worker is not None and self.speedtest_server_worker.isRunning():
            return

        executable = self._find_speedtest_executable()
        if not executable:
            self._set_speedtest_status(
                "LibreSpeed CLI not found. Put librespeed-cli.exe in tools/librespeed "
                "or install librespeed-cli so it is available on PATH."
            )
            return

        self._set_speedtest_status("Refreshing LibreSpeed server list...")
        if self.speedtest_refresh_servers_btn is not None:
            self.speedtest_refresh_servers_btn.setEnabled(False)
        self.speedtest_server_worker = SpeedTestServerListWorker(executable)
        self.speedtest_server_worker.servers_ready.connect(self._set_speedtest_servers)
        self.speedtest_server_worker.error_ready.connect(self._set_speedtest_error)
        self.speedtest_server_worker.finished.connect(self._finish_speedtest_server_refresh)
        self.speedtest_server_worker.finished.connect(self.speedtest_server_worker.deleteLater)
        self.speedtest_server_worker.finished.connect(lambda: setattr(self, "speedtest_server_worker", None))
        self.speedtest_server_worker.start()

    def _set_speedtest_servers(self, servers: list):
        if self.speedtest_server_combo is None:
            return

        current_id = self.speedtest_server_combo.currentData()
        self.speedtest_server_combo.blockSignals(True)
        self.speedtest_server_combo.clear()
        self.speedtest_server_combo.addItem("Auto select nearest server", None)
        selected_index = 0
        for server in servers:
            label = f"{server['id']} - {server['name']} ({server['sponsor']})"
            self.speedtest_server_combo.addItem(label, server["id"])
            if current_id and server["id"] == current_id:
                selected_index = self.speedtest_server_combo.count() - 1
        self.speedtest_server_combo.setCurrentIndex(selected_index)
        self.speedtest_server_combo.blockSignals(False)
        self._set_speedtest_status(f"Loaded {len(servers)} LibreSpeed servers.")

    def _finish_speedtest_server_refresh(self):
        if self.speedtest_refresh_servers_btn is not None:
            self.speedtest_refresh_servers_btn.setEnabled(True)

    def _set_speedtest_controls_enabled(self, enabled: bool):
        for widget in (
            self.speedtest_run_btn,
            self.speedtest_refresh_servers_btn,
            self.speedtest_server_combo,
            self.speedtest_duration_spin,
            self.speedtest_share_check,
        ):
            if widget is not None:
                widget.setEnabled(enabled)

    def _start_speedtest_progress(self, duration_seconds: int):
        self._stop_speedtest_progress(reset=False)
        self.speedtest_progress_elapsed_ms = 0
        # LibreSpeed's duration covers the transfer phase, not server selection,
        # ping/jitter probes, setup, and result parsing. Add a conservative
        # overhead so the progress bar tracks wall-clock runtime more closely.
        estimated_total_seconds = int(duration_seconds) + 25
        self.speedtest_progress_total_ms = max(1, estimated_total_seconds * 1000)
        if self.speedtest_progress_bar is not None:
            self.speedtest_progress_bar.setValue(0)
            self.speedtest_progress_bar.setFormat("Running... 0%")

        self.speedtest_progress_timer = QTimer(self)
        self.speedtest_progress_timer.setInterval(1000)
        self.speedtest_progress_timer.timeout.connect(self._update_speedtest_progress)
        self.speedtest_progress_timer.start()

    def _update_speedtest_progress(self):
        self.speedtest_progress_elapsed_ms += 1000
        pct = min(100, int((self.speedtest_progress_elapsed_ms / self.speedtest_progress_total_ms) * 100))
        if self.speedtest_progress_bar is not None:
            self.speedtest_progress_bar.setValue(pct)
            self.speedtest_progress_bar.setFormat("Running... %p%" if pct < 100 else "Finishing...")

    def _stop_speedtest_progress(self, reset: bool):
        if self.speedtest_progress_timer is not None:
            self.speedtest_progress_timer.stop()
            self.speedtest_progress_timer.deleteLater()
            self.speedtest_progress_timer = None

        if self.speedtest_progress_bar is not None:
            if reset:
                self.speedtest_progress_bar.setValue(0)
                self.speedtest_progress_bar.setFormat("Ready")
            else:
                self.speedtest_progress_bar.setValue(100)

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
        self._reset_speedtest_current_results()
        server_id = self.speedtest_server_combo.currentData() if self.speedtest_server_combo is not None else None
        duration = self.speedtest_duration_spin.value() if self.speedtest_duration_spin is not None else 15
        share = self.speedtest_share_check.isChecked() if self.speedtest_share_check is not None else False
        self._set_speedtest_controls_enabled(False)
        self._start_speedtest_progress(duration)
        self.speedtest_worker = SpeedTestWorker(executable, server_id=server_id, duration=duration, share=share)
        self.speedtest_worker.result_ready.connect(self._set_speedtest_result)
        self.speedtest_worker.error_ready.connect(self._set_speedtest_error)
        self.speedtest_worker.finished.connect(self._finish_speedtest)
        self.speedtest_worker.finished.connect(self.speedtest_worker.deleteLater)
        self.speedtest_worker.finished.connect(lambda: setattr(self, "speedtest_worker", None))
        self.speedtest_worker.start()

    def _reset_speedtest_current_results(self):
        for label in self.speedtest_labels.values():
            label.setText("N/A")

    def _set_speedtest_status(self, message: str):
        if self.speedtest_status_label is not None:
            self.speedtest_status_label.setText(message)
            if message.startswith("Speed test failed") or message.startswith("LibreSpeed CLI not found"):
                style = (
                    "QLabel { background: #fce8e6; color: #a50e0e; border: 1px solid #d28b82; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            elif message.startswith("Running") or message.startswith("Refreshing"):
                style = (
                    "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            elif message.startswith("Speed test completed") or message.startswith("Loaded"):
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

    def _format_bytes(self, value):
        if value is None:
            return "N/A"
        size = float(value)
        for unit in ("B", "KB", "MB", "GB"):
            if abs(size) < 1000 or unit == "GB":
                return f"{size:.2f} {unit}" if unit != "B" else f"{size:.0f} {unit}"
            size /= 1000

    def _format_timestamp(self, value):
        if not value:
            return "N/A"
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
        except ValueError:
            return str(value)

    def _speedtest_history_path(self):
        root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
        return os.path.join(root, "data", "speedtest_history.json")

    def _dict_get_any(self, data: dict, *keys):
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return data[key]
        return None

    def _host_info_isp(self):
        if self.public_isp_label is None:
            return None
        value = self.public_isp_label.text().strip()
        if value in ("", "Loading...", "N/A"):
            return None
        return value

    def _set_speedtest_result(self, data: dict):
        server = data.get("server", {}) or {}
        client = data.get("client", {}) or {}

        server_name = self._dict_get_any(server, "name", "Name") or "N/A"
        server_url = self._dict_get_any(server, "server", "url", "URL") or "N/A"
        bytes_received = self._format_bytes(data.get("bytes_received"))
        bytes_sent = self._format_bytes(data.get("bytes_sent"))
        isp = (
            self._dict_get_any(client, "isp", "ISP", "org", "Org")
            or self._dict_get_any(client, "ip", "IP")
            or self._host_info_isp()
            or "N/A"
        )

        values = {
            "download": self._format_mbps(data.get("download")),
            "upload": self._format_mbps(data.get("upload")),
            "latency": "N/A" if data.get("ping") is None else f"{float(data.get('ping')):.1f} ms",
            "jitter": "N/A" if data.get("jitter") is None else f"{float(data.get('jitter')):.1f} ms",
            "server": server_name,
            "server_url": server_url,
            "isp": isp,
            "result": data.get("share") or (
                "Unavailable from selected server" if self.speedtest_share_check is not None and self.speedtest_share_check.isChecked()
                else "N/A"
            ),
            "timestamp": self._format_timestamp(data.get("timestamp")),
            "data_used": f"Down {bytes_received} / Up {bytes_sent}",
        }

        for key, value in values.items():
            self.speedtest_labels[key].setText(value)
        self._add_speedtest_history(values)
        self._set_speedtest_status("Speed test completed.")

    def _add_speedtest_history(self, values: dict):
        if self.speedtest_history_table is None:
            return

        row_values = [
            values["timestamp"],
            values["download"],
            values["upload"],
            values["latency"],
            values["jitter"],
            values["server"],
            values["data_used"],
        ]
        self._insert_speedtest_history_row(row_values)
        self._save_speedtest_history()

    def _insert_speedtest_history_row(self, row_values):
        self.speedtest_history_table.insertRow(0)
        for col, value in enumerate(row_values):
            self.speedtest_history_table.setItem(0, col, QTableWidgetItem(value))

        while self.speedtest_history_table.rowCount() > 10:
            self.speedtest_history_table.removeRow(self.speedtest_history_table.rowCount() - 1)

    def _speedtest_history_rows(self):
        if self.speedtest_history_table is None:
            return []
        rows = []
        for row in range(self.speedtest_history_table.rowCount()):
            values = []
            for col in range(self.speedtest_history_table.columnCount()):
                item = self.speedtest_history_table.item(row, col)
                values.append(item.text() if item is not None else "")
            rows.append(values)
        return rows

    def _load_speedtest_history(self):
        if self.speedtest_history_loaded or self.speedtest_history_table is None:
            return
        self.speedtest_history_loaded = True
        path = self._speedtest_history_path()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                rows = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return

        if not isinstance(rows, list):
            return
        for row_values in reversed(rows[:10]):
            if isinstance(row_values, list) and len(row_values) == self.speedtest_history_table.columnCount():
                self._insert_speedtest_history_row([str(value) for value in row_values])

    def _save_speedtest_history(self):
        path = self._speedtest_history_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self._speedtest_history_rows()[:10], handle, indent=2)
        except OSError:
            pass

    def _set_speedtest_error(self, message: str):
        self._stop_speedtest_progress(reset=True)
        self._set_speedtest_status(f"Speed test failed: {message}")

    def _finish_speedtest(self):
        failed = self.speedtest_status_label is not None and self.speedtest_status_label.text().startswith("Speed test failed")
        if not failed:
            self._stop_speedtest_progress(reset=False)
        if self.speedtest_progress_bar is not None:
            if self.speedtest_status_label is not None and self.speedtest_status_label.text().startswith("Speed test completed"):
                self.speedtest_progress_bar.setValue(100)
                self.speedtest_progress_bar.setFormat("Complete")
            elif failed:
                self.speedtest_progress_bar.setFormat("Failed")
            else:
                self.speedtest_progress_bar.setFormat("Stopped")
        self._set_speedtest_controls_enabled(True)

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
        """Run expanded DNS/IP ownership lookup."""
        hostname = self.dns_input.text().strip()
        if not hostname:
            return
        if self.dns_whois_worker is not None and self.dns_whois_worker.isRunning():
            return

        self.dns_btn.setEnabled(False)
        self.dns_result_box.setPlainText("Running lookup...")
        record_type = self.dns_record_combo.currentText() if self.dns_record_combo is not None else "A"
        include_ip_info = self.dns_ip_info_check.isChecked() if self.dns_ip_info_check is not None else True
        self.dns_whois_worker = DnsWhoisWorker(hostname, record_type, include_ip_info)
        self.dns_whois_worker.result_ready.connect(self._set_dns_result)
        self.dns_whois_worker.error_ready.connect(self._show_dns_error)
        self.dns_whois_worker.finished.connect(lambda: self.dns_btn.setEnabled(True))
        self.dns_whois_worker.finished.connect(self.dns_whois_worker.deleteLater)
        self.dns_whois_worker.finished.connect(lambda: setattr(self, "dns_whois_worker", None))
        self.dns_whois_worker.start()

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
        host = self.trace_input.text().strip() if self.trace_input is not None else self.host_input.text().strip()
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
        if self.trace_raw_box is not None:
            self.trace_raw_box.clear()
            self.trace_raw_box.append(f"Running traceroute to {host}...")
        max_hops = self.trace_max_hops_spin.value() if self.trace_max_hops_spin is not None else 30
        timeout_ms = self.trace_timeout_spin.value() if self.trace_timeout_spin is not None else 4000
        self.tr_worker = TracerouteWorker(host, max_hops=max_hops, timeout_ms=timeout_ms)
        self.tr_worker.line_ready.connect(self.handle_trace_line)
        self.tr_worker.finished.connect(lambda: self.tr_button.setEnabled(True))
        self.tr_worker.finished.connect(self.tr_worker.deleteLater)
        self.tr_worker.finished.connect(lambda: setattr(self, "tr_worker", None))
        self.tr_worker.start()

    def handle_trace_line(self, line: str):
        """§3.D.i Append each traceroute hop to table."""
        if self.trace_raw_box is not None:
            self.trace_raw_box.append(line)
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
