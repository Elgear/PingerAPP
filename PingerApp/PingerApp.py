# PingerApp.py

# §1 ─────────────────────────────────────────────────────────────────────────────
# Imports
import sys
import socket
import subprocess
import platform
import re
import urllib.request
import urllib.error
import urllib.parse
import ping3
import math
import json
import os
import shutil
import time
import uuid
import errno
import ipaddress
import concurrent.futures
import ssl
import textwrap

from collections import deque
from datetime import datetime
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt, QPointF, QRectF, QSize
from PyQt5.QtGui import QPainter, QPen, QFont, QColor, QBrush
from PyQt5.QtWidgets import (
    QApplication, QWidget,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QFileDialog, QGroupBox, QSlider, QTextEdit,
    QSizePolicy, QGridLayout, QComboBox, QCheckBox, QSpinBox, QProgressBar,
    QTreeWidget, QTreeWidgetItem, QToolButton, QToolTip
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

def clean_probe_text(value, max_len=220):
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+", " ", value or "")
    value = re.sub(r"\s+", " ", value).strip()
    return value[:max_len]

def wrapped_detail_text(value, width=70):
    value = (value or "").strip()
    if not value:
        return ""
    value = re.sub(r"\s+\|\s+", "\n", value)
    lines = []
    for line in value.splitlines():
        line = line.strip()
        if not line:
            continue
        lines.extend(textwrap.wrap(line, width=width, break_long_words=False, break_on_hyphens=False) or [""])
    return "\n".join(lines)

def first_host_in_range(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "N/A"
    if ip.version != 4:
        return "N/A"
    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(next(network.hosts()))

def common_name_from_cert_name(name):
    for item in name or ():
        for key, value in item:
            if key == "commonName":
                return value
    return "N/A"

def get_tls_summary(url, timeout=5, verify=True):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return "N/A"

    port = parsed.port or 443
    try:
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        with socket.create_connection((parsed.hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                version = tls_sock.version() or "TLS"
    except Exception:
        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((parsed.hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    version = tls_sock.version() or "TLS"
        except Exception as e:
            return f"TLS lookup failed: {e}"

    subject = common_name_from_cert_name(cert.get("subject"))
    issuer = common_name_from_cert_name(cert.get("issuer"))
    expires = cert.get("notAfter", "N/A")
    trust = "verified" if verify else "not verified"
    return f"{version} ({trust}); Subject: {subject}; Issuer: {issuer}; Expires: {expires}"

def get_arp_mac(ip):
    if platform.system() != "Windows":
        return "N/A"
    try:
        kwargs = {"text": True, "timeout": 1.5}
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        out = subprocess.check_output(["arp", "-a", str(ip)], **kwargs)
    except Exception:
        return "N/A"

    pattern = re.compile(rf"\b{re.escape(str(ip))}\b\s+([0-9a-fA-F-]{{17}})")
    match = pattern.search(out)
    return match.group(1).replace("-", ":").upper() if match else "N/A"

def get_windows_netbios_info(ip):
    """Return NetBIOS hostname/MAC when the Windows target exposes it."""
    if platform.system() != "Windows":
        return {"hostname": "N/A", "mac": "N/A"}
    try:
        kwargs = {"capture_output": True, "text": True, "timeout": 1.5}
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        completed = subprocess.run(["nbtstat", "-A", str(ip)], **kwargs)
    except Exception:
        return {"hostname": "N/A", "mac": "N/A"}

    output = (completed.stdout or completed.stderr or "")
    hostname = "N/A"
    for line in output.splitlines():
        if "<00>" in line and "UNIQUE" in line.upper():
            candidate = line.split("<00>", 1)[0].strip()
            if candidate and candidate.upper() not in {"WORKGROUP", "MSHOME"}:
                hostname = candidate
                break

    mac = "N/A"
    match = re.search(r"MAC Address\s*=\s*([0-9A-Fa-f:-]{17})", output)
    if match:
        mac = match.group(1).replace("-", ":").upper()
    return {"hostname": hostname, "mac": mac}

def classify_connect_error(code):
    refused_codes = {
        errno.ECONNREFUSED,
        getattr(errno, "WSAECONNREFUSED", 10061),
        10061,
    }
    timeout_codes = {
        errno.ETIMEDOUT,
        getattr(errno, "WSAETIMEDOUT", 10060),
        10060,
    }
    unreachable_codes = {
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        getattr(errno, "WSAENETUNREACH", 10051),
        getattr(errno, "WSAEHOSTUNREACH", 10065),
        10051,
        10065,
    }
    if code in refused_codes:
        return "Closed", "Connection refused"
    if code in timeout_codes:
        return "Filtered", "Timed out / dropped"
    if code in unreachable_codes:
        return "Unreachable", "Network or host unreachable"
    return "Error", os.strerror(code) if code else "Unknown socket error"

def probe_open_service(host, port, timeout_seconds):
    """Best-effort, light service probe for already-open TCP ports."""
    timeout_seconds = max(0.3, min(timeout_seconds, 3.0))
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            if port in {443, 8443, 9443, 465, 993, 995}:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    if port in {443, 8443, 9443}:
                        tls_sock.sendall(
                            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", "ignore")
                        )
                        data = tls_sock.recv(2048).decode("utf-8", "replace")
                        lines = [line.strip() for line in data.splitlines() if line.strip()]
                        details = lines[:1]
                        details.extend(line for line in lines if line.lower().startswith("server:"))
                        return clean_probe_text(" | ".join(details)) or "TLS service responded"
                    return "TLS handshake succeeded"

            if port in {80, 8000, 8080, 8081, 8888}:
                sock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", "ignore")
                )
                data = sock.recv(2048).decode("utf-8", "replace")
                lines = [line.strip() for line in data.splitlines() if line.strip()]
                details = lines[:1]
                details.extend(line for line in lines if line.lower().startswith("server:"))
                return clean_probe_text(" | ".join(details)) or "HTTP service responded"

            try:
                data = sock.recv(1024)
                if data:
                    return clean_probe_text(data.decode("utf-8", "replace"))
            except socket.timeout:
                pass
            return "Open; no banner"
    except Exception as e:
        return f"Probe failed: {clean_probe_text(str(e), 160)}"

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

def parse_link_speed_mbps(value):
    text = str(value or "").strip().lower().replace(",", "")
    if not text or text == "n/a":
        return None
    match = re.search(r"(\d+(?:\.\d+)?)\s*([kmgt]?bps)", text)
    if not match:
        if text.isdigit():
            number = float(text)
            return number / 1_000_000 if number > 100000 else number
        return None
    number = float(match.group(1))
    unit = match.group(2)
    multipliers = {
        "kbps": 0.001,
        "mbps": 1,
        "gbps": 1000,
        "tbps": 1000000,
        "bps": 0.000001,
    }
    return number * multipliers.get(unit, 1)

def adapter_link_diagnosis(link_speed, connection_type="", status=""):
    status_text = str(status or "").strip()
    if status_text and status_text.lower() != "up":
        return f"Adapter status is {status_text}. The connection may not be usable until the adapter is up."

    speed_mbps = parse_link_speed_mbps(link_speed)
    type_text = str(connection_type or "")
    is_wifi = "wireless" in type_text.lower() or "wi-fi" in type_text.lower() or "wifi" in type_text.lower()

    if speed_mbps is None:
        return "Link speed is unavailable. Check adapter driver details, Windows adapter status, cable, dock, switch, or router port."
    if speed_mbps < 100:
        return f"Link is {link_speed}. This is below Fast Ethernet and will severely cap throughput."
    if speed_mbps < 1000:
        return (
            f"Link is {link_speed}. This can cap speed tests below gigabit. "
            "Check Ethernet cable pairs, wall socket, switch/router port speed, dock/USB adapter, and NIC auto-negotiation."
        )
    if is_wifi:
        return (
            f"Wi-Fi link rate is {link_speed}. Real speed tests are usually lower than link rate; "
            "check band, signal, channel width, interference, and access point capability."
        )
    return (
        f"Link is {link_speed}. Local adapter negotiation looks gigabit or faster. "
        "If internet speed is around 100 Mbps, check router WAN/LAN ports, ISP profile, speed test server choice, or congestion."
    )

def format_bits_per_second(value):
    if value is None:
        return "N/A"
    mbps = float(value) / 1_000_000
    if mbps >= 1000:
        return f"{mbps / 1000:.2f} Gbps"
    return f"{mbps:.2f} Mbps"

def format_mbps(value):
    if value is None:
        return "N/A"
    return f"{float(value):.2f} Mbps"

def format_bytes_decimal(value):
    if value is None:
        return "N/A"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1000 or unit == "TB":
            return f"{size:.2f} {unit}" if unit != "B" else f"{size:.0f} {unit}"
        size /= 1000

def format_count(value):
    if value is None:
        return "N/A"
    return f"{int(float(value)):,}"

def format_packet_rate(value):
    if value is None:
        return "N/A"
    return f"{float(value):.1f} packets/s"

def format_interface_traffic(bytes_value=None, packets_value=None, bytes_rate=None, packets_rate=None):
    if bytes_value is not None or packets_value is not None:
        return f"{format_bytes_decimal(bytes_value)}; {format_count(packets_value)} packets"
    if bytes_rate is not None or packets_rate is not None:
        return f"{format_bytes_decimal(bytes_rate)}/s; {format_packet_rate(packets_rate)}"
    return "N/A"

def numeric_counter(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def counter_delta(before, after, key):
    start = numeric_counter((before or {}).get(key))
    end = numeric_counter((after or {}).get(key))
    if start is None or end is None:
        return None
    delta = end - start
    if delta < 0:
        return None
    return delta

def format_count_delta(value):
    if value is None:
        return "N/A"
    return f"+{int(float(value)):,}"

def format_interface_delta(bytes_delta=None, packets_delta=None):
    if bytes_delta is None and packets_delta is None:
        return "N/A"
    return f"{format_bytes_decimal(bytes_delta)}; {format_count_delta(packets_delta)} packets"

def adapter_counter_watch_diagnosis(result):
    source = str(result.get("counter_source") or "N/A")
    if source.startswith("Unavailable"):
        return (
            f"Counter Watch could not read interface counters ({source}). Try running the app as Administrator if "
            "Windows blocks adapter statistics."
        )

    error_delta = sum(value or 0 for value in (
        result.get("rx_errors_delta"),
        result.get("tx_errors_delta"),
        result.get("rx_discards_delta"),
        result.get("tx_discards_delta"),
    ))
    transfer_delta = sum(value or 0 for value in (
        result.get("rx_bytes_delta"),
        result.get("tx_bytes_delta"),
    ))

    if error_delta > 0:
        return (
            "Counter Watch saw errors or discards increase during the test. That is suspicious while traffic is being "
            "generated and can point to cable, switch/router port, NIC, driver, Wi-Fi, or congestion problems."
        )
    if transfer_delta > 0:
        return (
            "Counter Watch saw traffic move without interface errors or discards increasing. That is a healthy result "
            "for the adapter during this test window."
        )
    if result.get("rx_bytes_delta") is None and result.get("tx_bytes_delta") is None:
        return (
            "Counter Watch could read error/discard counters, but traffic byte totals were unavailable from Windows. "
            "Use the error/discard deltas as the main signal."
        )
    return (
        "Counter Watch did not see traffic or counter errors change. Run it while a Speed Test or LAN Throughput test "
        "is active to stress the adapter path."
    )

def interface_counter_diagnosis(info):
    source = str(info.get("counter_source") or "N/A")
    if source.startswith("Unavailable"):
        return (
            f"Interface counters are unavailable ({source}). Try running the app as Administrator if Windows blocks "
            "adapter statistics on this PC."
        )

    raw_values = {
        "receive errors": info.get("rx_errors_raw"),
        "transmit errors": info.get("tx_errors_raw"),
        "receive discards": info.get("rx_discards_raw"),
        "transmit discards": info.get("tx_discards_raw"),
    }
    alerts = []
    for label, value in raw_values.items():
        try:
            numeric = int(float(value))
        except (TypeError, ValueError):
            continue
        if numeric > 0:
            alerts.append(f"{label}: {numeric:,}")

    source_note = ""
    if "performance counters" in source.lower():
        source_note = " Traffic is shown as a current rate because per-adapter totals need elevated Windows access."

    if alerts:
        return (
            "Interface counters show non-zero " + ", ".join(alerts) + ". "
            "Receive errors/discards can point to cable, port, adapter, driver, or congestion problems; compare these "
            "after a refresh or during a speed test to see whether they are increasing." + source_note
        )
    return "Interface error and discard counters look clean for the selected adapter." + source_note

def lan_throughput_diagnosis(bits_per_second):
    if bits_per_second is None:
        return "No throughput result was available. Check that iperf3 ran successfully and the server was reachable."
    mbps = float(bits_per_second) / 1_000_000
    if mbps < 150:
        return (
            f"LAN throughput is {mbps:.1f} Mbps. This is consistent with a 100 Mbps local bottleneck. "
            "Check Ethernet cable pairs, wall sockets, switch/router port speed, dock/USB adapter, and adapter negotiation."
        )
    if mbps < 500:
        return (
            f"LAN throughput is {mbps:.1f} Mbps. This is above 100 Mbps but below typical gigabit LAN performance. "
            "Check Wi-Fi conditions, CPU load, powerline adapters, older switches, and parallel traffic."
        )
    if mbps < 800:
        return (
            f"LAN throughput is {mbps:.1f} Mbps. Local LAN is faster than Fast Ethernet but below a healthy wired gigabit result. "
            "If this is Wi-Fi, it may be normal; if wired, check cabling, ports, and adapter settings."
        )
    return (
        f"LAN throughput is {mbps:.1f} Mbps. Local LAN path looks gigabit-class. "
        "If internet Speed Test is near 100 Mbps, focus on router WAN/LAN port speed, ISP profile, speed test server, or congestion."
    )


# §2 ─────────────────────────────────────────────────────────────────────────────
def gateway_stability_diagnosis(stats):
    sent = stats.get("sent", 0)
    if sent <= 0:
        return "No gateway samples have been collected yet."
    loss_pct = stats.get("loss_pct", 0.0)
    avg_ms = stats.get("avg_ms")
    max_ms = stats.get("max_ms")
    jitter_ms = stats.get("jitter_ms")
    spike_count = stats.get("spike_count", 0)
    spike_threshold = stats.get("spike_threshold_ms", 0)

    if loss_pct > 0:
        return (
            f"Gateway packet loss is {loss_pct:.1f}%. Loss to the first hop usually points to local Wi-Fi, cable, "
            "switch, router, adapter, or powerline issues before blaming the ISP path."
        )
    if spike_count:
        return (
            f"Gateway had {spike_count} latency spike(s) above {spike_threshold:.1f} ms. "
            "If this happens during downloads/uploads, the local router, Wi-Fi, or link may be saturating or struggling."
        )
    if max_ms is not None and max_ms >= 50:
        return (
            f"Gateway max latency reached {max_ms:.1f} ms. That is high for a local first hop; check Wi-Fi signal, "
            "router load, cabling, or local congestion."
        )
    if jitter_ms is not None and jitter_ms >= 10:
        return (
            f"Gateway jitter is {jitter_ms:.1f} ms. Local first-hop timing is inconsistent; check Wi-Fi quality, "
            "router load, or link saturation."
        )
    if avg_ms is not None:
        return (
            f"Gateway looks stable: average {avg_ms:.1f} ms, no packet loss. "
            "If internet tests are still poor, look beyond the local gateway: router WAN, ISP, route, or remote server."
        )
    return "Gateway did not return successful latency samples. It may block ping, be unreachable, or be dropping local traffic."

def route_health_diagnosis(result):
    paths = result.get("paths", {})

    def troubled(name):
        stats = paths.get(name, {})
        return stats.get("loss_pct", 0) > 0 or stats.get("spike_count", 0) > 0

    gateway_bad = troubled("gateway")
    isp_bad = troubled("isp")
    public_bad = troubled("public")
    gateway = paths.get("gateway", {})
    isp = paths.get("isp", {})
    public = paths.get("public", {})

    if gateway_bad:
        return (
            "Gateway path degraded during load. Because the first hop shows loss or spikes, start with local causes: "
            "Wi-Fi, Ethernet cable, switch/router LAN port, adapter, driver, or router CPU/queue pressure."
        )
    if isp_bad:
        return (
            "Gateway stayed cleaner than the ISP first hop, but the ISP hop degraded. That points beyond the local LAN: "
            "router WAN side, modem/ONT, ISP edge, or provider congestion."
        )
    if public_bad:
        return (
            "Gateway and ISP first hop looked cleaner than the public target. That points farther upstream: route, peering, "
            "remote network, or the selected public target."
        )
    if gateway.get("sent", 0) == 0 and isp.get("sent", 0) == 0 and public.get("sent", 0) == 0:
        return "No route health samples were collected."
    return (
        "Route health looked stable during the load window. If throughput was still poor, focus on link negotiation, "
        "router/WAN throughput, ISP profile, speed test server choice, or endpoint limits."
    )


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


class AdapterInfoWorker(QThread):
    """Fetch active adapter and link-speed details without blocking the UI."""
    info_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def run(self):
        if platform.system() != "Windows":
            self.info_ready.emit({
                "adapter": "N/A",
                "description": "N/A",
                "status": "N/A",
                "connection_type": "N/A",
                "link_speed": "N/A",
                "duplex": "N/A",
                "ipv4": get_local_ip(),
                "gateway": get_default_gateway(),
                "dns_servers": "N/A",
                "mac": get_primary_mac(),
                "interface_index": "N/A",
                "counter_source": "Unavailable on this operating system",
                "rx_traffic": "N/A",
                "tx_traffic": "N/A",
                "rx_errors": "N/A",
                "tx_errors": "N/A",
                "rx_discards": "N/A",
                "tx_discards": "N/A",
                "diagnosis": "Detailed adapter link speed checks are currently implemented for Windows.",
            })
            return

        try:
            info = self._windows_adapter_info()
        except Exception as e:
            self.error_ready.emit(f"Adapter info lookup failed: {e}")
            return

        self.info_ready.emit(info)

    def _windows_adapter_info(self):
        script = r"""
$ErrorActionPreference = "Stop"
function Get-ObjValue($obj, [string]$name) {
    if (-not $obj) { return $null }
    $prop = $obj.PSObject.Properties[$name]
    if ($prop) { return $prop.Value }
    return $null
}
function Sum-ObjValues($obj, [string[]]$names) {
    $total = 0
    $found = $false
    foreach ($name in $names) {
        $value = Get-ObjValue $obj $name
        if ($null -ne $value) {
            $total += [double]$value
            $found = $true
        }
    }
    if ($found) { return $total }
    return $null
}
function Normalize-Key([string]$value) {
    if (-not $value) { return "" }
    return (($value.ToLowerInvariant()) -replace "[^a-z0-9]", "")
}
function Get-PerfCounterMap([string]$adapterName, [string]$adapterDescription) {
    try {
        $counterPaths = @(
            "\Network Interface(*)\Bytes Received/sec",
            "\Network Interface(*)\Bytes Sent/sec",
            "\Network Interface(*)\Packets Received/sec",
            "\Network Interface(*)\Packets Sent/sec",
            "\Network Interface(*)\Packets Received Errors",
            "\Network Interface(*)\Packets Outbound Errors",
            "\Network Interface(*)\Packets Received Discarded",
            "\Network Interface(*)\Packets Outbound Discarded"
        )
        $samples = (Get-Counter $counterPaths -MaxSamples 1 -ErrorAction Stop).CounterSamples
    } catch {
        return $null
    }

    $groups = @{}
    foreach ($sample in $samples) {
        if ($sample.Path -notmatch "\\network interface\((?<instance>.+)\)\\(?<counter>[^\\]+)$") { continue }
        $instance = $Matches.instance
        $counter = $Matches.counter.ToLowerInvariant()
        $key = Normalize-Key $instance
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [ordered]@{
                Instance = $instance
                InstanceKey = $key
                Counters = @{}
            }
        }
        $groups[$key].Counters[$counter] = [double]$sample.CookedValue
    }

    $descriptionKey = Normalize-Key $adapterDescription
    $nameKey = Normalize-Key $adapterName
    $matches = @($groups.Values | Where-Object {
        $_.InstanceKey -eq $descriptionKey -or
        $_.InstanceKey -eq $nameKey -or
        ($descriptionKey -and ($_.InstanceKey.Contains($descriptionKey) -or $descriptionKey.Contains($_.InstanceKey))) -or
        ($nameKey -and ($_.InstanceKey.Contains($nameKey) -or $nameKey.Contains($_.InstanceKey)))
    })
    if ($matches.Count -gt 0) { return $matches[0].Counters }
    return $null
}
$configs = Get-NetIPConfiguration |
    Where-Object { $_.IPv4Address -and $_.NetAdapter -and $_.NetAdapter.Status -eq "Up" } |
    Sort-Object @{Expression={ if ($_.IPv4DefaultGateway) { 0 } else { 1 } }}, InterfaceMetric

$items = foreach ($cfg in $configs) {
    $adapter = Get-NetAdapter -InterfaceIndex $cfg.InterfaceIndex -ErrorAction SilentlyContinue
    if (-not $adapter) { continue }
    $dns = Get-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $duplex = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Speed.*Duplex|Duplex" } |
        Select-Object -First 1
    $stats = $null
    $statsError = $null
    try {
        $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction Stop
    } catch {
        $statsError = $_.Exception.Message
    }
    $perf = $null
    if (-not $stats) {
        $perf = Get-PerfCounterMap $adapter.Name $adapter.InterfaceDescription
    }
    $counterSource = "Unavailable"
    if ($stats) {
        $counterSource = "Get-NetAdapterStatistics"
    } elseif ($perf) {
        $counterSource = "Windows performance counters"
    } elseif ($statsError) {
        $counterSource = "Unavailable: $statsError"
    }

    [pscustomobject]@{
        Adapter = $adapter.Name
        Description = $adapter.InterfaceDescription
        Status = $adapter.Status
        ConnectionType = if ($adapter.PhysicalMediaType) { $adapter.PhysicalMediaType.ToString() } elseif ($adapter.MediaType) { $adapter.MediaType.ToString() } else { $null }
        LinkSpeed = $adapter.LinkSpeed
        Duplex = if ($duplex) { $duplex.DisplayValue } else { $null }
        IPv4 = ($cfg.IPv4Address | Select-Object -First 1 -ExpandProperty IPAddress)
        Gateway = ($cfg.IPv4DefaultGateway | Select-Object -First 1 -ExpandProperty NextHop)
        DnsServers = @($dns.ServerAddresses)
        Mac = $adapter.MacAddress
        InterfaceIndex = $cfg.InterfaceIndex
        HasGateway = [bool]$cfg.IPv4DefaultGateway
        CounterSource = $counterSource
        RxBytes = Get-ObjValue $stats "ReceivedBytes"
        TxBytes = Get-ObjValue $stats "SentBytes"
        RxPackets = Sum-ObjValues $stats @("ReceivedUnicastPackets", "ReceivedMulticastPackets", "ReceivedBroadcastPackets", "ReceivedPackets")
        TxPackets = Sum-ObjValues $stats @("SentUnicastPackets", "SentMulticastPackets", "SentBroadcastPackets", "SentPackets")
        RxBytesPerSec = if ($perf) { $perf["bytes received/sec"] } else { $null }
        TxBytesPerSec = if ($perf) { $perf["bytes sent/sec"] } else { $null }
        RxPacketsPerSec = if ($perf) { $perf["packets received/sec"] } else { $null }
        TxPacketsPerSec = if ($perf) { $perf["packets sent/sec"] } else { $null }
        RxErrors = if ($stats) { Get-ObjValue $stats "ReceivedPacketErrors" } elseif ($perf) { $perf["packets received errors"] } else { $null }
        TxErrors = if ($stats) { Get-ObjValue $stats "OutboundPacketErrors" } elseif ($perf) { $perf["packets outbound errors"] } else { $null }
        RxDiscards = if ($stats) { Get-ObjValue $stats "ReceivedDiscardedPackets" } elseif ($perf) { $perf["packets received discarded"] } else { $null }
        TxDiscards = if ($stats) { Get-ObjValue $stats "OutboundDiscardedPackets" } elseif ($perf) { $perf["packets outbound discarded"] } else { $null }
    }
}

$items | ConvertTo-Json -Depth 4 -Compress
"""
        kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": 10,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            **kwargs,
        )
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip()
            raise RuntimeError(message or "PowerShell returned no adapter data.")

        raw = (completed.stdout or "").strip()
        if not raw:
            raise RuntimeError("PowerShell returned no active adapter data.")
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list) or not parsed:
            raise RuntimeError("PowerShell returned no active adapter data.")

        selected = next((item for item in parsed if item.get("HasGateway")), parsed[0])
        dns_servers = selected.get("DnsServers")
        if isinstance(dns_servers, list):
            dns_text = ", ".join(str(value) for value in dns_servers if value)
        else:
            dns_text = str(dns_servers or "N/A")

        link_speed = str(selected.get("LinkSpeed") or "N/A")
        connection_type = str(selected.get("ConnectionType") or "N/A")
        info = {
            "adapter": str(selected.get("Adapter") or "N/A"),
            "description": str(selected.get("Description") or "N/A"),
            "status": str(selected.get("Status") or "N/A"),
            "connection_type": connection_type,
            "link_speed": link_speed,
            "duplex": str(selected.get("Duplex") or "N/A"),
            "ipv4": str(selected.get("IPv4") or "N/A"),
            "gateway": str(selected.get("Gateway") or "N/A"),
            "dns_servers": dns_text or "N/A",
            "mac": str(selected.get("Mac") or "N/A"),
            "interface_index": str(selected.get("InterfaceIndex") or "N/A"),
            "counter_source": str(selected.get("CounterSource") or "Unavailable"),
            "rx_traffic": format_interface_traffic(
                selected.get("RxBytes"),
                selected.get("RxPackets"),
                selected.get("RxBytesPerSec"),
                selected.get("RxPacketsPerSec"),
            ),
            "tx_traffic": format_interface_traffic(
                selected.get("TxBytes"),
                selected.get("TxPackets"),
                selected.get("TxBytesPerSec"),
                selected.get("TxPacketsPerSec"),
            ),
            "rx_errors": format_count(selected.get("RxErrors")),
            "tx_errors": format_count(selected.get("TxErrors")),
            "rx_discards": format_count(selected.get("RxDiscards")),
            "tx_discards": format_count(selected.get("TxDiscards")),
            "rx_errors_raw": selected.get("RxErrors"),
            "tx_errors_raw": selected.get("TxErrors"),
            "rx_discards_raw": selected.get("RxDiscards"),
            "tx_discards_raw": selected.get("TxDiscards"),
            "rx_bytes_raw": selected.get("RxBytes"),
            "tx_bytes_raw": selected.get("TxBytes"),
            "rx_packets_raw": selected.get("RxPackets"),
            "tx_packets_raw": selected.get("TxPackets"),
            "rx_bytes_per_sec_raw": selected.get("RxBytesPerSec"),
            "tx_bytes_per_sec_raw": selected.get("TxBytesPerSec"),
            "rx_packets_per_sec_raw": selected.get("RxPacketsPerSec"),
            "tx_packets_per_sec_raw": selected.get("TxPacketsPerSec"),
        }
        info["diagnosis"] = (
            adapter_link_diagnosis(link_speed, connection_type, info["status"])
            + "\n\n"
            + interface_counter_diagnosis(info)
        )
        return info


class AdapterCounterWatchWorker(QThread):
    """Compares adapter counters before and after a short test window."""
    status_ready = pyqtSignal(str)
    result_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def __init__(self, duration_sec=30):
        super().__init__()
        self.duration_sec = max(1, int(duration_sec))
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        if platform.system() != "Windows":
            self.error_ready.emit("Counter Watch is currently implemented for Windows adapters only.")
            return

        reader = AdapterInfoWorker()
        try:
            self.status_ready.emit("Counter Watch baseline captured.")
            before = reader._windows_adapter_info()
            for remaining in range(self.duration_sec, 0, -1):
                if self._stop_requested:
                    self.status_ready.emit("Counter Watch stopped.")
                    return
                self.status_ready.emit(f"Counter Watch running... {remaining} sec remaining")
                self.msleep(1000)
            if self._stop_requested:
                self.status_ready.emit("Counter Watch stopped.")
                return
            after = reader._windows_adapter_info()
        except Exception as e:
            self.error_ready.emit(f"Counter Watch failed: {e}")
            return

        duration = float(self.duration_sec)
        result = {
            "adapter": after.get("adapter", before.get("adapter", "N/A")),
            "counter_source": after.get("counter_source", before.get("counter_source", "N/A")),
            "duration_sec": self.duration_sec,
            "rx_bytes_delta": counter_delta(before, after, "rx_bytes_raw"),
            "tx_bytes_delta": counter_delta(before, after, "tx_bytes_raw"),
            "rx_packets_delta": counter_delta(before, after, "rx_packets_raw"),
            "tx_packets_delta": counter_delta(before, after, "tx_packets_raw"),
            "rx_errors_delta": counter_delta(before, after, "rx_errors_raw"),
            "tx_errors_delta": counter_delta(before, after, "tx_errors_raw"),
            "rx_discards_delta": counter_delta(before, after, "rx_discards_raw"),
            "tx_discards_delta": counter_delta(before, after, "tx_discards_raw"),
            "end_info": after,
        }
        if result["rx_bytes_delta"] is not None:
            result["rx_avg_bps"] = (result["rx_bytes_delta"] * 8) / duration
        else:
            result["rx_avg_bps"] = None
        if result["tx_bytes_delta"] is not None:
            result["tx_avg_bps"] = (result["tx_bytes_delta"] * 8) / duration
        else:
            result["tx_avg_bps"] = None

        result["rx_transfer"] = format_interface_delta(result["rx_bytes_delta"], result["rx_packets_delta"])
        result["tx_transfer"] = format_interface_delta(result["tx_bytes_delta"], result["tx_packets_delta"])
        result["rx_rate"] = format_bits_per_second(result["rx_avg_bps"])
        result["tx_rate"] = format_bits_per_second(result["tx_avg_bps"])
        result["error_delta"] = (
            f"RX {format_count_delta(result['rx_errors_delta'])}; TX {format_count_delta(result['tx_errors_delta'])}"
        )
        result["discard_delta"] = (
            f"RX {format_count_delta(result['rx_discards_delta'])}; TX {format_count_delta(result['tx_discards_delta'])}"
        )
        result["diagnosis"] = adapter_counter_watch_diagnosis(result)
        self.result_ready.emit(result)


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


def summarize_nslookup_output(output: str):
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    if not lines:
        return "N/A"
    useful = []
    skip_prefixes = ("server:",)
    for line in lines:
        lower = line.lower()
        if any(lower.startswith(prefix) for prefix in skip_prefixes):
            continue
        if lower.startswith("address:") and not useful:
            continue
        useful.append(line)
    return "\n".join(useful[-20:]) if useful else "\n".join(lines[-20:])


class DnsCompareWorker(QThread):
    """Compares DNS answers from several resolvers using nslookup."""
    result_ready = pyqtSignal(dict)

    RESOLVERS = [
        ("System", None),
        ("Cloudflare", "1.1.1.1"),
        ("Google", "8.8.8.8"),
        ("Quad9", "9.9.9.9"),
    ]

    def __init__(self, query: str, record_type: str, timeout_ms=5000):
        super().__init__()
        self.query = query
        self.record_type = record_type
        self.timeout_ms = timeout_ms

    def run(self):
        timeout_seconds = max(1, self.timeout_ms / 1000)
        for name, resolver in self.RESOLVERS:
            cmd = ["nslookup", f"-type={self.record_type}", self.query]
            if resolver:
                cmd.append(resolver)
            started = time.perf_counter()
            answers = "N/A"
            error = ""
            try:
                kwargs = {"capture_output": True, "text": True, "timeout": timeout_seconds}
                if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                completed = subprocess.run(cmd, **kwargs)
                elapsed_ms = (time.perf_counter() - started) * 1000
                output = (completed.stdout or completed.stderr or "").strip()
                answers = summarize_nslookup_output(output)
                if completed.returncode != 0:
                    error = (completed.stderr or completed.stdout or f"nslookup exited {completed.returncode}").strip()
            except subprocess.TimeoutExpired:
                elapsed_ms = (time.perf_counter() - started) * 1000
                error = f"Timed out after {timeout_seconds:.1f}s"
            except OSError as e:
                elapsed_ms = (time.perf_counter() - started) * 1000
                error = str(e)

            self.result_ready.emit({
                "resolver": name,
                "server": resolver or "System default",
                "time_ms": elapsed_ms,
                "answers": answers,
                "error": error or "N/A",
            })


class MtuTestWorker(QThread):
    """Finds the largest non-fragmenting ICMP payload using system ping."""
    result_ready = pyqtSignal(dict)
    progress_ready = pyqtSignal(str)
    error_ready = pyqtSignal(str)

    def __init__(self, target: str, start_size=1200, max_size=1500, timeout_ms=3000):
        super().__init__()
        self.target = target
        self.start_size = start_size
        self.max_size = max_size
        self.timeout_ms = timeout_ms

    def _ping_payload(self, size):
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-f", "-l", str(size), "-w", str(self.timeout_ms), self.target]
        else:
            timeout_s = str(max(1, int(self.timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), "-W", timeout_s, self.target]

        try:
            kwargs = {"capture_output": True, "text": True, "timeout": max(2, int(self.timeout_ms / 1000) + 2)}
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except subprocess.TimeoutExpired as e:
            output = (e.stdout or e.stderr or "Timed out").strip()
            return False, output
        except OSError as e:
            return False, str(e)

        output = (completed.stdout or completed.stderr or "").strip()
        lower = output.lower()
        fragmented = any(
            marker in lower
            for marker in (
                "fragment",
                "packet needs to be fragmented",
                "message too long",
                "frag needed",
            )
        )
        timed_out = any(marker in lower for marker in ("request timed out", "100% loss", "destination host unreachable"))
        success = completed.returncode == 0 and not fragmented and not timed_out
        return success, output

    def run(self):
        if not self.target:
            self.error_ready.emit("Enter a target.")
            return
        if self.start_size < 0 or self.max_size < 0 or self.start_size > self.max_size:
            self.error_ready.emit("Enter a valid start/max payload range.")
            return

        low = self.start_size
        high = self.max_size
        best = None
        raw_sections = []

        while low <= high:
            size = (low + high) // 2
            self.progress_ready.emit(f"Testing payload {size} bytes...")
            success, output = self._ping_payload(size)
            raw_sections.append(f"Payload {size} bytes: {'OK' if success else 'FAILED'}\n{output}")
            if success:
                best = size
                low = size + 1
            else:
                high = size - 1

        if best is None:
            self.result_ready.emit({
                "target": self.target,
                "payload": "N/A",
                "mtu": "N/A",
                "status": "No payload in range succeeded",
                "raw": "\n\n".join(raw_sections),
            })
            return

        self.result_ready.emit({
            "target": self.target,
            "payload": best,
            "mtu": best + 28,
            "status": "Completed",
            "raw": "\n\n".join(raw_sections),
        })


class PortCheckWorker(QThread):
    """Runs safe TCP network discovery and port scanning without blocking the UI."""
    result_ready = pyqtSignal(dict)
    progress_ready = pyqtSignal(int, int)
    host_ready = pyqtSignal(dict)

    def __init__(self, host: str, targets: list, ports: list, timeout_ms=3000, detect_services=False, max_workers=64):
        super().__init__()
        self.host = host
        self.targets = targets
        self.ports = ports
        self.timeout_ms = timeout_ms
        self.detect_services = detect_services
        self.max_workers = max(1, min(int(max_workers), 256))
        self.discovery_ports = [80, 443, 22, 445, 3389]
        self._stop_requested = False
        self.was_stopped = False

    def request_stop(self):
        self._stop_requested = True

    def _shutdown_executor(self, executor, wait):
        try:
            executor.shutdown(wait=wait, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=wait)

    def _reverse_name(self, host):
        try:
            return socket.gethostbyaddr(str(host))[0]
        except (socket.herror, OSError):
            return "N/A"

    def _host_identity(self, host):
        reverse_name = self._reverse_name(host)
        arp_mac = get_arp_mac(host)
        netbios = {"hostname": "N/A", "mac": "N/A"}
        if reverse_name == "N/A" or arp_mac == "N/A":
            netbios = get_windows_netbios_info(host)
        hostname = first_available(reverse_name, netbios.get("hostname"))
        mac = first_available(arp_mac, netbios.get("mac"))
        return {"hostname": hostname, "mac": mac}

    def _tcp_probe(self, host, port, timeout_seconds, include_probe=False):
        started = time.perf_counter()
        latency = None
        detail = ""
        status = "Closed"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_seconds)
            code = sock.connect_ex((str(host), int(port)))
            latency = (time.perf_counter() - started) * 1000
            if code == 0:
                status = "Open"
                detail = probe_open_service(str(host), int(port), timeout_seconds) if include_probe else ""
            else:
                status, detail = classify_connect_error(code)
                if status in {"Filtered", "Unreachable"}:
                    latency = None
        except socket.timeout:
            status = "Filtered"
            detail = "Timed out / dropped"
            latency = None
        except OSError as e:
            status, detail = classify_connect_error(getattr(e, "errno", None))
            if not detail or detail == "Unknown socket error":
                detail = str(e)
            latency = None
        finally:
            sock.close()

        return {
            "host": str(host),
            "hostname": "N/A",
            "port": int(port),
            "service": service_name(port),
            "status": status,
            "latency": latency,
            "error": detail,
        }

    def _discover_host(self, host, timeout_seconds):
        host = str(host)
        reasons = []
        latency = None
        ping_latency = None
        try:
            ping_latency = ping3.ping(host, timeout=min(1, timeout_seconds), unit="ms")
        except Exception:
            ping_latency = None
        if ping_latency is not None:
            latency = ping_latency
            reasons.append("ICMP reply")

        open_or_refused = []
        for port in self.discovery_ports:
            result = self._tcp_probe(host, port, min(timeout_seconds, 1.0), include_probe=False)
            if result["status"] == "Open":
                open_or_refused.append(f"{port}/tcp open")
                if latency is None:
                    latency = result.get("latency")
                break
            if result["status"] == "Closed":
                open_or_refused.append(f"{port}/tcp refused")
                if latency is None:
                    latency = result.get("latency")
                break

        reasons.extend(open_or_refused)
        alive = bool(reasons)
        identity = self._host_identity(host) if alive else {"hostname": "N/A", "mac": "N/A"}
        return {
            "host": host,
            "hostname": identity["hostname"],
            "port": "",
            "service": "",
            "status": "Host Up" if alive else "No Response",
            "latency": latency,
            "error": ", ".join(reasons) if reasons else "No ICMP or TCP discovery response",
            "mac": identity["mac"],
            "alive": alive,
        }

    def run(self):
        timeout_seconds = max(0.1, self.timeout_ms / 1000)
        completed = 0
        total = len(self.ports) if len(self.targets) == 1 else len(self.targets)

        live_targets = list(self.targets)
        live_host_info = {}
        if len(self.targets) > 1:
            live_targets = []
            target_iter = iter(self.targets)
            pending = set()
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.targets)))
            try:
                def submit_discovery():
                    while not self._stop_requested and len(pending) < self.max_workers:
                        try:
                            target = next(target_iter)
                        except StopIteration:
                            break
                        pending.add(executor.submit(self._discover_host, target, timeout_seconds))

                submit_discovery()
                while pending and not self._stop_requested:
                    done, pending = concurrent.futures.wait(
                        pending,
                        timeout=0.2,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    for future in done:
                        result = future.result()
                        completed += 1
                        if result.get("alive"):
                            live_targets.append(result["host"])
                            live_host_info[result["host"]] = result
                            self.host_ready.emit(result)
                        self.progress_ready.emit(completed, total)
                    submit_discovery()
            finally:
                self.was_stopped = self._stop_requested
                self._shutdown_executor(executor, wait=True)
            if self._stop_requested:
                return
            total = completed + (len(live_targets) * len(self.ports))
            self.progress_ready.emit(completed, total)

        if not live_targets:
            return

        if len(live_targets) == 1 and not live_host_info:
            identity = self._host_identity(live_targets[0])
            live_host_info[live_targets[0]] = {
                "hostname": identity["hostname"],
                "mac": identity["mac"],
            }
        job_iter = ((target, port) for target in live_targets for port in self.ports)
        pending = set()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            def submit_scan_jobs():
                while not self._stop_requested and len(pending) < self.max_workers:
                    try:
                        target, port = next(job_iter)
                    except StopIteration:
                        break
                    pending.add(executor.submit(self._tcp_probe, target, port, timeout_seconds, self.detect_services))

            submit_scan_jobs()
            while pending and not self._stop_requested:
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=0.2,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    result = future.result()
                    identity = live_host_info.get(result["host"], {})
                    result["hostname"] = identity.get("hostname", "N/A")
                    result["mac"] = identity.get("mac", "N/A")
                    self.result_ready.emit(result)
                    completed += 1
                    self.progress_ready.emit(completed, total)
                submit_scan_jobs()
        finally:
            self.was_stopped = self._stop_requested
            self._shutdown_executor(executor, wait=True)


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


class LanThroughputWorker(QThread):
    """Runs an iperf3 client throughput test in the background."""
    result_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def __init__(self, executable: str, host: str, port=5201, duration=10, reverse=False):
        super().__init__()
        self.executable = executable
        self.host = host
        self.port = port
        self.duration = duration
        self.reverse = reverse

    def run(self):
        cmd = [
            self.executable,
            "-c", self.host,
            "-p", str(self.port),
            "-t", str(self.duration),
            "-J",
        ]
        if self.reverse:
            cmd.append("-R")
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": max(30, int(self.duration) + 30),
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except FileNotFoundError:
            self.error_ready.emit("iperf3 executable was not found.")
            return
        except subprocess.TimeoutExpired:
            self.error_ready.emit("LAN throughput test timed out.")
            return
        except OSError as e:
            self.error_ready.emit(f"Could not run iperf3: {e}")
            return

        output = (completed.stdout or "").strip()
        if completed.returncode != 0:
            message = self._format_iperf_error(output, completed.stderr)
            self.error_ready.emit(message)
            return

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.error_ready.emit("iperf3 returned output that was not valid JSON.")
            return

        end = data.get("end", {}) or {}
        summary = end.get("sum_received") if self.reverse else end.get("sum_sent")
        if not summary:
            summary = end.get("sum") or end.get("sum_sent") or end.get("sum_received") or {}
        bits_per_second = summary.get("bits_per_second")
        seconds = summary.get("seconds")
        bytes_transferred = summary.get("bytes")
        retransmits = summary.get("retransmits")

        result = {
            "host": self.host,
            "port": self.port,
            "duration": self.duration,
            "direction": "Download from server" if self.reverse else "Upload to server",
            "bits_per_second": bits_per_second,
            "throughput": format_bits_per_second(bits_per_second),
            "seconds": "N/A" if seconds is None else f"{float(seconds):.1f} sec",
            "transferred": "N/A" if bytes_transferred is None else format_bytes_decimal(bytes_transferred),
            "retransmits": "N/A" if retransmits is None else str(retransmits),
            "diagnosis": lan_throughput_diagnosis(bits_per_second),
            "raw": json.dumps(data, indent=2),
        }
        self.result_ready.emit(result)

    def _format_iperf_error(self, stdout: str, stderr: str):
        error_text = ""
        if stdout:
            try:
                parsed = json.loads(stdout)
                error_text = str(parsed.get("error", "")).strip()
            except json.JSONDecodeError:
                error_text = stdout.strip()
        if not error_text:
            error_text = (stderr or "iperf3 failed.").strip()

        lower = error_text.lower()
        if "unable to connect to server" in lower or "connection timed out" in lower:
            return (
                f"Could not connect to iperf3 server at {self.host}:{self.port}. "
                "Start the LAN Throughput server on another PC, enter that PC's IP address here, "
                "and allow the selected port through Windows Firewall. Most gateways/routers do not run iperf3."
            )
        if "connection refused" in lower:
            return (
                f"{self.host}:{self.port} is reachable but no iperf3 server accepted the connection. "
                "Start iperf3 server mode on that device or choose the port used by the server."
            )
        return error_text


class GatewayStabilityWorker(QThread):
    """Pings a gateway repeatedly and emits rolling stability statistics."""
    sample_ready = pyqtSignal(dict)
    stats_ready = pyqtSignal(dict)

    def __init__(self, target: str, count=30, interval_ms=1000, timeout_ms=1000, spike_threshold_ms=20):
        super().__init__()
        self.target = target
        self.count = count
        self.interval_ms = interval_ms
        self.timeout_ms = timeout_ms
        self.spike_threshold_ms = spike_threshold_ms
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        latencies = []
        jitters = []
        prev_latency = None
        sent = 0
        received = 0
        spike_count = 0

        for index in range(1, self.count + 1):
            if self._stop_requested:
                break
            sent += 1
            latency, raw = self._ping_once()
            if latency is not None:
                received += 1
                latencies.append(latency)
                if prev_latency is not None:
                    jitters.append(abs(latency - prev_latency))
                prev_latency = latency
                if latency >= self.spike_threshold_ms:
                    spike_count += 1
            else:
                prev_latency = None

            loss_pct = ((sent - received) / sent) * 100 if sent else 0.0
            avg_ms = sum(latencies) / len(latencies) if latencies else None
            max_ms = max(latencies) if latencies else None
            jitter_ms = sum(jitters) / len(jitters) if jitters else None
            stats = {
                "target": self.target,
                "sent": sent,
                "received": received,
                "lost": sent - received,
                "loss_pct": loss_pct,
                "current_ms": latency,
                "avg_ms": avg_ms,
                "max_ms": max_ms,
                "jitter_ms": jitter_ms,
                "spike_count": spike_count,
                "spike_threshold_ms": self.spike_threshold_ms,
                "complete": index >= self.count or self._stop_requested,
            }
            stats["diagnosis"] = gateway_stability_diagnosis(stats)
            self.sample_ready.emit({
                "index": index,
                "latency": latency,
                "raw": raw,
                "status": "Timeout" if latency is None else f"{latency:.1f} ms",
            })
            self.stats_ready.emit(stats)

            if index < self.count and not self._stop_requested:
                self.msleep(max(0, int(self.interval_ms)))

    def _ping_once(self):
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(self.timeout_ms), self.target]
        else:
            timeout_seconds = max(1, int(math.ceil(self.timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), self.target]
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": max(2, int(math.ceil(self.timeout_ms / 1000)) + 2),
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except Exception as e:
            return None, f"Ping failed: {e}"

        raw = (completed.stdout or completed.stderr or "").strip()
        match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", raw, re.IGNORECASE)
        if not match:
            match = re.search(r"time\s+(\d+(?:\.\d+)?)\s*ms", raw, re.IGNORECASE)
        if match and completed.returncode == 0:
            return float(match.group(1)), raw
        return None, raw or "No ping output"


class LoadedLatencyWorker(QThread):
    """Measures baseline latency, then latency while LibreSpeed load runs."""
    phase_ready = pyqtSignal(str)
    sample_ready = pyqtSignal(dict)
    result_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def __init__(self, executable: str, ping_target: str, baseline_count=10, load_duration=15, interval_ms=1000, timeout_ms=1000):
        super().__init__()
        self.executable = executable
        self.ping_target = ping_target
        self.baseline_count = baseline_count
        self.load_duration = load_duration
        self.interval_ms = interval_ms
        self.timeout_ms = timeout_ms
        self._stop_requested = False
        self._load_process = None

    def stop(self):
        self._stop_requested = True
        proc = self._load_process
        if proc is not None and proc.poll() is None:
            proc.terminate()

    def run(self):
        self.phase_ready.emit("Collecting idle latency baseline...")
        idle_samples = self._collect_ping_samples("idle", count=self.baseline_count)
        if self._stop_requested:
            return

        self.phase_ready.emit("Running LibreSpeed load and measuring loaded latency...")
        loaded_samples, speed_data, speed_error = self._run_loaded_phase()
        if self._stop_requested:
            return

        if speed_error:
            self.error_ready.emit(speed_error)
            return

        result = self._build_result(idle_samples, loaded_samples, speed_data)
        self.result_ready.emit(result)

    def _run_loaded_phase(self):
        cmd = [
            self.executable,
            "--json",
            "--no-icmp",
            "--duration", str(self.load_duration),
            "--telemetry-level", "disabled",
        ]
        try:
            kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            self._load_process = subprocess.Popen(cmd, **kwargs)
        except FileNotFoundError:
            return [], None, "LibreSpeed CLI executable was not found."
        except OSError as e:
            return [], None, f"Could not run LibreSpeed CLI: {e}"

        samples = []
        started = time.monotonic()
        max_seconds = max(60, int(self.load_duration) + 90)
        while not self._stop_requested and self._load_process.poll() is None:
            if time.monotonic() - started > max_seconds:
                self._load_process.terminate()
                return samples, None, f"LibreSpeed load timed out after {max_seconds} seconds."
            latency, raw = self._ping_once()
            samples.append(latency)
            self.sample_ready.emit({
                "phase": "loaded",
                "index": len(samples),
                "latency": latency,
                "raw": raw,
                "status": "Timeout" if latency is None else f"{latency:.1f} ms",
            })
            self.msleep(max(0, int(self.interval_ms)))

        if self._stop_requested:
            return samples, None, None

        try:
            stdout, stderr = self._load_process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self._load_process.kill()
            stdout, stderr = self._load_process.communicate(timeout=5)

        if self._load_process.returncode != 0:
            message = (stderr or stdout or "LibreSpeed CLI failed during loaded latency test.").strip()
            return samples, None, message

        output = (stdout or "").strip()
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            start = output.find("{")
            end = output.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return samples, None, "LibreSpeed CLI did not return JSON output."
            try:
                parsed = json.loads(output[start:end+1])
            except json.JSONDecodeError:
                return samples, None, "Could not parse LibreSpeed JSON output."

        if isinstance(parsed, list):
            parsed = parsed[0] if parsed else {}
        if not isinstance(parsed, dict):
            return samples, None, "LibreSpeed CLI returned an unsupported JSON shape."
        return samples, parsed, None

    def _collect_ping_samples(self, phase: str, count: int):
        samples = []
        for index in range(1, count + 1):
            if self._stop_requested:
                break
            latency, raw = self._ping_once()
            samples.append(latency)
            self.sample_ready.emit({
                "phase": phase,
                "index": index,
                "latency": latency,
                "raw": raw,
                "status": "Timeout" if latency is None else f"{latency:.1f} ms",
            })
            if index < count and not self._stop_requested:
                self.msleep(max(0, int(self.interval_ms)))
        return samples

    def _ping_once(self):
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(self.timeout_ms), self.ping_target]
        else:
            timeout_seconds = max(1, int(math.ceil(self.timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), self.ping_target]
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": max(2, int(math.ceil(self.timeout_ms / 1000)) + 2),
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except Exception as e:
            return None, f"Ping failed: {e}"

        raw = (completed.stdout or completed.stderr or "").strip()
        match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", raw, re.IGNORECASE)
        if not match:
            match = re.search(r"time\s+(\d+(?:\.\d+)?)\s*ms", raw, re.IGNORECASE)
        if match and completed.returncode == 0:
            return float(match.group(1)), raw
        return None, raw or "No ping output"

    def _sample_stats(self, samples):
        valid = [value for value in samples if value is not None]
        jitters = [abs(valid[index] - valid[index - 1]) for index in range(1, len(valid))]
        return {
            "sent": len(samples),
            "received": len(valid),
            "lost": len(samples) - len(valid),
            "loss_pct": 0.0 if not samples else ((len(samples) - len(valid)) / len(samples)) * 100,
            "avg_ms": None if not valid else sum(valid) / len(valid),
            "max_ms": None if not valid else max(valid),
            "jitter_ms": None if not jitters else sum(jitters) / len(jitters),
        }

    def _build_result(self, idle_samples, loaded_samples, speed_data):
        idle = self._sample_stats(idle_samples)
        loaded = self._sample_stats(loaded_samples)
        delta = None
        if idle["avg_ms"] is not None and loaded["avg_ms"] is not None:
            delta = loaded["avg_ms"] - idle["avg_ms"]

        result = {
            "target": self.ping_target,
            "idle": idle,
            "loaded": loaded,
            "increase_ms": delta,
            "download": format_mbps((speed_data or {}).get("download")),
            "upload": format_mbps((speed_data or {}).get("upload")),
            "speed_raw": json.dumps(speed_data or {}, indent=2),
        }
        result["diagnosis"] = self._diagnosis(result)
        return result

    def _diagnosis(self, result):
        loaded = result["loaded"]
        delta = result.get("increase_ms")
        if loaded["loss_pct"] > 0:
            return (
                f"Loaded packet loss is {loaded['loss_pct']:.1f}%. Loss while the line is busy can indicate Wi-Fi instability, "
                "router queue pressure, ISP congestion, or a saturated local link."
            )
        if delta is None:
            return "Not enough successful ping replies to compare idle and loaded latency."
        if delta <= 20:
            return f"Loaded latency increased by {delta:.1f} ms. This looks healthy for most connections."
        if delta <= 75:
            return (
                f"Loaded latency increased by {delta:.1f} ms. This is noticeable queueing under load. "
                "QoS/SQM on the router may improve responsiveness."
            )
        return (
            f"Loaded latency increased by {delta:.1f} ms. This is likely bufferbloat or heavy queueing under load. "
            "Check router SQM/QoS, Wi-Fi quality, and whether upload/download bandwidth is saturating."
        )


class RouteHealthWorker(QThread):
    """Pings gateway, ISP edge, and public target while LibreSpeed load runs."""
    phase_ready = pyqtSignal(str)
    sample_ready = pyqtSignal(dict)
    result_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def __init__(
        self,
        executable: str,
        gateway: str,
        isp_hop: str,
        public_target: str,
        duration=15,
        interval_ms=1000,
        timeout_ms=1000,
        spike_threshold_ms=75,
    ):
        super().__init__()
        self.executable = executable
        self.gateway = gateway.strip()
        self.isp_hop = isp_hop.strip()
        self.public_target = public_target.strip()
        self.duration = duration
        self.interval_ms = interval_ms
        self.timeout_ms = timeout_ms
        self.spike_threshold_ms = spike_threshold_ms
        self._stop_requested = False
        self._load_process = None

    def stop(self):
        self._stop_requested = True
        proc = self._load_process
        if proc is not None and proc.poll() is None:
            proc.terminate()

    def run(self):
        if not self.gateway:
            self.error_ready.emit("Enter a gateway target.")
            return
        if not self.public_target:
            self.error_ready.emit("Enter a public target.")
            return

        detected_note = ""
        if not self.isp_hop:
            self.phase_ready.emit("Detecting ISP first hop...")
            self.isp_hop = self._detect_isp_hop()
            detected_note = "Auto-detected ISP hop." if self.isp_hop else "Could not auto-detect ISP hop."

        self.phase_ready.emit("Starting LibreSpeed load and route health probes...")
        samples, speed_data, speed_error = self._run_loaded_route_test()
        if self._stop_requested:
            return
        if speed_error:
            self.error_ready.emit(speed_error)
            return

        result = self._build_result(samples, speed_data, detected_note)
        self.result_ready.emit(result)

    def _detect_isp_hop(self):
        target = self.public_target
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", "4", "-w", str(self.timeout_ms), target]
        else:
            cmd = ["traceroute", "-n", "-m", "4", "-w", str(max(1, int(self.timeout_ms / 1000))), target]
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 12,
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except Exception:
            return ""

        output = completed.stdout or completed.stderr or ""
        gateway_ip = self.gateway.strip()
        for line in output.splitlines():
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            for ip in ips:
                if ip != gateway_ip and ip != target:
                    return ip
        return ""

    def _run_loaded_route_test(self):
        cmd = [
            self.executable,
            "--json",
            "--no-icmp",
            "--duration", str(self.duration),
            "--telemetry-level", "disabled",
        ]
        try:
            kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            self._load_process = subprocess.Popen(cmd, **kwargs)
        except FileNotFoundError:
            return {}, None, "LibreSpeed CLI executable was not found."
        except OSError as e:
            return {}, None, f"Could not run LibreSpeed CLI: {e}"

        samples = {
            "gateway": {"label": "Gateway", "target": self.gateway, "samples": []},
            "isp": {"label": "ISP first hop", "target": self.isp_hop, "samples": []},
            "public": {"label": "Public target", "target": self.public_target, "samples": []},
        }
        started = time.monotonic()
        max_seconds = max(60, int(self.duration) + 90)
        index = 0
        while not self._stop_requested and self._load_process.poll() is None:
            if time.monotonic() - started > max_seconds:
                self._load_process.terminate()
                return samples, None, f"LibreSpeed load timed out after {max_seconds} seconds."
            index += 1
            for key, item in samples.items():
                target = item.get("target", "")
                if not target:
                    continue
                latency, raw = self._ping_once(target)
                item["samples"].append(latency)
                self.sample_ready.emit({
                    "path": key,
                    "label": item["label"],
                    "target": target,
                    "index": index,
                    "latency": latency,
                    "raw": raw,
                    "status": "Timeout" if latency is None else f"{latency:.1f} ms",
                })
            self.msleep(max(0, int(self.interval_ms)))

        if self._stop_requested:
            return samples, None, None

        try:
            stdout, stderr = self._load_process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self._load_process.kill()
            stdout, stderr = self._load_process.communicate(timeout=5)

        if self._load_process.returncode != 0:
            message = (stderr or stdout or "LibreSpeed CLI failed during route health test.").strip()
            return samples, None, message

        output = (stdout or "").strip()
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            start = output.find("{")
            end = output.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return samples, None, "LibreSpeed CLI did not return JSON output."
            try:
                parsed = json.loads(output[start:end+1])
            except json.JSONDecodeError:
                return samples, None, "Could not parse LibreSpeed JSON output."

        if isinstance(parsed, list):
            parsed = parsed[0] if parsed else {}
        if not isinstance(parsed, dict):
            return samples, None, "LibreSpeed CLI returned an unsupported JSON shape."
        return samples, parsed, None

    def _ping_once(self, target):
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(self.timeout_ms), target]
        else:
            timeout_seconds = max(1, int(math.ceil(self.timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), target]
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": max(2, int(math.ceil(self.timeout_ms / 1000)) + 2),
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            completed = subprocess.run(cmd, **kwargs)
        except Exception as e:
            return None, f"Ping failed: {e}"

        raw = (completed.stdout or completed.stderr or "").strip()
        match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", raw, re.IGNORECASE)
        if not match:
            match = re.search(r"time\s+(\d+(?:\.\d+)?)\s*ms", raw, re.IGNORECASE)
        if match and completed.returncode == 0:
            return float(match.group(1)), raw
        return None, raw or "No ping output"

    def _sample_stats(self, item):
        values = item.get("samples", [])
        valid = [value for value in values if value is not None]
        jitters = [abs(valid[index] - valid[index - 1]) for index in range(1, len(valid))]
        spikes = [value for value in valid if value >= self.spike_threshold_ms]
        return {
            "label": item.get("label", "N/A"),
            "target": item.get("target") or "N/A",
            "sent": len(values),
            "received": len(valid),
            "lost": len(values) - len(valid),
            "loss_pct": 0.0 if not values else ((len(values) - len(valid)) / len(values)) * 100,
            "avg_ms": None if not valid else sum(valid) / len(valid),
            "max_ms": None if not valid else max(valid),
            "jitter_ms": None if not jitters else sum(jitters) / len(jitters),
            "spike_count": len(spikes),
            "spike_threshold_ms": self.spike_threshold_ms,
        }

    def _build_result(self, samples, speed_data, note):
        paths = {key: self._sample_stats(item) for key, item in samples.items()}
        result = {
            "paths": paths,
            "download": format_mbps((speed_data or {}).get("download")),
            "upload": format_mbps((speed_data or {}).get("upload")),
            "speed_raw": json.dumps(speed_data or {}, indent=2),
            "note": note,
        }
        result["diagnosis"] = route_health_diagnosis(result)
        return result


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


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TrackingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpTestWorker(QThread):
    """Runs an HTTP/HTTPS request in the background and returns timing and headers."""
    result_ready = pyqtSignal(dict)
    error_ready = pyqtSignal(str)

    def __init__(self, url: str, method="HEAD", follow_redirects=True, timeout_ms=5000, verify_tls=True):
        super().__init__()
        self.url = url
        self.method = method
        self.follow_redirects = follow_redirects
        self.timeout_ms = timeout_ms
        self.verify_tls = verify_tls

    def _normalized_url(self):
        url = self.url.strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url
        return url

    def run(self):
        url = self._normalized_url()
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            self.error_ready.emit("Enter a valid HTTP or HTTPS URL.")
            return

        timeout_seconds = max(0.5, self.timeout_ms / 1000)
        redirect_handler = TrackingRedirectHandler() if self.follow_redirects else NoRedirectHandler()
        handlers = [redirect_handler]
        if not self.verify_tls:
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        opener = urllib.request.build_opener(*handlers)
        request = urllib.request.Request(
            url,
            method=self.method,
            headers={"User-Agent": "PingerApp/1.0"},
        )

        started = time.perf_counter()
        response = None
        error = ""
        try:
            response = opener.open(request, timeout=timeout_seconds)
            if self.method == "GET":
                response.read(4096)
        except urllib.error.HTTPError as e:
            response = e
            error = f"HTTP error response: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            self.error_ready.emit(f"HTTP request failed: {e.reason}")
            return
        except Exception as e:
            self.error_ready.emit(f"HTTP request failed: {e}")
            return
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000

        headers = response.headers if response is not None else {}
        header_lines = [f"{key}: {value}" for key, value in headers.items()]
        final_url = response.geturl() if response is not None else "N/A"
        result = {
            "url": url,
            "method": self.method,
            "status_code": getattr(response, "status", getattr(response, "code", "N/A")),
            "reason": getattr(response, "reason", ""),
            "response_time_ms": elapsed_ms,
            "final_url": final_url,
            "redirect_count": getattr(redirect_handler, "redirect_count", 0),
            "tls": get_tls_summary(final_url if final_url != "N/A" else url, timeout=timeout_seconds, verify=self.verify_tls),
            "headers": "\n".join(header_lines) or "N/A",
            "error": error or "N/A",
        }
        try:
            response.close()
        except Exception:
            pass
        self.result_ready.emit(result)


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
        self.dns_compare_worker = None
        self.mtu_test_worker = None
        self.start_worker = None
        self.tr_worker = None
        self.port_check_worker = None
        self.adapter_info_worker = None
        self.lan_throughput_worker = None
        self.lan_server_process = None
        self.gateway_stability_worker = None
        self.loaded_latency_worker = None
        self.http_test_worker = None
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
        self.dns_compare_window = None
        self.dns_compare_input = None
        self.dns_compare_record_combo = None
        self.dns_compare_timeout_spin = None
        self.dns_compare_run_btn = None
        self.dns_compare_status_label = None
        self.dns_compare_table = None
        self.dns_compare_tool_btn = QPushButton("DNS Compare")
        self.dns_compare_tool_btn.setFixedSize(135, 30)
        self.dns_compare_tool_btn.setToolTip("Compare DNS answers across resolvers")
        self.dns_compare_tool_btn.clicked.connect(self.show_dns_compare_window)
        self.mtu_window = None
        self.mtu_target_input = None
        self.mtu_start_spin = None
        self.mtu_max_spin = None
        self.mtu_timeout_spin = None
        self.mtu_run_btn = None
        self.mtu_status_label = None
        self.mtu_payload_field = None
        self.mtu_estimated_field = None
        self.mtu_result_status_field = None
        self.mtu_raw_box = None
        self.mtu_tool_btn = QPushButton("MTU Test")
        self.mtu_tool_btn.setFixedSize(135, 30)
        self.mtu_tool_btn.setToolTip("Find largest non-fragmenting ping payload")
        self.mtu_tool_btn.clicked.connect(self.show_mtu_test_window)
        self.port_window = None
        self.port_host_input = None
        self.port_ports_combo = None
        self.port_manual_ports_input = None
        self.port_ports_preview = None
        self.port_port_presets = {
            "Manual ports": "",
            "Top troubleshooting": "20-23,25,53,80,110,139,143,443,445,587,993,995,3389,5900,8080,8443",
            "Common web": "80,443,8080,8443",
            "Common remote access": "22,23,3389,5900",
            "Common mail": "25,110,143,465,587,993,995",
            "Common network services": "21,22,23,53,80,123,139,443,445,3389",
            "Top 1024 TCP ports": "1-1024",
            "All TCP ports": "1-65535",
            "HTTPS only": "443",
            "HTTP only": "80",
        }
        self.port_target_mode_combo = None
        self.port_subnet_combo = None
        self.port_filter_combo = None
        self.port_timeout_spin = None
        self.port_concurrency_spin = None
        self.port_run_btn = None
        self.port_stop_btn = None
        self.port_status_label = None
        self.port_table = None
        self.port_open_only_check = None
        self.port_service_probe_check = None
        self.port_progress_bar = None
        self.port_help_label = None
        self.port_scan_results = []
        self.port_host_items = {}
        self.port_host_summaries = {}
        self.port_scan_seen_hosts = set()
        self.port_scan_result_count = 0
        self.port_scan_open_count = 0
        self.port_scan_filtered_count = 0
        self.port_scan_host_count = 0
        self.port_tool_btn = QPushButton("Network Scanner")
        self.port_tool_btn.setFixedSize(135, 30)
        self.port_tool_btn.setToolTip("Open network discovery and TCP port scanning")
        self.port_tool_btn.clicked.connect(self.show_port_check_window)
        self.http_window = None
        self.http_url_input = None
        self.http_method_combo = None
        self.http_follow_redirects_check = None
        self.http_ignore_tls_check = None
        self.http_timeout_spin = None
        self.http_run_btn = None
        self.http_status_label = None
        self.http_status_code_field = None
        self.http_response_time_field = None
        self.http_final_url_field = None
        self.http_redirects_field = None
        self.http_tls_field = None
        self.http_error_field = None
        self.http_headers_box = None
        self.http_tool_btn = QPushButton("HTTP Test")
        self.http_tool_btn.setFixedSize(135, 30)
        self.http_tool_btn.setToolTip("Open HTTP/HTTPS request diagnostics")
        self.http_tool_btn.clicked.connect(self.show_http_test_window)

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
        self.adapter_window = None
        self.adapter_labels = {}
        self.adapter_status_label = None
        self.adapter_refresh_btn = None
        self.adapter_watch_duration_spin = None
        self.adapter_watch_run_btn = None
        self.adapter_watch_stop_btn = None
        self.adapter_watch_labels = {}
        self.adapter_counter_watch_worker = None
        self.adapter_watch_last_result = None
        self.adapter_diagnosis_box = None
        self.adapter_info_btn = QPushButton("Adapter Info")
        self.adapter_info_btn.setFixedSize(135, 30)
        self.adapter_info_btn.setToolTip("Check active adapter link speed and network settings")
        self.adapter_info_btn.clicked.connect(self.show_adapter_info_window)
        self.lan_window = None
        self.lan_host_input = None
        self.lan_port_spin = None
        self.lan_duration_spin = None
        self.lan_direction_combo = None
        self.lan_run_btn = None
        self.lan_server_port_spin = None
        self.lan_server_start_btn = None
        self.lan_server_stop_btn = None
        self.lan_status_label = None
        self.lan_result_labels = {}
        self.lan_diagnosis_box = None
        self.lan_raw_box = None
        self.lan_last_result = None
        self.lan_throughput_btn = QPushButton("LAN Throughput")
        self.lan_throughput_btn.setFixedSize(135, 30)
        self.lan_throughput_btn.setToolTip("Run iperf3 LAN throughput tests")
        self.lan_throughput_btn.clicked.connect(self.show_lan_throughput_window)
        self.gateway_window = None
        self.gateway_target_input = None
        self.gateway_count_spin = None
        self.gateway_interval_spin = None
        self.gateway_timeout_spin = None
        self.gateway_spike_spin = None
        self.gateway_start_btn = None
        self.gateway_stop_btn = None
        self.gateway_status_label = None
        self.gateway_result_labels = {}
        self.gateway_diagnosis_box = None
        self.gateway_raw_box = None
        self.gateway_last_stats = None
        self.gateway_stability_btn = QPushButton("Gateway Stability")
        self.gateway_stability_btn.setFixedSize(135, 30)
        self.gateway_stability_btn.setToolTip("Monitor default gateway latency, loss, jitter, and spikes")
        self.gateway_stability_btn.clicked.connect(self.show_gateway_stability_window)
        self.route_health_worker = None
        self.route_window = None
        self.route_gateway_input = None
        self.route_isp_input = None
        self.route_public_input = None
        self.route_duration_spin = None
        self.route_interval_spin = None
        self.route_timeout_spin = None
        self.route_spike_spin = None
        self.route_run_btn = None
        self.route_stop_btn = None
        self.route_status_label = None
        self.route_summary_labels = {}
        self.route_table = None
        self.route_diagnosis_box = None
        self.route_raw_box = None
        self.route_last_result = None
        self.route_last_error = None
        self.route_health_btn = QPushButton("Route Health")
        self.route_health_btn.setFixedSize(135, 30)
        self.route_health_btn.setToolTip("Ping gateway, ISP hop, and public target during speed-test load")
        self.route_health_btn.clicked.connect(self.show_route_health_window)
        self.loaded_window = None
        self.loaded_target_input = None
        self.loaded_baseline_spin = None
        self.loaded_duration_spin = None
        self.loaded_interval_spin = None
        self.loaded_timeout_spin = None
        self.loaded_start_btn = None
        self.loaded_stop_btn = None
        self.loaded_status_label = None
        self.loaded_result_labels = {}
        self.loaded_diagnosis_box = None
        self.loaded_raw_box = None
        self.loaded_last_result = None
        self.loaded_latency_btn = QPushButton("Loaded Latency")
        self.loaded_latency_btn.setFixedSize(135, 30)
        self.loaded_latency_btn.setToolTip("Measure bufferbloat by pinging during a speed test")
        self.loaded_latency_btn.clicked.connect(self.show_loaded_latency_window)
        self.report_window = None
        self.report_checkboxes = {}
        self.report_preview_box = None
        self.report_tool_btn = QPushButton("Report")
        self.report_tool_btn.setFixedSize(135, 30)
        self.report_tool_btn.setToolTip("Build and save a troubleshooting report")
        self.report_tool_btn.clicked.connect(self.show_report_window)
        self.help_window = None
        self.help_text_box = None
        self.help_tool_btn = QPushButton("Help")
        self.help_tool_btn.setFixedSize(135, 30)
        self.help_tool_btn.setToolTip("Open PingerApp help and field guide")
        self.help_tool_btn.clicked.connect(self.show_help_window)

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
        tools_layout.addWidget(self.adapter_info_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.lan_throughput_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.gateway_stability_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.loaded_latency_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.route_health_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.port_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.http_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.dns_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.dns_compare_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.mtu_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.trace_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.alerts_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.report_tool_btn, 0, Qt.AlignCenter)
        tools_layout.addWidget(self.help_tool_btn, 0, Qt.AlignCenter)
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

    def _help_label(self, text: str, help_text: str):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        label = QLabel(text)
        button = QToolButton()
        button.setText("?")
        button.setFixedSize(18, 18)
        button.setAutoRaise(True)
        button.setToolTip(help_text)
        button.clicked.connect(
            lambda checked=False, btn=button, msg=help_text: QToolTip.showText(
                btn.mapToGlobal(btn.rect().bottomLeft()), msg, btn
            )
        )
        layout.addWidget(label)
        layout.addWidget(button)
        layout.addStretch(1)
        return widget

    def _help_button(self, help_text: str):
        button = QToolButton()
        button.setText("?")
        button.setFixedSize(18, 18)
        button.setAutoRaise(True)
        button.setToolTip(help_text)
        button.clicked.connect(
            lambda checked=False, btn=button, msg=help_text: QToolTip.showText(
                btn.mapToGlobal(btn.rect().bottomLeft()), msg, btn
            )
        )
        return button

    def _section_box(self, title: str, help_text: str, group: QGroupBox):
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(2)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(4, 0, 0, 0)
        header_layout.setSpacing(4)
        label = QLabel(title)
        label.setStyleSheet("QLabel { font-weight: bold; }")
        header_layout.addWidget(label)
        header_layout.addWidget(self._help_button(help_text))
        header_layout.addStretch(1)

        wrapper_layout.addWidget(header)
        wrapper_layout.addWidget(group)
        return wrapper

    def show_port_check_window(self):
        """Open the Network Scanner diagnostic window."""
        if self.port_window is None:
            self.port_window = QWidget(None, Qt.Window)
            self.port_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.port_window.setWindowTitle("Network Scanner")
            self.port_window.setMinimumSize(900, 560)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            self.port_host_input = QLineEdit(self._default_network_scan_host())
            self.port_host_input.setMinimumWidth(260)
            self.port_host_input.setPlaceholderText("Host, IP, or network base")
            self.port_target_mode_combo = QComboBox()
            self.port_target_mode_combo.addItems(["Single host", "Subnet"])
            self.port_target_mode_combo.setToolTip("Single host scans exactly the target. Subnet scans the selected CIDR range around the entered IP.")
            self.port_target_mode_combo.currentTextChanged.connect(self._update_port_target_controls)
            self.port_subnet_combo = QComboBox()
            self.port_subnet_combo.addItems([
                "/32 single address",
                "/31 point-to-point",
                "/30 4 addresses",
                "/29 8 addresses",
                "/28 16 addresses",
                "/27 32 addresses",
                "/26 64 addresses",
                "/25 128 addresses",
                "/24 256 addresses",
                "/23 512 addresses",
                "/22 1024 addresses",
                "/21 2048 addresses",
                "/20 4096 addresses",
                "/16 65536 addresses",
            ])
            self.port_subnet_combo.setCurrentText("/24 256 addresses")
            self.port_subnet_combo.setToolTip("Subnet size to combine with the Host/IP field when Target is Subnet.")
            self.port_ports_combo = QComboBox()
            self.port_ports_combo.setEditable(False)
            self.port_ports_combo.addItems(list(self.port_port_presets.keys()))
            self.port_ports_combo.setMinimumWidth(180)
            self.port_ports_combo.setMaximumWidth(230)
            self.port_ports_combo.setCurrentText("Top troubleshooting")
            self.port_ports_combo.setToolTip("Choose a named preset, or select Manual ports and type the exact TCP ports to scan.")
            self.port_ports_combo.currentTextChanged.connect(self._update_port_preview)
            self.port_manual_ports_input = QLineEdit()
            self.port_manual_ports_input.setPlaceholderText("443 or 80,443,8000-8010")
            self.port_manual_ports_input.setToolTip("Manual TCP ports to scan. Use commas, spaces, or ranges such as 80,443,8000-8010.")
            self.port_manual_ports_input.textEdited.connect(self._manual_ports_edited)
            self.port_ports_preview = QLineEdit()
            self.port_ports_preview.setReadOnly(True)
            self.port_ports_preview.setToolTip("Exact TCP ports that will be scanned for the selected preset or manual entry.")
            self.port_timeout_spin = QSpinBox()
            self.port_timeout_spin.setRange(250, 30000)
            self.port_timeout_spin.setSingleStep(250)
            self.port_timeout_spin.setValue(3000)
            self.port_timeout_spin.setSuffix(" ms")
            self.port_concurrency_spin = QSpinBox()
            self.port_concurrency_spin.setRange(1, 256)
            self.port_concurrency_spin.setValue(64)
            self.port_concurrency_spin.setToolTip("Parallel probes means how many TCP connection attempts can run at the same time. Lower is gentler; higher is faster.")
            self.port_filter_combo = QComboBox()
            self.port_filter_combo.addItems([
                "All results",
                "Open/live only",
                "Open ports only",
                "Filtered/dropped only",
                "Closed/refused only",
            ])
            self.port_filter_combo.setToolTip("Filter what appears in the results table.")
            self.port_filter_combo.currentTextChanged.connect(self._refresh_port_table)
            self.port_run_btn = QPushButton("Run Scan")
            self.port_run_btn.clicked.connect(self.start_port_check)
            self.port_stop_btn = QPushButton("Stop")
            self.port_stop_btn.setEnabled(False)
            self.port_stop_btn.clicked.connect(self.stop_port_check)
            self.port_open_only_check = QCheckBox("Show open/live only")
            self.port_open_only_check.setVisible(False)
            self.port_service_probe_check = QCheckBox("Probe service banners")
            self.port_service_probe_check.setToolTip("Best-effort banner, HTTP header, and TLS handshake checks on open ports.")

            target_help = (
                "Choose Single host for one device, or Subnet to discover devices in the selected CIDR range. "
                "For example, Host 172.16.10.1 with /24 scans 172.16.10.0/24."
            )
            target_group = QGroupBox()
            target_layout = QGridLayout()
            target_layout.setHorizontalSpacing(8)
            target_layout.setVerticalSpacing(6)
            target_layout.addWidget(QLabel("Host"), 0, 0)
            target_layout.addWidget(self.port_host_input, 0, 1)
            target_layout.addWidget(QLabel("Target"), 0, 2)
            target_layout.addWidget(self.port_target_mode_combo, 0, 3)
            target_layout.addWidget(QLabel("Subnet"), 0, 4)
            target_layout.addWidget(self.port_subnet_combo, 0, 5)
            target_layout.setColumnStretch(1, 1)
            target_group.setLayout(target_layout)

            scan_help = (
                "Port presets: Top troubleshooting covers common remote, web, mail, file sharing, and DNS ports. "
                "Common web scans HTTP/HTTPS alternates. Common remote access checks SSH, Telnet, RDP, and VNC. "
                "Common mail checks SMTP/POP/IMAP variants. Common network services checks FTP/SSH/Telnet/DNS/NTP/SMB/RDP. "
                "Select Manual ports to scan one specific port or a custom list. "
                "The preview field shows the exact TCP ports that will be scanned."
            )
            scan_group = QGroupBox()
            scan_layout = QGridLayout()
            scan_layout.setHorizontalSpacing(8)
            scan_layout.setVerticalSpacing(6)
            scan_layout.addWidget(QLabel("Port preset"), 0, 0)
            scan_layout.addWidget(self.port_ports_combo, 0, 1)
            scan_layout.addWidget(QLabel("Manual ports"), 0, 2)
            scan_layout.addWidget(self.port_manual_ports_input, 0, 3, 1, 3)
            scan_layout.addWidget(QLabel("Ports scanned"), 1, 0)
            scan_layout.addWidget(self.port_ports_preview, 1, 1, 1, 5)
            scan_layout.addWidget(QLabel("Timeout"), 2, 0)
            scan_layout.addWidget(self.port_timeout_spin, 2, 1)
            scan_layout.addWidget(QLabel("Parallel probes"), 2, 2)
            scan_layout.addWidget(self.port_concurrency_spin, 2, 3)
            scan_layout.addWidget(self.port_service_probe_check, 2, 4, 1, 2)
            scan_layout.setColumnStretch(1, 1)
            scan_group.setLayout(scan_layout)

            display_help = (
                "Results are grouped by host. Host State only shows whether the host was discovered. "
                "Open Ports summarizes open port numbers for the host. Port State is shown on each child port row."
            )
            display_group = QGroupBox()
            display_layout = QGridLayout()
            display_layout.setHorizontalSpacing(8)
            display_layout.setVerticalSpacing(6)
            display_layout.addWidget(QLabel("Filter"), 0, 0)
            display_layout.addWidget(self.port_filter_combo, 0, 1)
            display_layout.addWidget(self.port_run_btn, 0, 2)
            display_layout.addWidget(self.port_stop_btn, 0, 3)
            display_layout.setColumnStretch(1, 1)
            display_group.setLayout(display_layout)

            layout.addWidget(self._section_box("Target", target_help, target_group))
            layout.addWidget(self._section_box("Scan", scan_help, scan_group))
            layout.addWidget(self._section_box("Display", display_help, display_group))

            self._update_port_target_controls()
            self._update_port_preview()

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

            self.port_table = QTreeWidget()
            self.port_table.setColumnCount(10)
            self.port_table.setHeaderLabels(["Host", "Hostname", "Host State", "MAC", "Open Ports", "Port", "Service", "Port State", "Latency", "Details"])
            self.port_table.setRootIsDecorated(True)
            self.port_table.setAlternatingRowColors(True)
            self.port_table.setSelectionBehavior(QTreeWidget.SelectRows)
            self.port_table.setUniformRowHeights(False)
            self.port_table.setWordWrap(True)
            self.port_table.setStyleSheet(
                "QTreeWidget::item { padding: 2px 12px 2px 4px; } "
                "QHeaderView::section { padding: 3px 12px 3px 4px; }"
            )
            ph = self.port_table.header()
            ph.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(3, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(4, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(5, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(6, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(7, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(8, QHeaderView.ResizeToContents)
            ph.setSectionResizeMode(9, QHeaderView.Stretch)
            layout.addWidget(self.port_table, 1)
            self.port_window.setLayout(layout)

        if self.port_host_input is not None and not self.port_host_input.text().strip():
            self.port_host_input.setText(self._default_network_scan_host())
        self.port_window.show()
        self.port_window.raise_()
        self.port_window.activateWindow()

    def _default_network_scan_host(self):
        gateway = self.gateway_label.text().strip() if hasattr(self, "gateway_label") else ""
        local_ip = self.host_ip_label.text().strip() if hasattr(self, "host_ip_label") else ""
        for value in (gateway, first_host_in_range(local_ip), local_ip, self.host_input.text().strip()):
            if value and value not in {"N/A", "Loading...", "Host Not Found"}:
                return value
        return ""

    def _selected_port_text(self):
        if self.port_ports_combo is None:
            return ""
        text = self.port_ports_combo.currentText().strip()
        if text == "Manual ports":
            return self.port_manual_ports_input.text().strip() if self.port_manual_ports_input is not None else ""
        return self.port_port_presets.get(text, text)

    def _update_port_preview(self, *args):
        if self.port_ports_preview is None:
            return
        text = self._selected_port_text()
        self.port_ports_preview.setText(text)

    def _manual_ports_edited(self, *args):
        if self.port_ports_combo is None:
            return
        index = self.port_ports_combo.findText("Manual ports")
        if index >= 0 and self.port_ports_combo.currentIndex() != index:
            self.port_ports_combo.setCurrentIndex(index)
        self._update_port_preview()

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
        return deduped

    def _update_port_target_controls(self):
        if self.port_target_mode_combo is None or self.port_subnet_combo is None:
            return
        subnet_mode = self.port_target_mode_combo.currentText() == "Subnet"
        self.port_subnet_combo.setEnabled(subnet_mode)

    def _selected_subnet_prefix(self):
        if self.port_subnet_combo is None:
            return 24
        match = re.search(r"/(\d+)", self.port_subnet_combo.currentText())
        return int(match.group(1)) if match else 24

    def _expand_scan_targets(self, target: str, mode: str, prefix=None):
        target = target.strip()
        if not target:
            raise ValueError("Enter a host, IP address, or CIDR range.")

        if mode == "Subnet":
            try:
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                else:
                    network = ipaddress.ip_interface(f"{target}/{prefix or 24}").network
            except ValueError as e:
                raise ValueError(f"Enter a valid IPv4 address or CIDR range, for example 192.168.1.10. {e}")

            if network.version != 4:
                raise ValueError("Network discovery currently supports IPv4 ranges only.")
            if network.num_addresses > 512:
                raise ValueError("Network discovery is limited to 512 addresses at a time. Use /23 or smaller.")
            hosts = list(network.hosts()) if network.prefixlen < 31 else list(network)
            if not hosts:
                raise ValueError("The selected range has no usable hosts.")
            return [str(host) for host in hosts]

        if "/" in target:
            try:
                interface = ipaddress.ip_interface(target)
                return [str(interface.ip)]
            except ValueError:
                pass
        return [target]

    def start_port_check(self):
        """Run network discovery and TCP scanning in the Network Scanner window."""
        if self.port_check_worker is not None and self.port_check_worker.isRunning():
            return

        host = self.port_host_input.text().strip() if self.port_host_input is not None else self.host_input.text().strip()
        if not host:
            return

        try:
            ports = self._parse_port_list(self._selected_port_text())
        except ValueError as e:
            QMessageBox.warning(self, "Network Scanner Error", str(e))
            return

        mode = self.port_target_mode_combo.currentText() if self.port_target_mode_combo is not None else "Single host"
        try:
            targets = self._expand_scan_targets(host, mode, self._selected_subnet_prefix())
        except ValueError as e:
            QMessageBox.warning(self, "Network Scanner Error", str(e))
            return

        if len(targets) > 1 and len(ports) > 256:
            QMessageBox.warning(
                self,
                "Network Scanner Limit",
                "Network range scans are limited to 256 selected ports per live host. "
                "Use a smaller port preset for ranges, or scan one host for a full 1-65535 port sweep.",
            )
            return

        timeout_ms = self.port_timeout_spin.value() if self.port_timeout_spin is not None else 3000
        max_workers = self.port_concurrency_spin.value() if self.port_concurrency_spin is not None else 64
        detect_services = self.port_service_probe_check is not None and self.port_service_probe_check.isChecked()
        self.port_table.clear()
        self.port_table.setHeaderLabels(["Host", "Hostname", "Host State", "MAC", "Open Ports", "Port", "Service", "Port State", "Latency", "Details"])
        self.port_scan_results = []
        self.port_host_items = {}
        self.port_host_summaries = {}
        self.port_scan_seen_hosts = set()
        self.port_scan_result_count = 0
        self.port_scan_open_count = 0
        self.port_scan_filtered_count = 0
        self.port_scan_host_count = 0
        self.port_run_btn.setEnabled(False)
        if self.port_stop_btn is not None:
            self.port_stop_btn.setEnabled(True)
        if self.port_progress_bar is not None:
            self.port_progress_bar.setValue(0)
            self.port_progress_bar.setFormat("Scanning... 0%")
        if len(targets) == 1:
            self.port_status_label.setText(f"Scanning {len(ports)} TCP port(s) on {host}...")
        else:
            self.port_status_label.setText(f"Discovering {len(targets)} host(s), then scanning {len(ports)} TCP port(s) on live hosts...")
        self.port_status_label.setStyleSheet(
            "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

        self.port_check_worker = PortCheckWorker(
            host,
            targets,
            ports,
            timeout_ms=timeout_ms,
            detect_services=detect_services,
            max_workers=max_workers,
        )
        self.port_check_worker.host_ready.connect(self._add_port_check_result)
        self.port_check_worker.result_ready.connect(self._add_port_check_result)
        self.port_check_worker.progress_ready.connect(self._update_port_scan_progress)
        self.port_check_worker.finished.connect(self._finish_port_check)
        self.port_check_worker.finished.connect(self.port_check_worker.deleteLater)
        self.port_check_worker.finished.connect(lambda: setattr(self, "port_check_worker", None))
        self.port_check_worker.start()

    def stop_port_check(self):
        if self.port_check_worker is None or not self.port_check_worker.isRunning():
            return
        self.port_check_worker.request_stop()
        if self.port_stop_btn is not None:
            self.port_stop_btn.setEnabled(False)
        if self.port_status_label is not None:
            self.port_status_label.setText("Stopping scan after active probes finish...")
            self.port_status_label.setStyleSheet(
                "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

    def _add_port_check_result(self, result: dict):
        if self.port_table is None:
            return
        status = result.get("status", "")
        host = result.get("host", "")
        if status == "Host Up" and host not in self.port_scan_seen_hosts:
            self.port_scan_seen_hosts.add(host)
            self.port_scan_host_count += 1
        elif status in {"Open", "Closed"} and host not in self.port_scan_seen_hosts:
            self.port_scan_seen_hosts.add(host)
            self.port_scan_host_count += 1
        if status != "Host Up":
            self.port_scan_result_count += 1
        if status == "Open":
            self.port_scan_open_count += 1
        if status == "Filtered":
            self.port_scan_filtered_count += 1
        if (
            self.port_open_only_check is not None
            and self.port_open_only_check.isChecked()
            and status not in {"Open", "Host Up"}
        ):
            return
        self.port_scan_results.append(result)
        if not self._port_result_visible(result):
            return
        self._insert_port_result(result)

    def _port_result_visible(self, result: dict):
        status = result.get("status", "")
        selected = self.port_filter_combo.currentText() if self.port_filter_combo is not None else "All results"
        if selected == "Open/live only":
            return status in {"Open", "Host Up"}
        if selected == "Open ports only":
            return status == "Open"
        if selected == "Filtered/dropped only":
            return status == "Filtered"
        if selected == "Closed/refused only":
            return status == "Closed"
        return True

    def _refresh_port_table(self, *args):
        if self.port_table is None:
            return
        self.port_table.clear()
        self.port_table.setHeaderLabels(["Host", "Hostname", "Host State", "MAC", "Open Ports", "Port", "Service", "Port State", "Latency", "Details"])
        self.port_host_items = {}
        self.port_host_summaries = {}
        for result in self.port_scan_results:
            if self._port_result_visible(result):
                self._insert_port_result(result)

    def _blank_host_summary(self, result):
        return {
            "host": result.get("host", ""),
            "hostname": result.get("hostname", "N/A"),
            "mac": result.get("mac", "N/A"),
            "alive": False,
            "open": 0,
            "open_ports": [],
            "closed": 0,
            "filtered": 0,
            "unreachable": 0,
            "other": 0,
            "latency": None,
            "details": "",
        }

    def _apply_tree_item_style(self, item, status):
        row_background = None
        if status == "Open":
            row_background = QBrush(QColor("#dff3e6"))
        elif status == "Host Up":
            row_background = QBrush(QColor("#e8f0fe"))
        elif status == "Filtered":
            row_background = QBrush(QColor("#fff4ce"))
        elif status in {"Closed", "No Response"}:
            row_background = QBrush(QColor("#f8d7da"))
        if row_background is not None:
            for col in range(item.columnCount()):
                item.setBackground(col, row_background)

    def _update_host_summary_item(self, host):
        item = self.port_host_items.get(host)
        summary = self.port_host_summaries.get(host)
        if item is None or summary is None:
            return
        scanned = summary["open"] + summary["closed"] + summary["filtered"] + summary["unreachable"] + summary["other"]
        state = "Host Up" if summary["alive"] else "Host"
        if scanned:
            if summary["open_ports"]:
                port_summary = f"{summary['open']}/{scanned} open: {', '.join(summary['open_ports'])}"
            else:
                port_summary = f"0/{scanned} open"
        else:
            port_summary = ""
        latency = "N/A" if summary["latency"] is None else f"{summary['latency']:.1f} ms"
        item.setText(0, host)
        item.setText(1, summary["hostname"])
        item.setText(2, state)
        item.setText(3, summary["mac"])
        item.setText(4, port_summary)
        item.setText(5, "")
        item.setText(6, "")
        item.setText(7, "")
        item.setText(8, latency)
        item.setText(9, wrapped_detail_text(summary["details"]))
        item.setToolTip(9, summary["details"])
        if summary["open"]:
            self._apply_tree_item_style(item, "Open")
        elif summary["alive"]:
            self._apply_tree_item_style(item, "Host Up")
        elif summary["filtered"] and not summary["closed"]:
            self._apply_tree_item_style(item, "Filtered")
        elif summary["closed"]:
            self._apply_tree_item_style(item, "Closed")

    def _get_host_item(self, result):
        host = result.get("host", "")
        if host in self.port_host_items:
            return self.port_host_items[host]
        item = QTreeWidgetItem(["", "", "", "", "", "", "", "", "", ""])
        self.port_table.addTopLevelItem(item)
        self.port_host_items[host] = item
        self.port_host_summaries[host] = self._blank_host_summary(result)
        self._update_host_summary_item(host)
        item.setExpanded(True)
        return item

    def _insert_port_result(self, result: dict):
        status = result.get("status", "")
        latency = "N/A" if result.get("latency") is None else f"{result['latency']:.1f} ms"
        host_item = self._get_host_item(result)
        summary = self.port_host_summaries[result.get("host", "")]
        summary["hostname"] = first_available(result.get("hostname"), summary["hostname"])
        summary["mac"] = first_available(result.get("mac"), summary["mac"])
        if result.get("latency") is not None and summary["latency"] is None:
            summary["latency"] = result.get("latency")
        if status == "Host Up":
            summary["alive"] = True
            summary["details"] = result.get("error", "")
            self._update_host_summary_item(result.get("host", ""))
            return

        if status == "Open":
            summary["alive"] = True
            summary["open"] += 1
            port_text = str(result.get("port", ""))
            if port_text and port_text not in summary["open_ports"]:
                summary["open_ports"].append(port_text)
        elif status == "Closed":
            summary["alive"] = True
            summary["closed"] += 1
        elif status == "Filtered":
            summary["filtered"] += 1
        elif status == "Unreachable":
            summary["unreachable"] += 1
        else:
            summary["other"] += 1

        child = QTreeWidgetItem([
            "",
            "",
            "",
            "",
            "",
            str(result.get("port", "")),
            result.get("service", ""),
            status,
            latency,
            wrapped_detail_text(result.get("error", "")),
        ])
        child.setToolTip(9, result.get("error", ""))
        self._apply_tree_item_style(child, status)
        host_item.addChild(child)
        self._update_host_summary_item(result.get("host", ""))

    def _update_port_scan_progress(self, completed: int, total: int):
        if self.port_progress_bar is None:
            return
        pct = 100 if total <= 0 else int((completed / total) * 100)
        self.port_progress_bar.setValue(min(100, pct))
        self.port_progress_bar.setFormat(f"Scanned {completed}/{total} port(s)")

    def _finish_port_check(self):
        if self.port_run_btn is not None:
            self.port_run_btn.setEnabled(True)
        if self.port_stop_btn is not None:
            self.port_stop_btn.setEnabled(False)
        stopped = self.port_check_worker is not None and getattr(self.port_check_worker, "was_stopped", False)
        if self.port_status_label is not None:
            suffix = ""
            if self.port_filter_combo is not None and self.port_filter_combo.currentText() != "All results":
                suffix = f" ({self.port_filter_combo.currentText()} view)"
            prefix = "Stopped" if stopped else "Completed"
            self.port_status_label.setText(
                f"{prefix}. {self.port_scan_host_count} host(s) found, "
                f"{self.port_scan_open_count}/{self.port_scan_result_count} port(s) open, "
                f"{self.port_scan_filtered_count} filtered/dropped{suffix}."
            )
            if stopped:
                self.port_status_label.setStyleSheet(
                    "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            else:
                self.port_status_label.setStyleSheet(
                    "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
        if self.port_progress_bar is not None:
            if stopped:
                self.port_progress_bar.setFormat("Stopped")
            else:
                self.port_progress_bar.setValue(100)
                self.port_progress_bar.setFormat("Complete")

    def show_adapter_info_window(self):
        """Open the active adapter and link speed diagnostic window."""
        if self.adapter_window is None:
            self.adapter_window = QWidget(None, Qt.Window)
            self.adapter_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.adapter_window.setWindowTitle("Adapter Info")
            self.adapter_window.setMinimumSize(820, 680)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls = QHBoxLayout()
            self.adapter_refresh_btn = QPushButton("Refresh Adapter Info")
            self.adapter_refresh_btn.clicked.connect(self.refresh_adapter_info)
            self.adapter_watch_duration_spin = QSpinBox()
            self.adapter_watch_duration_spin.setRange(5, 300)
            self.adapter_watch_duration_spin.setValue(30)
            self.adapter_watch_duration_spin.setSuffix(" sec")
            self.adapter_watch_duration_spin.setToolTip("How long to watch adapter counters for changes.")
            self.adapter_watch_run_btn = QPushButton("Run Counter Watch")
            self.adapter_watch_run_btn.setToolTip("Measure transfer, errors, and discards over the selected duration.")
            self.adapter_watch_run_btn.clicked.connect(self.start_adapter_counter_watch)
            self.adapter_watch_stop_btn = QPushButton("Stop Watch")
            self.adapter_watch_stop_btn.setEnabled(False)
            self.adapter_watch_stop_btn.clicked.connect(self.stop_adapter_counter_watch)
            controls.addWidget(self.adapter_refresh_btn)
            controls.addWidget(QLabel("Watch duration"))
            controls.addWidget(self.adapter_watch_duration_spin)
            controls.addWidget(self.adapter_watch_run_btn)
            controls.addWidget(self.adapter_watch_stop_btn)
            controls.addStretch(1)
            layout.addLayout(controls)

            self.adapter_status_label = QLabel("Ready")
            self.adapter_status_label.setAlignment(Qt.AlignCenter)
            self.adapter_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.adapter_status_label)

            details_group = QGroupBox("Active Adapter")
            details = QGridLayout()
            details.setContentsMargins(10,10,10,10)
            details.setHorizontalSpacing(12)
            details.setVerticalSpacing(8)
            fields = [
                ("adapter", "Adapter"),
                ("description", "Description"),
                ("status", "Status"),
                ("connection_type", "Type"),
                ("link_speed", "Link Speed"),
                ("duplex", "Duplex / Setting"),
                ("ipv4", "IPv4"),
                ("gateway", "Gateway"),
                ("dns_servers", "DNS Servers"),
                ("mac", "MAC"),
                ("interface_index", "Interface Index"),
            ]
            self.adapter_labels = {}
            for row, (key, label_text) in enumerate(fields):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.adapter_labels[key] = value
                details.addWidget(name, row, 0)
                details.addWidget(value, row, 1)
            details.setColumnStretch(1, 1)
            details_group.setLayout(details)
            layout.addWidget(details_group)

            counters_group = QGroupBox("Interface Counters")
            counters = QGridLayout()
            counters.setContentsMargins(10,10,10,10)
            counters.setHorizontalSpacing(12)
            counters.setVerticalSpacing(8)
            counter_fields = [
                ("counter_source", "Source"),
                ("rx_traffic", "Received"),
                ("tx_traffic", "Sent"),
                ("rx_errors", "Receive Errors"),
                ("tx_errors", "Transmit Errors"),
                ("rx_discards", "Receive Discards"),
                ("tx_discards", "Transmit Discards"),
            ]
            for row, (key, label_text) in enumerate(counter_fields):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.adapter_labels[key] = value
                counters.addWidget(name, row // 2, (row % 2) * 2)
                counters.addWidget(value, row // 2, (row % 2) * 2 + 1)
            counters.setColumnStretch(1, 1)
            counters.setColumnStretch(3, 1)
            counters_group.setLayout(counters)
            layout.addWidget(counters_group)

            watch_group = QGroupBox("Counter Watch Result")
            watch = QGridLayout()
            watch.setContentsMargins(10,10,10,10)
            watch.setHorizontalSpacing(12)
            watch.setVerticalSpacing(8)
            watch_fields = [
                ("duration", "Duration"),
                ("received_delta", "Received During Watch"),
                ("sent_delta", "Sent During Watch"),
                ("receive_rate", "Avg Receive Rate"),
                ("send_rate", "Avg Send Rate"),
                ("error_delta", "Error Increase"),
                ("discard_delta", "Discard Increase"),
            ]
            self.adapter_watch_labels = {}
            for row, (key, label_text) in enumerate(watch_fields):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.adapter_watch_labels[key] = value
                watch.addWidget(name, row // 2, (row % 2) * 2)
                watch.addWidget(value, row // 2, (row % 2) * 2 + 1)
            watch.setColumnStretch(1, 1)
            watch.setColumnStretch(3, 1)
            watch_group.setLayout(watch)
            layout.addWidget(watch_group)

            diagnosis_group = QGroupBox("Diagnosis")
            diagnosis_layout = QVBoxLayout()
            self.adapter_diagnosis_box = QTextEdit()
            self.adapter_diagnosis_box.setReadOnly(True)
            self.adapter_diagnosis_box.setMinimumHeight(110)
            self.adapter_diagnosis_box.setLineWrapMode(QTextEdit.WidgetWidth)
            diagnosis_layout.addWidget(self.adapter_diagnosis_box)
            diagnosis_group.setLayout(diagnosis_layout)
            layout.addWidget(diagnosis_group, 1)

            self.adapter_window.setLayout(layout)

        self.adapter_window.show()
        self.adapter_window.raise_()
        self.adapter_window.activateWindow()
        self.refresh_adapter_info()

    def refresh_adapter_info(self):
        if self.adapter_info_worker is not None and self.adapter_info_worker.isRunning():
            return
        if self.adapter_counter_watch_worker is not None and self.adapter_counter_watch_worker.isRunning():
            return
        if self.adapter_refresh_btn is not None:
            self.adapter_refresh_btn.setEnabled(False)
        if self.adapter_watch_run_btn is not None:
            self.adapter_watch_run_btn.setEnabled(False)
        if self.adapter_status_label is not None:
            self.adapter_status_label.setText("Reading active adapter details...")
            self.adapter_status_label.setStyleSheet(
                "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

        self.adapter_info_worker = AdapterInfoWorker()
        self.adapter_info_worker.info_ready.connect(self._set_adapter_info)
        self.adapter_info_worker.error_ready.connect(self._set_adapter_info_error)
        self.adapter_info_worker.finished.connect(self._finish_adapter_info)
        self.adapter_info_worker.finished.connect(self.adapter_info_worker.deleteLater)
        self.adapter_info_worker.finished.connect(lambda: setattr(self, "adapter_info_worker", None))
        self.adapter_info_worker.start()

    def _set_adapter_info(self, info: dict):
        for key, label in self.adapter_labels.items():
            value = str(info.get(key, "N/A") or "N/A")
            label.setText(value)
            label.setToolTip(value)
        if self.adapter_watch_labels:
            for label in self.adapter_watch_labels.values():
                label.setText("N/A")
                label.setToolTip("N/A")
        self.adapter_watch_last_result = None
        diagnosis = info.get("diagnosis", "N/A")
        if self.adapter_diagnosis_box is not None:
            self.adapter_diagnosis_box.setPlainText(diagnosis)
        if self.adapter_status_label is not None:
            self.adapter_status_label.setText("Adapter info loaded.")
            self.adapter_status_label.setStyleSheet(
                "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

    def _set_adapter_info_error(self, message: str):
        fallback = {
            "adapter": "N/A",
            "description": "PowerShell adapter details unavailable",
            "status": "N/A",
            "connection_type": "N/A",
            "link_speed": "N/A",
            "duplex": "N/A",
            "ipv4": get_local_ip(),
            "gateway": get_default_gateway(),
            "dns_servers": "N/A",
            "mac": get_primary_mac(),
            "interface_index": "N/A",
            "counter_source": "Unavailable",
            "rx_traffic": "N/A",
            "tx_traffic": "N/A",
            "rx_errors": "N/A",
            "tx_errors": "N/A",
            "rx_discards": "N/A",
            "tx_discards": "N/A",
            "diagnosis": (
                f"{message}\n\n"
                "The app could not read Windows adapter link-speed data. "
                "You can still compare local IP/gateway here, then check Windows Settings > Network & internet > "
                "Advanced network settings for Link speed."
            ),
        }
        self._set_adapter_info(fallback)
        if self.adapter_status_label is not None:
            self.adapter_status_label.setText("Adapter link-speed details unavailable.")
            self.adapter_status_label.setStyleSheet(
                "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

    def _finish_adapter_info(self):
        if self.adapter_refresh_btn is not None:
            self.adapter_refresh_btn.setEnabled(True)
        if self.adapter_watch_run_btn is not None:
            self.adapter_watch_run_btn.setEnabled(True)

    def start_adapter_counter_watch(self):
        if self.adapter_counter_watch_worker is not None and self.adapter_counter_watch_worker.isRunning():
            return
        if self.adapter_info_worker is not None and self.adapter_info_worker.isRunning():
            return

        duration = self.adapter_watch_duration_spin.value() if self.adapter_watch_duration_spin is not None else 30
        for label in self.adapter_watch_labels.values():
            label.setText("N/A")
            label.setToolTip("N/A")
        self.adapter_watch_last_result = None
        if self.adapter_refresh_btn is not None:
            self.adapter_refresh_btn.setEnabled(False)
        if self.adapter_watch_run_btn is not None:
            self.adapter_watch_run_btn.setEnabled(False)
        if self.adapter_watch_stop_btn is not None:
            self.adapter_watch_stop_btn.setEnabled(True)
        if self.adapter_watch_duration_spin is not None:
            self.adapter_watch_duration_spin.setEnabled(False)
        self._set_adapter_status("Counter Watch starting...", "running")

        self.adapter_counter_watch_worker = AdapterCounterWatchWorker(duration)
        self.adapter_counter_watch_worker.status_ready.connect(lambda message: self._set_adapter_status(message, "running"))
        self.adapter_counter_watch_worker.result_ready.connect(self._set_adapter_counter_watch_result)
        self.adapter_counter_watch_worker.error_ready.connect(self._set_adapter_counter_watch_error)
        self.adapter_counter_watch_worker.finished.connect(self._finish_adapter_counter_watch)
        self.adapter_counter_watch_worker.finished.connect(self.adapter_counter_watch_worker.deleteLater)
        self.adapter_counter_watch_worker.finished.connect(lambda: setattr(self, "adapter_counter_watch_worker", None))
        self.adapter_counter_watch_worker.start()

    def stop_adapter_counter_watch(self):
        if self.adapter_counter_watch_worker is not None and self.adapter_counter_watch_worker.isRunning():
            self.adapter_counter_watch_worker.stop()
            self._set_adapter_status("Stopping Counter Watch...", "running")

    def _set_adapter_status(self, message: str, level="info"):
        if self.adapter_status_label is None:
            return
        styles = {
            "info": ("#eef2f7", "#3c4043", "#b7c0cc"),
            "running": ("#fff4ce", "#8a5a00", "#d8b756"),
            "ok": ("#e6f4ea", "#137333", "#8abf9a"),
            "error": ("#fce8e6", "#a50e0e", "#d28b82"),
        }
        bg, fg, border = styles.get(level, styles["info"])
        self.adapter_status_label.setText(message)
        self.adapter_status_label.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {fg}; border: 1px solid {border}; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

    def _set_adapter_counter_watch_result(self, result: dict):
        self.adapter_watch_last_result = result
        end_info = result.get("end_info", {})
        for key, label in self.adapter_labels.items():
            value = str(end_info.get(key, "N/A") or "N/A")
            label.setText(value)
            label.setToolTip(value)

        values = {
            "duration": f"{result.get('duration_sec', 'N/A')} sec",
            "received_delta": result.get("rx_transfer", "N/A"),
            "sent_delta": result.get("tx_transfer", "N/A"),
            "receive_rate": result.get("rx_rate", "N/A"),
            "send_rate": result.get("tx_rate", "N/A"),
            "error_delta": result.get("error_delta", "N/A"),
            "discard_delta": result.get("discard_delta", "N/A"),
        }
        for key, value in values.items():
            label = self.adapter_watch_labels.get(key)
            if label is not None:
                label.setText(str(value))
                label.setToolTip(str(value))

        base_diagnosis = end_info.get("diagnosis", "N/A")
        watch_diagnosis = result.get("diagnosis", "N/A")
        if self.adapter_diagnosis_box is not None:
            self.adapter_diagnosis_box.setPlainText(f"{base_diagnosis}\n\nCounter Watch:\n{watch_diagnosis}")

        error_delta = sum(value or 0 for value in (
            result.get("rx_errors_delta"),
            result.get("tx_errors_delta"),
            result.get("rx_discards_delta"),
            result.get("tx_discards_delta"),
        ))
        level = "error" if error_delta > 0 else "ok"
        self._set_adapter_status("Counter Watch completed.", level)

    def _set_adapter_counter_watch_error(self, message: str):
        if self.adapter_diagnosis_box is not None:
            self.adapter_diagnosis_box.setPlainText(message)
        self._set_adapter_status(message, "error")

    def _finish_adapter_counter_watch(self):
        if self.adapter_refresh_btn is not None:
            self.adapter_refresh_btn.setEnabled(True)
        if self.adapter_watch_run_btn is not None:
            self.adapter_watch_run_btn.setEnabled(True)
        if self.adapter_watch_stop_btn is not None:
            self.adapter_watch_stop_btn.setEnabled(False)
        if self.adapter_watch_duration_spin is not None:
            self.adapter_watch_duration_spin.setEnabled(True)

    def show_lan_throughput_window(self):
        """Open the iperf3 LAN throughput diagnostic window."""
        if self.lan_window is None:
            self.lan_window = QWidget(None, Qt.Window)
            self.lan_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.lan_window.setWindowTitle("LAN Throughput")
            self.lan_window.setMinimumSize(820, 650)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            client_group = QGroupBox("Client Test")
            client_grid = QGridLayout()
            client_grid.setHorizontalSpacing(8)
            client_grid.setVerticalSpacing(8)
            self.lan_host_input = QLineEdit()
            self.lan_host_input.setPlaceholderText("IP of another PC running LAN Throughput server")
            self.lan_host_input.setMinimumWidth(320)
            self.lan_port_spin = QSpinBox()
            self.lan_port_spin.setRange(1, 65535)
            self.lan_port_spin.setValue(5201)
            self.lan_duration_spin = QSpinBox()
            self.lan_duration_spin.setRange(1, 120)
            self.lan_duration_spin.setValue(10)
            self.lan_duration_spin.setSuffix(" sec")
            self.lan_direction_combo = QComboBox()
            self.lan_direction_combo.addItems(["Upload to server", "Download from server"])
            self.lan_run_btn = QPushButton("Run LAN Test")
            self.lan_run_btn.clicked.connect(self.start_lan_throughput_test)
            client_hint = QLabel(
                "Use another PC on the LAN as the server. Do not use the gateway/router IP unless it is actually running iperf3."
            )
            client_hint.setWordWrap(True)
            client_hint.setStyleSheet("QLabel { color: #5f6368; }")

            client_grid.addWidget(QLabel("Server"), 0, 0)
            client_grid.addWidget(self.lan_host_input, 0, 1, 1, 5)
            client_grid.addWidget(client_hint, 1, 0, 1, 7)
            client_grid.addWidget(QLabel("Port"), 2, 0)
            client_grid.addWidget(self.lan_port_spin, 2, 1)
            client_grid.addWidget(QLabel("Duration"), 2, 2)
            client_grid.addWidget(self.lan_duration_spin, 2, 3)
            client_grid.addWidget(QLabel("Direction"), 2, 4)
            client_grid.addWidget(self.lan_direction_combo, 2, 5)
            client_grid.addWidget(self.lan_run_btn, 2, 6)
            client_grid.setColumnStretch(1, 1)
            client_group.setLayout(client_grid)
            layout.addWidget(client_group)

            server_group = QGroupBox("Local Server")
            server_grid = QGridLayout()
            server_grid.setHorizontalSpacing(8)
            server_grid.setVerticalSpacing(8)
            self.lan_server_port_spin = QSpinBox()
            self.lan_server_port_spin.setRange(1, 65535)
            self.lan_server_port_spin.setValue(5201)
            self.lan_server_start_btn = QPushButton("Start Server")
            self.lan_server_start_btn.clicked.connect(self.start_lan_server)
            self.lan_server_stop_btn = QPushButton("Stop Server")
            self.lan_server_stop_btn.setEnabled(False)
            self.lan_server_stop_btn.clicked.connect(self.stop_lan_server)
            server_grid.addWidget(QLabel("Port"), 0, 0)
            server_grid.addWidget(self.lan_server_port_spin, 0, 1)
            server_grid.addWidget(self.lan_server_start_btn, 0, 2)
            server_grid.addWidget(self.lan_server_stop_btn, 0, 3)
            server_grid.addWidget(QLabel(f"This PC IP: {self.host_ip_label.text().strip() or get_local_ip()}"), 0, 4)
            server_grid.setColumnStretch(4, 1)
            server_group.setLayout(server_grid)
            layout.addWidget(server_group)

            self.lan_status_label = QLabel("Ready")
            self.lan_status_label.setAlignment(Qt.AlignCenter)
            self.lan_status_label.setWordWrap(True)
            self.lan_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.lan_status_label)

            results_group = QGroupBox("Results")
            results_grid = QGridLayout()
            results_grid.setHorizontalSpacing(12)
            results_grid.setVerticalSpacing(8)
            result_fields = [
                ("throughput", "Throughput"),
                ("direction", "Direction"),
                ("server", "Server"),
                ("duration", "Duration"),
                ("transferred", "Transferred"),
                ("retransmits", "Retransmits"),
            ]
            self.lan_result_labels = {}
            for row, (key, label_text) in enumerate(result_fields):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.lan_result_labels[key] = value
                results_grid.addWidget(name, row // 2, (row % 2) * 2)
                results_grid.addWidget(value, row // 2, (row % 2) * 2 + 1)
            results_grid.setColumnStretch(1, 1)
            results_grid.setColumnStretch(3, 1)
            results_group.setLayout(results_grid)
            layout.addWidget(results_group)

            diagnosis_group = QGroupBox("Diagnosis")
            diagnosis_layout = QVBoxLayout()
            self.lan_diagnosis_box = QTextEdit()
            self.lan_diagnosis_box.setReadOnly(True)
            self.lan_diagnosis_box.setMinimumHeight(90)
            self.lan_diagnosis_box.setLineWrapMode(QTextEdit.WidgetWidth)
            diagnosis_layout.addWidget(self.lan_diagnosis_box)
            diagnosis_group.setLayout(diagnosis_layout)
            layout.addWidget(diagnosis_group)

            raw_group = QGroupBox("Raw iperf3 JSON")
            raw_layout = QVBoxLayout()
            self.lan_raw_box = QTextEdit()
            self.lan_raw_box.setReadOnly(True)
            self.lan_raw_box.setMinimumHeight(130)
            self.lan_raw_box.setLineWrapMode(QTextEdit.NoWrap)
            raw_layout.addWidget(self.lan_raw_box)
            raw_group.setLayout(raw_layout)
            layout.addWidget(raw_group, 1)

            self.lan_window.setLayout(layout)

        self.lan_window.show()
        self.lan_window.raise_()
        self.lan_window.activateWindow()

    def _find_iperf3_executable(self):
        exe_name = "iperf3.exe" if platform.system() == "Windows" else "iperf3"
        for root in self._speedtest_candidate_roots():
            for rel in (
                os.path.join("tools", "iperf3", exe_name),
                os.path.join("bin", exe_name),
                exe_name,
            ):
                candidate = os.path.join(root, rel)
                if os.path.isfile(candidate):
                    return candidate
        return shutil.which("iperf3")

    def _set_lan_status(self, message: str, level="info"):
        if self.lan_status_label is None:
            return
        styles = {
            "info": ("#eef2f7", "#3c4043", "#b7c0cc"),
            "running": ("#fff4ce", "#8a5a00", "#d8b756"),
            "ok": ("#e6f4ea", "#137333", "#8abf9a"),
            "error": ("#fce8e6", "#a50e0e", "#d28b82"),
        }
        bg, fg, border = styles.get(level, styles["info"])
        self.lan_status_label.setText(message)
        self.lan_status_label.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {fg}; border: 1px solid {border}; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

    def start_lan_throughput_test(self):
        if self.lan_throughput_worker is not None and self.lan_throughput_worker.isRunning():
            return
        executable = self._find_iperf3_executable()
        if not executable:
            self._set_lan_status(
                "iperf3 not found. Put iperf3.exe in tools/iperf3 or install iperf3 so it is available on PATH.",
                "error",
            )
            return
        host = self.lan_host_input.text().strip() if self.lan_host_input is not None else ""
        if not host:
            QMessageBox.warning(self, "LAN Throughput Error", "Enter an iperf3 server host.")
            return

        if self.lan_run_btn is not None:
            self.lan_run_btn.setEnabled(False)
        for label in self.lan_result_labels.values():
            label.setText("N/A")
        if self.lan_diagnosis_box is not None:
            self.lan_diagnosis_box.clear()
        if self.lan_raw_box is not None:
            self.lan_raw_box.clear()
        self._set_lan_status("Running LAN throughput test...", "running")

        self.lan_throughput_worker = LanThroughputWorker(
            executable,
            host,
            port=self.lan_port_spin.value(),
            duration=self.lan_duration_spin.value(),
            reverse=self.lan_direction_combo.currentText().startswith("Download"),
        )
        self.lan_throughput_worker.result_ready.connect(self._set_lan_result)
        self.lan_throughput_worker.error_ready.connect(self._set_lan_error)
        self.lan_throughput_worker.finished.connect(self._finish_lan_test)
        self.lan_throughput_worker.finished.connect(self.lan_throughput_worker.deleteLater)
        self.lan_throughput_worker.finished.connect(lambda: setattr(self, "lan_throughput_worker", None))
        self.lan_throughput_worker.start()

    def _set_lan_result(self, result: dict):
        self.lan_last_result = result
        values = {
            "throughput": result.get("throughput", "N/A"),
            "direction": result.get("direction", "N/A"),
            "server": f"{result.get('host', 'N/A')}:{result.get('port', 'N/A')}",
            "duration": result.get("seconds", "N/A"),
            "transferred": result.get("transferred", "N/A"),
            "retransmits": result.get("retransmits", "N/A"),
        }
        for key, value in values.items():
            if key in self.lan_result_labels:
                self.lan_result_labels[key].setText(str(value))
        if self.lan_diagnosis_box is not None:
            self.lan_diagnosis_box.setPlainText(result.get("diagnosis", "N/A"))
        if self.lan_raw_box is not None:
            self.lan_raw_box.setPlainText(result.get("raw", ""))
        self._set_lan_status("LAN throughput test completed.", "ok")

    def _set_lan_error(self, message: str):
        self._set_lan_status(f"LAN throughput failed: {message}", "error")
        if self.lan_diagnosis_box is not None:
            self.lan_diagnosis_box.setPlainText(
                "Check that iperf3 is installed on both machines, the remote server is running, "
                "Windows Firewall allows the selected port, and both devices are on the expected LAN path."
            )

    def _finish_lan_test(self):
        if self.lan_run_btn is not None:
            self.lan_run_btn.setEnabled(True)

    def start_lan_server(self):
        if self.lan_server_process is not None and self.lan_server_process.poll() is None:
            self._set_lan_status("iperf3 server is already running.", "info")
            return
        executable = self._find_iperf3_executable()
        if not executable:
            self._set_lan_status(
                "iperf3 not found. Put iperf3.exe in tools/iperf3 or install iperf3 so it is available on PATH.",
                "error",
            )
            return
        port = self.lan_server_port_spin.value() if self.lan_server_port_spin is not None else 5201
        cmd = [executable, "-s", "-p", str(port)]
        try:
            kwargs = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if platform.system() == "Windows" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            self.lan_server_process = subprocess.Popen(cmd, **kwargs)
        except OSError as e:
            self._set_lan_status(f"Could not start iperf3 server: {e}", "error")
            return

        if self.lan_server_start_btn is not None:
            self.lan_server_start_btn.setEnabled(False)
        if self.lan_server_stop_btn is not None:
            self.lan_server_stop_btn.setEnabled(True)
        self._set_lan_status(f"iperf3 server running on port {port}. Use this PC IP from another machine.", "ok")

    def stop_lan_server(self):
        proc = self.lan_server_process
        self.lan_server_process = None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if self.lan_server_start_btn is not None:
            self.lan_server_start_btn.setEnabled(True)
        if self.lan_server_stop_btn is not None:
            self.lan_server_stop_btn.setEnabled(False)
        self._set_lan_status("iperf3 server stopped.", "info")

    def show_gateway_stability_window(self):
        """Open the gateway latency/loss stability monitor."""
        if self.gateway_window is None:
            self.gateway_window = QWidget(None, Qt.Window)
            self.gateway_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.gateway_window.setWindowTitle("Gateway Stability")
            self.gateway_window.setMinimumSize(820, 620)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls_group = QGroupBox("Monitor")
            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.gateway_target_input = QLineEdit(self._default_gateway_target())
            self.gateway_target_input.setPlaceholderText("Default gateway IP")
            self.gateway_target_input.setMinimumWidth(260)
            self.gateway_count_spin = QSpinBox()
            self.gateway_count_spin.setRange(1, 10000)
            self.gateway_count_spin.setValue(60)
            self.gateway_interval_spin = QSpinBox()
            self.gateway_interval_spin.setRange(100, 10000)
            self.gateway_interval_spin.setSingleStep(100)
            self.gateway_interval_spin.setValue(1000)
            self.gateway_interval_spin.setSuffix(" ms")
            self.gateway_timeout_spin = QSpinBox()
            self.gateway_timeout_spin.setRange(250, 10000)
            self.gateway_timeout_spin.setSingleStep(250)
            self.gateway_timeout_spin.setValue(1000)
            self.gateway_timeout_spin.setSuffix(" ms")
            self.gateway_spike_spin = QSpinBox()
            self.gateway_spike_spin.setRange(1, 1000)
            self.gateway_spike_spin.setValue(20)
            self.gateway_spike_spin.setSuffix(" ms")
            self.gateway_start_btn = QPushButton("Start Monitor")
            self.gateway_start_btn.clicked.connect(self.start_gateway_stability)
            self.gateway_stop_btn = QPushButton("Stop")
            self.gateway_stop_btn.setEnabled(False)
            self.gateway_stop_btn.clicked.connect(self.stop_gateway_stability)

            controls.addWidget(QLabel("Target"), 0, 0)
            controls.addWidget(self.gateway_target_input, 0, 1, 1, 5)
            controls.addWidget(QLabel("Samples"), 1, 0)
            controls.addWidget(self.gateway_count_spin, 1, 1)
            controls.addWidget(QLabel("Interval"), 1, 2)
            controls.addWidget(self.gateway_interval_spin, 1, 3)
            controls.addWidget(QLabel("Timeout"), 1, 4)
            controls.addWidget(self.gateway_timeout_spin, 1, 5)
            controls.addWidget(QLabel("Spike over"), 2, 0)
            controls.addWidget(self.gateway_spike_spin, 2, 1)
            controls.addWidget(self.gateway_start_btn, 2, 4)
            controls.addWidget(self.gateway_stop_btn, 2, 5)
            controls.setColumnStretch(1, 1)
            controls_group.setLayout(controls)
            layout.addWidget(controls_group)

            self.gateway_status_label = QLabel("Ready")
            self.gateway_status_label.setAlignment(Qt.AlignCenter)
            self.gateway_status_label.setWordWrap(True)
            self.gateway_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.gateway_status_label)

            results_group = QGroupBox("Results")
            results = QGridLayout()
            results.setHorizontalSpacing(12)
            results.setVerticalSpacing(8)
            fields = [
                ("current", "Current"),
                ("average", "Average"),
                ("maximum", "Maximum"),
                ("jitter", "Jitter"),
                ("loss", "Packet Loss"),
                ("spikes", "Spikes"),
                ("sent", "Sent"),
                ("received", "Received"),
            ]
            self.gateway_result_labels = {}
            for row, (key, label_text) in enumerate(fields):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.gateway_result_labels[key] = value
                results.addWidget(name, row // 2, (row % 2) * 2)
                results.addWidget(value, row // 2, (row % 2) * 2 + 1)
            results.setColumnStretch(1, 1)
            results.setColumnStretch(3, 1)
            results_group.setLayout(results)
            layout.addWidget(results_group)

            diagnosis_group = QGroupBox("Diagnosis")
            diagnosis_layout = QVBoxLayout()
            self.gateway_diagnosis_box = QTextEdit()
            self.gateway_diagnosis_box.setReadOnly(True)
            self.gateway_diagnosis_box.setMinimumHeight(90)
            self.gateway_diagnosis_box.setLineWrapMode(QTextEdit.WidgetWidth)
            diagnosis_layout.addWidget(self.gateway_diagnosis_box)
            diagnosis_group.setLayout(diagnosis_layout)
            layout.addWidget(diagnosis_group)

            raw_group = QGroupBox("Ping Log")
            raw_layout = QVBoxLayout()
            self.gateway_raw_box = QTextEdit()
            self.gateway_raw_box.setReadOnly(True)
            self.gateway_raw_box.setMinimumHeight(160)
            self.gateway_raw_box.setLineWrapMode(QTextEdit.WidgetWidth)
            raw_layout.addWidget(self.gateway_raw_box)
            raw_group.setLayout(raw_layout)
            layout.addWidget(raw_group, 1)

            self.gateway_window.setLayout(layout)

        if self.gateway_target_input is not None and not self.gateway_target_input.text().strip():
            self.gateway_target_input.setText(self._default_gateway_target())
        self.gateway_window.show()
        self.gateway_window.raise_()
        self.gateway_window.activateWindow()

    def _default_gateway_target(self):
        for value in (
            self.gateway_label.text().strip() if hasattr(self, "gateway_label") else "",
            get_default_gateway(),
        ):
            if value and value not in ("Loading...", "N/A"):
                return value
        return ""

    def _set_gateway_status(self, message: str, level="info"):
        if self.gateway_status_label is None:
            return
        styles = {
            "info": ("#eef2f7", "#3c4043", "#b7c0cc"),
            "running": ("#fff4ce", "#8a5a00", "#d8b756"),
            "ok": ("#e6f4ea", "#137333", "#8abf9a"),
            "error": ("#fce8e6", "#a50e0e", "#d28b82"),
        }
        bg, fg, border = styles.get(level, styles["info"])
        self.gateway_status_label.setText(message)
        self.gateway_status_label.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {fg}; border: 1px solid {border}; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

    def start_gateway_stability(self):
        if self.gateway_stability_worker is not None and self.gateway_stability_worker.isRunning():
            return
        target = self.gateway_target_input.text().strip() if self.gateway_target_input is not None else ""
        if not target:
            QMessageBox.warning(self, "Gateway Stability Error", "Enter a gateway or first-hop target.")
            return
        for label in self.gateway_result_labels.values():
            label.setText("N/A")
        if self.gateway_diagnosis_box is not None:
            self.gateway_diagnosis_box.clear()
        if self.gateway_raw_box is not None:
            self.gateway_raw_box.clear()
        self.gateway_last_stats = None
        self.gateway_start_btn.setEnabled(False)
        self.gateway_stop_btn.setEnabled(True)
        self._set_gateway_status("Monitoring gateway stability...", "running")

        self.gateway_stability_worker = GatewayStabilityWorker(
            target,
            count=self.gateway_count_spin.value(),
            interval_ms=self.gateway_interval_spin.value(),
            timeout_ms=self.gateway_timeout_spin.value(),
            spike_threshold_ms=self.gateway_spike_spin.value(),
        )
        self.gateway_stability_worker.sample_ready.connect(self._add_gateway_sample)
        self.gateway_stability_worker.stats_ready.connect(self._set_gateway_stats)
        self.gateway_stability_worker.finished.connect(self._finish_gateway_stability)
        self.gateway_stability_worker.finished.connect(self.gateway_stability_worker.deleteLater)
        self.gateway_stability_worker.finished.connect(lambda: setattr(self, "gateway_stability_worker", None))
        self.gateway_stability_worker.start()

    def stop_gateway_stability(self):
        if self.gateway_stability_worker is not None and self.gateway_stability_worker.isRunning():
            self.gateway_stability_worker.stop()
            self._set_gateway_status("Stopping gateway monitor...", "running")

    def _add_gateway_sample(self, sample: dict):
        if self.gateway_raw_box is None:
            return
        raw = sample.get("raw", "").strip()
        self.gateway_raw_box.append(f"Sample {sample.get('index')}: {sample.get('status')}")
        if raw:
            self.gateway_raw_box.append(raw)
        self.gateway_raw_box.append("")

    def _set_gateway_stats(self, stats: dict):
        self.gateway_last_stats = stats
        values = {
            "current": "Timeout" if stats.get("current_ms") is None else f"{stats.get('current_ms'):.1f} ms",
            "average": "N/A" if stats.get("avg_ms") is None else f"{stats.get('avg_ms'):.1f} ms",
            "maximum": "N/A" if stats.get("max_ms") is None else f"{stats.get('max_ms'):.1f} ms",
            "jitter": "N/A" if stats.get("jitter_ms") is None else f"{stats.get('jitter_ms'):.1f} ms",
            "loss": f"{stats.get('loss_pct', 0):.1f}%",
            "spikes": f"{stats.get('spike_count', 0)} over {stats.get('spike_threshold_ms', 0):.0f} ms",
            "sent": str(stats.get("sent", 0)),
            "received": str(stats.get("received", 0)),
        }
        for key, value in values.items():
            if key in self.gateway_result_labels:
                self.gateway_result_labels[key].setText(value)
        if self.gateway_diagnosis_box is not None:
            self.gateway_diagnosis_box.setPlainText(stats.get("diagnosis", "N/A"))

    def _finish_gateway_stability(self):
        if self.gateway_start_btn is not None:
            self.gateway_start_btn.setEnabled(True)
        if self.gateway_stop_btn is not None:
            self.gateway_stop_btn.setEnabled(False)
        if self.gateway_last_stats is not None:
            level = "ok" if self.gateway_last_stats.get("loss_pct", 0) == 0 and self.gateway_last_stats.get("spike_count", 0) == 0 else "error"
            self._set_gateway_status("Gateway stability monitor completed.", level)
        else:
            self._set_gateway_status("Gateway stability monitor stopped.", "info")

    def show_route_health_window(self):
        """Open route/hop health diagnostics during speed-test load."""
        if self.route_window is None:
            self.route_window = QWidget(None, Qt.Window)
            self.route_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.route_window.setWindowTitle("Route Health")
            self.route_window.setMinimumSize(900, 700)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls_group = QGroupBox("Test")
            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.route_gateway_input = QLineEdit(self._default_gateway_target())
            self.route_gateway_input.setPlaceholderText("Default gateway")
            self.route_isp_input = QLineEdit()
            self.route_isp_input.setPlaceholderText("Auto-detect if blank")
            self.route_public_input = QLineEdit("1.1.1.1")
            self.route_public_input.setPlaceholderText("Public target")
            self.route_duration_spin = QSpinBox()
            self.route_duration_spin.setRange(5, 60)
            self.route_duration_spin.setValue(15)
            self.route_duration_spin.setSuffix(" sec")
            self.route_interval_spin = QSpinBox()
            self.route_interval_spin.setRange(250, 5000)
            self.route_interval_spin.setSingleStep(250)
            self.route_interval_spin.setValue(1000)
            self.route_interval_spin.setSuffix(" ms")
            self.route_timeout_spin = QSpinBox()
            self.route_timeout_spin.setRange(250, 10000)
            self.route_timeout_spin.setSingleStep(250)
            self.route_timeout_spin.setValue(1000)
            self.route_timeout_spin.setSuffix(" ms")
            self.route_spike_spin = QSpinBox()
            self.route_spike_spin.setRange(1, 1000)
            self.route_spike_spin.setValue(75)
            self.route_spike_spin.setSuffix(" ms")
            self.route_run_btn = QPushButton("Run Route Health")
            self.route_run_btn.clicked.connect(self.start_route_health_test)
            self.route_stop_btn = QPushButton("Stop")
            self.route_stop_btn.setEnabled(False)
            self.route_stop_btn.clicked.connect(self.stop_route_health_test)

            controls.addWidget(QLabel("Gateway"), 0, 0)
            controls.addWidget(self.route_gateway_input, 0, 1)
            controls.addWidget(QLabel("ISP hop"), 0, 2)
            controls.addWidget(self.route_isp_input, 0, 3)
            controls.addWidget(QLabel("Public target"), 0, 4)
            controls.addWidget(self.route_public_input, 0, 5)
            controls.addWidget(QLabel("Load duration"), 1, 0)
            controls.addWidget(self.route_duration_spin, 1, 1)
            controls.addWidget(QLabel("Ping interval"), 1, 2)
            controls.addWidget(self.route_interval_spin, 1, 3)
            controls.addWidget(QLabel("Timeout"), 1, 4)
            controls.addWidget(self.route_timeout_spin, 1, 5)
            controls.addWidget(QLabel("Spike over"), 2, 0)
            controls.addWidget(self.route_spike_spin, 2, 1)
            controls.addWidget(self.route_run_btn, 2, 4)
            controls.addWidget(self.route_stop_btn, 2, 5)
            controls.setColumnStretch(1, 1)
            controls.setColumnStretch(3, 1)
            controls.setColumnStretch(5, 1)
            controls_group.setLayout(controls)
            layout.addWidget(controls_group)

            self.route_status_label = QLabel("Ready")
            self.route_status_label.setAlignment(Qt.AlignCenter)
            self.route_status_label.setWordWrap(True)
            self.route_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.route_status_label)

            summary_group = QGroupBox("Speed Load")
            summary = QGridLayout()
            summary.setHorizontalSpacing(12)
            summary.setVerticalSpacing(8)
            self.route_summary_labels = {}
            for row, (key, label_text) in enumerate((("download", "Download"), ("upload", "Upload"), ("note", "Detection"))):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.route_summary_labels[key] = value
                summary.addWidget(name, row, 0)
                summary.addWidget(value, row, 1)
            summary.setColumnStretch(1, 1)
            summary_group.setLayout(summary)
            layout.addWidget(summary_group)

            self.route_table = QTableWidget(0, 9)
            self.route_table.setHorizontalHeaderLabels([
                "Path", "Target", "Sent", "Received", "Loss", "Avg", "Max", "Jitter", "Spikes"
            ])
            self.route_table.verticalHeader().setVisible(False)
            self.route_table.setAlternatingRowColors(True)
            rh = self.route_table.horizontalHeader()
            for col in range(0, 9):
                rh.setSectionResizeMode(col, QHeaderView.ResizeToContents)
            rh.setSectionResizeMode(1, QHeaderView.Stretch)
            layout.addWidget(self.route_table)

            diagnosis_group = QGroupBox("Diagnosis")
            diagnosis_layout = QVBoxLayout()
            self.route_diagnosis_box = QTextEdit()
            self.route_diagnosis_box.setReadOnly(True)
            self.route_diagnosis_box.setMinimumHeight(90)
            self.route_diagnosis_box.setLineWrapMode(QTextEdit.WidgetWidth)
            diagnosis_layout.addWidget(self.route_diagnosis_box)
            diagnosis_group.setLayout(diagnosis_layout)
            layout.addWidget(diagnosis_group)

            raw_group = QGroupBox("Ping Log / Speed Test JSON")
            raw_layout = QVBoxLayout()
            self.route_raw_box = QTextEdit()
            self.route_raw_box.setReadOnly(True)
            self.route_raw_box.setMinimumHeight(150)
            self.route_raw_box.setLineWrapMode(QTextEdit.WidgetWidth)
            raw_layout.addWidget(self.route_raw_box)
            raw_group.setLayout(raw_layout)
            layout.addWidget(raw_group, 1)

            self.route_window.setLayout(layout)

        if self.route_gateway_input is not None and not self.route_gateway_input.text().strip():
            self.route_gateway_input.setText(self._default_gateway_target())
        self.route_window.show()
        self.route_window.raise_()
        self.route_window.activateWindow()

    def _set_route_status(self, message: str, level="info"):
        if self.route_status_label is None:
            return
        styles = {
            "info": ("#eef2f7", "#3c4043", "#b7c0cc"),
            "running": ("#fff4ce", "#8a5a00", "#d8b756"),
            "ok": ("#e6f4ea", "#137333", "#8abf9a"),
            "error": ("#fce8e6", "#a50e0e", "#d28b82"),
        }
        bg, fg, border = styles.get(level, styles["info"])
        self.route_status_label.setText(message)
        self.route_status_label.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {fg}; border: 1px solid {border}; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

    def start_route_health_test(self):
        if self.route_health_worker is not None and self.route_health_worker.isRunning():
            return
        executable = self._find_speedtest_executable()
        if not executable:
            self._set_route_status(
                "LibreSpeed CLI not found. Put librespeed-cli.exe in tools/librespeed or install librespeed-cli on PATH.",
                "error",
            )
            return
        gateway = self.route_gateway_input.text().strip() if self.route_gateway_input is not None else ""
        public_target = self.route_public_input.text().strip() if self.route_public_input is not None else ""
        if not gateway or not public_target:
            QMessageBox.warning(self, "Route Health Error", "Enter a gateway and public target.")
            return

        self.route_last_result = None
        self.route_last_error = None
        for label in self.route_summary_labels.values():
            label.setText("N/A")
        if self.route_table is not None:
            self.route_table.setRowCount(0)
        if self.route_diagnosis_box is not None:
            self.route_diagnosis_box.clear()
        if self.route_raw_box is not None:
            self.route_raw_box.clear()
        self.route_run_btn.setEnabled(False)
        self.route_stop_btn.setEnabled(True)
        self._set_route_status("Starting route health test...", "running")

        self.route_health_worker = RouteHealthWorker(
            executable,
            gateway,
            self.route_isp_input.text().strip() if self.route_isp_input is not None else "",
            public_target,
            duration=self.route_duration_spin.value(),
            interval_ms=self.route_interval_spin.value(),
            timeout_ms=self.route_timeout_spin.value(),
            spike_threshold_ms=self.route_spike_spin.value(),
        )
        self.route_health_worker.phase_ready.connect(lambda message: self._set_route_status(message, "running"))
        self.route_health_worker.sample_ready.connect(self._add_route_health_sample)
        self.route_health_worker.result_ready.connect(self._set_route_health_result)
        self.route_health_worker.error_ready.connect(self._set_route_health_error)
        self.route_health_worker.finished.connect(self._finish_route_health_test)
        self.route_health_worker.finished.connect(self.route_health_worker.deleteLater)
        self.route_health_worker.finished.connect(lambda: setattr(self, "route_health_worker", None))
        self.route_health_worker.start()

    def stop_route_health_test(self):
        if self.route_health_worker is not None and self.route_health_worker.isRunning():
            self.route_health_worker.stop()
            self._set_route_status("Stopping route health test...", "running")

    def _add_route_health_sample(self, sample: dict):
        if self.route_raw_box is None:
            return
        self.route_raw_box.append(
            f"{sample.get('label')} {sample.get('target')} sample {sample.get('index')}: {sample.get('status')}"
        )

    def _set_route_health_result(self, result: dict):
        self.route_last_result = result
        values = {
            "download": result.get("download", "N/A"),
            "upload": result.get("upload", "N/A"),
            "note": result.get("note", "N/A") or "N/A",
        }
        for key, value in values.items():
            label = self.route_summary_labels.get(key)
            if label is not None:
                label.setText(str(value))

        paths = result.get("paths", {})
        ordered = [("gateway", "Gateway"), ("isp", "ISP first hop"), ("public", "Public target")]
        if self.route_table is not None:
            self.route_table.setRowCount(len(ordered))
            for row, (key, fallback_label) in enumerate(ordered):
                stats = paths.get(key, {})
                def ms_text(name):
                    value = stats.get(name)
                    return "N/A" if value is None else f"{value:.1f} ms"
                cells = [
                    stats.get("label", fallback_label),
                    stats.get("target", "N/A"),
                    str(stats.get("sent", 0)),
                    str(stats.get("received", 0)),
                    f"{stats.get('loss_pct', 0):.1f}%",
                    ms_text("avg_ms"),
                    ms_text("max_ms"),
                    ms_text("jitter_ms"),
                    f"{stats.get('spike_count', 0)} over {stats.get('spike_threshold_ms', 0):.0f} ms",
                ]
                for col, text in enumerate(cells):
                    self.route_table.setItem(row, col, QTableWidgetItem(str(text)))
            self.route_table.resizeRowsToContents()

        if self.route_diagnosis_box is not None:
            self.route_diagnosis_box.setPlainText(result.get("diagnosis", "N/A"))
        if self.route_raw_box is not None:
            self.route_raw_box.append("")
            self.route_raw_box.append("LibreSpeed JSON:")
            self.route_raw_box.append(result.get("speed_raw", ""))

        problem = any(
            stats.get("loss_pct", 0) > 0 or stats.get("spike_count", 0) > 0
            for stats in paths.values()
        )
        self._set_route_status("Route health test completed.", "error" if problem else "ok")

    def _set_route_health_error(self, message: str):
        self.route_last_error = message
        self._set_route_status(f"Route health failed: {message}", "error")
        if self.route_diagnosis_box is not None:
            self.route_diagnosis_box.setPlainText(
                "Check that LibreSpeed CLI is available, the gateway/public targets respond to ping, and traceroute is allowed."
            )

    def _finish_route_health_test(self):
        if self.route_run_btn is not None:
            self.route_run_btn.setEnabled(True)
        if self.route_stop_btn is not None:
            self.route_stop_btn.setEnabled(False)
        if self.route_last_result is None and self.route_last_error is None:
            self._set_route_status("Route health test stopped.", "info")

    def show_loaded_latency_window(self):
        """Open the bufferbloat / loaded latency diagnostic window."""
        if self.loaded_window is None:
            self.loaded_window = QWidget(None, Qt.Window)
            self.loaded_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.loaded_window.setWindowTitle("Loaded Latency")
            self.loaded_window.setMinimumSize(820, 650)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls_group = QGroupBox("Test")
            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.loaded_target_input = QLineEdit("1.1.1.1")
            self.loaded_target_input.setPlaceholderText("Ping target during test")
            self.loaded_target_input.setMinimumWidth(260)
            self.loaded_baseline_spin = QSpinBox()
            self.loaded_baseline_spin.setRange(3, 100)
            self.loaded_baseline_spin.setValue(10)
            self.loaded_duration_spin = QSpinBox()
            self.loaded_duration_spin.setRange(5, 60)
            self.loaded_duration_spin.setValue(15)
            self.loaded_duration_spin.setSuffix(" sec")
            self.loaded_interval_spin = QSpinBox()
            self.loaded_interval_spin.setRange(250, 5000)
            self.loaded_interval_spin.setSingleStep(250)
            self.loaded_interval_spin.setValue(1000)
            self.loaded_interval_spin.setSuffix(" ms")
            self.loaded_timeout_spin = QSpinBox()
            self.loaded_timeout_spin.setRange(250, 10000)
            self.loaded_timeout_spin.setSingleStep(250)
            self.loaded_timeout_spin.setValue(1000)
            self.loaded_timeout_spin.setSuffix(" ms")
            self.loaded_start_btn = QPushButton("Run Loaded Latency")
            self.loaded_start_btn.clicked.connect(self.start_loaded_latency_test)
            self.loaded_stop_btn = QPushButton("Stop")
            self.loaded_stop_btn.setEnabled(False)
            self.loaded_stop_btn.clicked.connect(self.stop_loaded_latency_test)

            controls.addWidget(QLabel("Ping Target"), 0, 0)
            controls.addWidget(self.loaded_target_input, 0, 1, 1, 5)
            controls.addWidget(QLabel("Baseline samples"), 1, 0)
            controls.addWidget(self.loaded_baseline_spin, 1, 1)
            controls.addWidget(QLabel("Load duration"), 1, 2)
            controls.addWidget(self.loaded_duration_spin, 1, 3)
            controls.addWidget(QLabel("Ping interval"), 1, 4)
            controls.addWidget(self.loaded_interval_spin, 1, 5)
            controls.addWidget(QLabel("Ping timeout"), 2, 0)
            controls.addWidget(self.loaded_timeout_spin, 2, 1)
            controls.addWidget(self.loaded_start_btn, 2, 4)
            controls.addWidget(self.loaded_stop_btn, 2, 5)
            controls.setColumnStretch(1, 1)
            controls_group.setLayout(controls)
            layout.addWidget(controls_group)

            self.loaded_status_label = QLabel("Ready")
            self.loaded_status_label.setAlignment(Qt.AlignCenter)
            self.loaded_status_label.setWordWrap(True)
            self.loaded_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.loaded_status_label)

            results_group = QGroupBox("Results")
            results = QGridLayout()
            results.setHorizontalSpacing(12)
            results.setVerticalSpacing(8)
            fields = [
                ("idle_avg", "Idle Avg"),
                ("loaded_avg", "Loaded Avg"),
                ("increase", "Increase"),
                ("loaded_max", "Loaded Max"),
                ("loaded_jitter", "Loaded Jitter"),
                ("loaded_loss", "Loaded Loss"),
                ("download", "Download"),
                ("upload", "Upload"),
            ]
            self.loaded_result_labels = {}
            for row, (key, label_text) in enumerate(fields):
                name = QLabel(label_text)
                value = QLabel("N/A")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)
                value.setMinimumHeight(26)
                value.setStyleSheet(
                    "QLabel { background: #ffffff; border: 1px solid #d4d7dc; "
                    "border-radius: 3px; padding: 4px 6px; }"
                )
                self.loaded_result_labels[key] = value
                results.addWidget(name, row // 2, (row % 2) * 2)
                results.addWidget(value, row // 2, (row % 2) * 2 + 1)
            results.setColumnStretch(1, 1)
            results.setColumnStretch(3, 1)
            results_group.setLayout(results)
            layout.addWidget(results_group)

            diagnosis_group = QGroupBox("Diagnosis")
            diagnosis_layout = QVBoxLayout()
            self.loaded_diagnosis_box = QTextEdit()
            self.loaded_diagnosis_box.setReadOnly(True)
            self.loaded_diagnosis_box.setMinimumHeight(90)
            self.loaded_diagnosis_box.setLineWrapMode(QTextEdit.WidgetWidth)
            diagnosis_layout.addWidget(self.loaded_diagnosis_box)
            diagnosis_group.setLayout(diagnosis_layout)
            layout.addWidget(diagnosis_group)

            raw_group = QGroupBox("Ping Log / Speed Test JSON")
            raw_layout = QVBoxLayout()
            self.loaded_raw_box = QTextEdit()
            self.loaded_raw_box.setReadOnly(True)
            self.loaded_raw_box.setMinimumHeight(170)
            self.loaded_raw_box.setLineWrapMode(QTextEdit.WidgetWidth)
            raw_layout.addWidget(self.loaded_raw_box)
            raw_group.setLayout(raw_layout)
            layout.addWidget(raw_group, 1)

            self.loaded_window.setLayout(layout)

        self.loaded_window.show()
        self.loaded_window.raise_()
        self.loaded_window.activateWindow()

    def _set_loaded_status(self, message: str, level="info"):
        if self.loaded_status_label is None:
            return
        styles = {
            "info": ("#eef2f7", "#3c4043", "#b7c0cc"),
            "running": ("#fff4ce", "#8a5a00", "#d8b756"),
            "ok": ("#e6f4ea", "#137333", "#8abf9a"),
            "error": ("#fce8e6", "#a50e0e", "#d28b82"),
        }
        bg, fg, border = styles.get(level, styles["info"])
        self.loaded_status_label.setText(message)
        self.loaded_status_label.setStyleSheet(
            f"QLabel {{ background: {bg}; color: {fg}; border: 1px solid {border}; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

    def start_loaded_latency_test(self):
        if self.loaded_latency_worker is not None and self.loaded_latency_worker.isRunning():
            return
        executable = self._find_speedtest_executable()
        if not executable:
            self._set_loaded_status(
                "LibreSpeed CLI not found. Put librespeed-cli.exe in tools/librespeed or install librespeed-cli on PATH.",
                "error",
            )
            return
        target = self.loaded_target_input.text().strip() if self.loaded_target_input is not None else ""
        if not target:
            QMessageBox.warning(self, "Loaded Latency Error", "Enter a ping target.")
            return

        for label in self.loaded_result_labels.values():
            label.setText("N/A")
        if self.loaded_diagnosis_box is not None:
            self.loaded_diagnosis_box.clear()
        if self.loaded_raw_box is not None:
            self.loaded_raw_box.clear()
        self.loaded_last_result = None
        self.loaded_start_btn.setEnabled(False)
        self.loaded_stop_btn.setEnabled(True)
        self._set_loaded_status("Starting loaded latency test...", "running")

        self.loaded_latency_worker = LoadedLatencyWorker(
            executable,
            target,
            baseline_count=self.loaded_baseline_spin.value(),
            load_duration=self.loaded_duration_spin.value(),
            interval_ms=self.loaded_interval_spin.value(),
            timeout_ms=self.loaded_timeout_spin.value(),
        )
        self.loaded_latency_worker.phase_ready.connect(lambda message: self._set_loaded_status(message, "running"))
        self.loaded_latency_worker.sample_ready.connect(self._add_loaded_latency_sample)
        self.loaded_latency_worker.result_ready.connect(self._set_loaded_latency_result)
        self.loaded_latency_worker.error_ready.connect(self._set_loaded_latency_error)
        self.loaded_latency_worker.finished.connect(self._finish_loaded_latency_test)
        self.loaded_latency_worker.finished.connect(self.loaded_latency_worker.deleteLater)
        self.loaded_latency_worker.finished.connect(lambda: setattr(self, "loaded_latency_worker", None))
        self.loaded_latency_worker.start()

    def stop_loaded_latency_test(self):
        if self.loaded_latency_worker is not None and self.loaded_latency_worker.isRunning():
            self.loaded_latency_worker.stop()
            self._set_loaded_status("Stopping loaded latency test...", "running")

    def _add_loaded_latency_sample(self, sample: dict):
        if self.loaded_raw_box is None:
            return
        self.loaded_raw_box.append(
            f"{sample.get('phase', '').title()} sample {sample.get('index')}: {sample.get('status')}"
        )

    def _set_loaded_latency_result(self, result: dict):
        self.loaded_last_result = result
        idle = result.get("idle", {})
        loaded = result.get("loaded", {})
        increase = result.get("increase_ms")
        values = {
            "idle_avg": "N/A" if idle.get("avg_ms") is None else f"{idle.get('avg_ms'):.1f} ms",
            "loaded_avg": "N/A" if loaded.get("avg_ms") is None else f"{loaded.get('avg_ms'):.1f} ms",
            "increase": "N/A" if increase is None else f"+{increase:.1f} ms",
            "loaded_max": "N/A" if loaded.get("max_ms") is None else f"{loaded.get('max_ms'):.1f} ms",
            "loaded_jitter": "N/A" if loaded.get("jitter_ms") is None else f"{loaded.get('jitter_ms'):.1f} ms",
            "loaded_loss": f"{loaded.get('loss_pct', 0):.1f}%",
            "download": result.get("download", "N/A"),
            "upload": result.get("upload", "N/A"),
        }
        for key, value in values.items():
            if key in self.loaded_result_labels:
                self.loaded_result_labels[key].setText(value)
        if self.loaded_diagnosis_box is not None:
            self.loaded_diagnosis_box.setPlainText(result.get("diagnosis", "N/A"))
        if self.loaded_raw_box is not None:
            self.loaded_raw_box.append("")
            self.loaded_raw_box.append("LibreSpeed JSON:")
            self.loaded_raw_box.append(result.get("speed_raw", ""))
        level = "ok" if loaded.get("loss_pct", 0) == 0 and (increase is None or increase <= 75) else "error"
        self._set_loaded_status("Loaded latency test completed.", level)

    def _set_loaded_latency_error(self, message: str):
        self._set_loaded_status(f"Loaded latency failed: {message}", "error")
        if self.loaded_diagnosis_box is not None:
            self.loaded_diagnosis_box.setPlainText(
                "Check that LibreSpeed CLI is available, the internet connection is reachable, and the ping target responds."
            )

    def _finish_loaded_latency_test(self):
        if self.loaded_start_btn is not None:
            self.loaded_start_btn.setEnabled(True)
        if self.loaded_stop_btn is not None:
            self.loaded_stop_btn.setEnabled(False)
        if self.loaded_last_result is None and self.loaded_status_label is not None:
            current = self.loaded_status_label.text()
            if current.startswith("Stopping"):
                self._set_loaded_status("Loaded latency test stopped.", "info")

    def show_http_test_window(self):
        """Open the HTTP/HTTPS diagnostic window."""
        if self.http_window is None:
            self.http_window = QWidget(None, Qt.Window)
            self.http_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.http_window.setWindowTitle("HTTP Test")
            self.http_window.setMinimumSize(760, 620)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls_group = QGroupBox("Request")
            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.http_url_input = QLineEdit(self._default_http_url())
            self.http_url_input.setPlaceholderText("https://example.com")
            self.http_url_input.setMinimumWidth(420)
            self.http_method_combo = QComboBox()
            self.http_method_combo.addItems(["HEAD", "GET"])
            self.http_follow_redirects_check = QCheckBox("Follow redirects")
            self.http_follow_redirects_check.setChecked(True)
            self.http_ignore_tls_check = QCheckBox("Ignore TLS certificate errors")
            self.http_ignore_tls_check.setToolTip("Allow testing local HTTPS services with self-signed or invalid certificates.")
            self.http_timeout_spin = QSpinBox()
            self.http_timeout_spin.setRange(500, 60000)
            self.http_timeout_spin.setSingleStep(500)
            self.http_timeout_spin.setValue(5000)
            self.http_timeout_spin.setSuffix(" ms")
            self.http_run_btn = QPushButton("Run HTTP Test")
            self.http_run_btn.clicked.connect(self.start_http_test)

            controls.addWidget(QLabel("URL"), 0, 0)
            controls.addWidget(self.http_url_input, 0, 1, 1, 5)
            controls.addWidget(QLabel("Method"), 1, 0)
            controls.addWidget(self.http_method_combo, 1, 1)
            controls.addWidget(QLabel("Timeout"), 1, 2)
            controls.addWidget(self.http_timeout_spin, 1, 3)
            controls.addWidget(self.http_follow_redirects_check, 1, 4)
            controls.addWidget(self.http_run_btn, 1, 5)
            controls.addWidget(self.http_ignore_tls_check, 2, 1, 1, 5)
            controls.setColumnStretch(1, 1)
            controls_group.setLayout(controls)
            layout.addWidget(controls_group)

            self.http_status_label = QLabel("Ready")
            self.http_status_label.setAlignment(Qt.AlignCenter)
            self.http_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.http_status_label)

            results_group = QGroupBox("Results")
            results = QGridLayout()
            results.setHorizontalSpacing(8)
            results.setVerticalSpacing(8)
            self.http_status_code_field = self._readonly_result_field()
            self.http_response_time_field = self._readonly_result_field()
            self.http_final_url_field = self._readonly_result_field()
            self.http_redirects_field = self._readonly_result_field()
            self.http_tls_field = self._readonly_result_field()
            self.http_error_field = self._readonly_result_field()

            results.addWidget(QLabel("Status"), 0, 0)
            results.addWidget(self.http_status_code_field, 0, 1)
            results.addWidget(QLabel("Response Time"), 0, 2)
            results.addWidget(self.http_response_time_field, 0, 3)
            results.addWidget(QLabel("Redirects"), 1, 0)
            results.addWidget(self.http_redirects_field, 1, 1)
            results.addWidget(QLabel("Final URL"), 1, 2)
            results.addWidget(self.http_final_url_field, 1, 3)
            results.addWidget(QLabel("TLS"), 2, 0)
            results.addWidget(self.http_tls_field, 2, 1, 1, 3)
            results.addWidget(QLabel("Error"), 3, 0)
            results.addWidget(self.http_error_field, 3, 1, 1, 3)
            results.setColumnStretch(1, 1)
            results.setColumnStretch(3, 1)
            results_group.setLayout(results)
            layout.addWidget(results_group)

            headers_group = QGroupBox("Headers")
            headers_layout = QVBoxLayout()
            self.http_headers_box = QTextEdit()
            self.http_headers_box.setReadOnly(True)
            self.http_headers_box.setLineWrapMode(QTextEdit.WidgetWidth)
            headers_layout.addWidget(self.http_headers_box)
            headers_group.setLayout(headers_layout)
            layout.addWidget(headers_group, 1)

            self.http_window.setLayout(layout)

        if self.http_url_input is not None and not self.http_url_input.text().strip():
            self.http_url_input.setText(self._default_http_url())
        self.http_window.show()
        self.http_window.raise_()
        self.http_window.activateWindow()

    def _readonly_result_field(self):
        field = QLineEdit()
        field.setReadOnly(True)
        return field

    def _default_http_url(self):
        host = self.host_input.text().strip()
        if not host:
            return "https://example.com"
        if re.match(r"^https?://", host, re.IGNORECASE):
            return host
        return "https://" + host

    def start_http_test(self):
        if self.http_test_worker is not None and self.http_test_worker.isRunning():
            return
        url = self.http_url_input.text().strip() if self.http_url_input is not None else ""
        if not url:
            QMessageBox.warning(self, "HTTP Test Error", "Enter a URL.")
            return

        self.http_run_btn.setEnabled(False)
        self.http_status_label.setText("Running HTTP test...")
        self.http_status_label.setStyleSheet(
            "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )
        for field in (
            self.http_status_code_field,
            self.http_response_time_field,
            self.http_final_url_field,
            self.http_redirects_field,
            self.http_tls_field,
            self.http_error_field,
        ):
            field.clear()
        self.http_headers_box.clear()

        self.http_test_worker = HttpTestWorker(
            url,
            method=self.http_method_combo.currentText(),
            follow_redirects=self.http_follow_redirects_check.isChecked(),
            timeout_ms=self.http_timeout_spin.value(),
            verify_tls=not self.http_ignore_tls_check.isChecked(),
        )
        self.http_test_worker.result_ready.connect(self._set_http_result)
        self.http_test_worker.error_ready.connect(self._set_http_error)
        self.http_test_worker.finished.connect(self.http_test_worker.deleteLater)
        self.http_test_worker.finished.connect(lambda: setattr(self, "http_test_worker", None))
        self.http_test_worker.start()

    def _set_http_result(self, result: dict):
        if self.http_run_btn is not None:
            self.http_run_btn.setEnabled(True)
        status_text = f"{result.get('status_code', 'N/A')} {result.get('reason', '')}".strip()
        self.http_status_code_field.setText(status_text)
        self.http_response_time_field.setText(f"{result.get('response_time_ms', 0):.1f} ms")
        self.http_final_url_field.setText(result.get("final_url", "N/A"))
        self.http_redirects_field.setText(str(result.get("redirect_count", 0)))
        self.http_tls_field.setText(result.get("tls", "N/A"))
        self.http_error_field.setText(result.get("error", "N/A"))
        self.http_headers_box.setPlainText(result.get("headers", "N/A"))

        is_error = result.get("error") not in (None, "", "N/A")
        if self.http_status_label is not None:
            self.http_status_label.setText("HTTP test completed." if not is_error else "HTTP test completed with HTTP error response.")
            self.http_status_label.setStyleSheet(
                "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
                if not is_error else
                "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

    def _set_http_error(self, error: str):
        if self.http_run_btn is not None:
            self.http_run_btn.setEnabled(True)
        if self.http_status_label is not None:
            self.http_status_label.setText(error)
            self.http_status_label.setStyleSheet(
                "QLabel { background: #fce8e6; color: #a50e0e; border: 1px solid #d28b82; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
        if self.http_error_field is not None:
            self.http_error_field.setText(error)

    def show_dns_compare_window(self):
        """Open the DNS resolver comparison diagnostic window."""
        if self.dns_compare_window is None:
            self.dns_compare_window = QWidget(None, Qt.Window)
            self.dns_compare_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.dns_compare_window.setWindowTitle("DNS Compare")
            self.dns_compare_window.setMinimumSize(820, 520)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls_group = QGroupBox("Query")
            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.dns_compare_input = QLineEdit(self.host_input.text().strip())
            self.dns_compare_input.setPlaceholderText("example.com")
            self.dns_compare_input.setMinimumWidth(360)
            self.dns_compare_record_combo = QComboBox()
            self.dns_compare_record_combo.addItems(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
            self.dns_compare_timeout_spin = QSpinBox()
            self.dns_compare_timeout_spin.setRange(1000, 30000)
            self.dns_compare_timeout_spin.setSingleStep(1000)
            self.dns_compare_timeout_spin.setValue(5000)
            self.dns_compare_timeout_spin.setSuffix(" ms")
            self.dns_compare_run_btn = QPushButton("Run Compare")
            self.dns_compare_run_btn.clicked.connect(self.start_dns_compare)

            controls.addWidget(QLabel("Hostname"), 0, 0)
            controls.addWidget(self.dns_compare_input, 0, 1)
            controls.addWidget(QLabel("Record"), 0, 2)
            controls.addWidget(self.dns_compare_record_combo, 0, 3)
            controls.addWidget(QLabel("Timeout"), 0, 4)
            controls.addWidget(self.dns_compare_timeout_spin, 0, 5)
            controls.addWidget(self.dns_compare_run_btn, 0, 6)
            controls.setColumnStretch(1, 1)
            controls_group.setLayout(controls)
            layout.addWidget(controls_group)

            self.dns_compare_status_label = QLabel("Ready")
            self.dns_compare_status_label.setAlignment(Qt.AlignCenter)
            self.dns_compare_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.dns_compare_status_label)

            self.dns_compare_table = QTableWidget(0, 5)
            self.dns_compare_table.setHorizontalHeaderLabels(["Resolver", "Server", "Time", "Answers", "Error"])
            self.dns_compare_table.verticalHeader().setVisible(False)
            self.dns_compare_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.dns_compare_table.setSelectionBehavior(QTableWidget.SelectRows)
            self.dns_compare_table.setWordWrap(True)
            self.dns_compare_table.setStyleSheet(
                "QTableWidget::item { padding: 3px 10px 3px 4px; } "
                "QHeaderView::section { padding: 3px 10px 3px 4px; }"
            )
            dh = self.dns_compare_table.horizontalHeader()
            dh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            dh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            dh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            dh.setSectionResizeMode(3, QHeaderView.Stretch)
            dh.setSectionResizeMode(4, QHeaderView.Stretch)
            layout.addWidget(self.dns_compare_table, 1)

            self.dns_compare_window.setLayout(layout)

        if self.dns_compare_input is not None and not self.dns_compare_input.text().strip():
            self.dns_compare_input.setText(self.host_input.text().strip())
        self.dns_compare_window.show()
        self.dns_compare_window.raise_()
        self.dns_compare_window.activateWindow()

    def start_dns_compare(self):
        if self.dns_compare_worker is not None and self.dns_compare_worker.isRunning():
            return
        query = self.dns_compare_input.text().strip() if self.dns_compare_input is not None else ""
        if not query:
            QMessageBox.warning(self, "DNS Compare Error", "Enter a hostname.")
            return

        self.dns_compare_table.setRowCount(0)
        self.dns_compare_run_btn.setEnabled(False)
        self.dns_compare_status_label.setText("Comparing DNS resolvers...")
        self.dns_compare_status_label.setStyleSheet(
            "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

        self.dns_compare_worker = DnsCompareWorker(
            query,
            self.dns_compare_record_combo.currentText(),
            timeout_ms=self.dns_compare_timeout_spin.value(),
        )
        self.dns_compare_worker.result_ready.connect(self._add_dns_compare_result)
        self.dns_compare_worker.finished.connect(self._finish_dns_compare)
        self.dns_compare_worker.finished.connect(self.dns_compare_worker.deleteLater)
        self.dns_compare_worker.finished.connect(lambda: setattr(self, "dns_compare_worker", None))
        self.dns_compare_worker.start()

    def _add_dns_compare_result(self, result: dict):
        if self.dns_compare_table is None:
            return
        row = self.dns_compare_table.rowCount()
        self.dns_compare_table.insertRow(row)
        values = [
            result.get("resolver", ""),
            result.get("server", ""),
            f"{result.get('time_ms', 0):.1f} ms",
            wrapped_detail_text(result.get("answers", ""), width=85),
            wrapped_detail_text(result.get("error", ""), width=85),
        ]
        has_error = result.get("error") not in (None, "", "N/A")
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if has_error:
                item.setBackground(QBrush(QColor("#fff4ce")))
            self.dns_compare_table.setItem(row, col, item)
        self.dns_compare_table.resizeRowsToContents()

    def _finish_dns_compare(self):
        if self.dns_compare_run_btn is not None:
            self.dns_compare_run_btn.setEnabled(True)
        error_count = 0
        if self.dns_compare_table is not None:
            for row in range(self.dns_compare_table.rowCount()):
                error_item = self.dns_compare_table.item(row, 4)
                if error_item is not None and error_item.text() not in ("", "N/A"):
                    error_count += 1
        if self.dns_compare_status_label is not None:
            if error_count:
                self.dns_compare_status_label.setText(f"DNS compare completed with {error_count} resolver error(s).")
                self.dns_compare_status_label.setStyleSheet(
                    "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )
            else:
                self.dns_compare_status_label.setText("DNS compare completed.")
                self.dns_compare_status_label.setStyleSheet(
                    "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                    "border-radius: 4px; padding: 8px; font-weight: bold; }"
                )

    def show_mtu_test_window(self):
        """Open the MTU discovery diagnostic window."""
        if self.mtu_window is None:
            self.mtu_window = QWidget(None, Qt.Window)
            self.mtu_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.mtu_window.setWindowTitle("MTU Test")
            self.mtu_window.setMinimumSize(760, 560)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            controls_group = QGroupBox("Test")
            controls = QGridLayout()
            controls.setHorizontalSpacing(8)
            controls.setVerticalSpacing(8)
            self.mtu_target_input = QLineEdit(self._default_network_scan_host() or self.host_input.text().strip())
            self.mtu_target_input.setMinimumWidth(320)
            self.mtu_start_spin = QSpinBox()
            self.mtu_start_spin.setRange(0, 9000)
            self.mtu_start_spin.setValue(1200)
            self.mtu_start_spin.setSuffix(" bytes")
            self.mtu_max_spin = QSpinBox()
            self.mtu_max_spin.setRange(0, 9000)
            self.mtu_max_spin.setValue(1500)
            self.mtu_max_spin.setSuffix(" bytes")
            self.mtu_timeout_spin = QSpinBox()
            self.mtu_timeout_spin.setRange(500, 30000)
            self.mtu_timeout_spin.setSingleStep(500)
            self.mtu_timeout_spin.setValue(3000)
            self.mtu_timeout_spin.setSuffix(" ms")
            self.mtu_run_btn = QPushButton("Run MTU Test")
            self.mtu_run_btn.clicked.connect(self.start_mtu_test)

            controls.addWidget(QLabel("Target"), 0, 0)
            controls.addWidget(self.mtu_target_input, 0, 1, 1, 5)
            controls.addWidget(QLabel("Start payload"), 1, 0)
            controls.addWidget(self.mtu_start_spin, 1, 1)
            controls.addWidget(QLabel("Max payload"), 1, 2)
            controls.addWidget(self.mtu_max_spin, 1, 3)
            controls.addWidget(QLabel("Timeout"), 1, 4)
            controls.addWidget(self.mtu_timeout_spin, 1, 5)
            controls.addWidget(self.mtu_run_btn, 1, 6)
            controls.setColumnStretch(1, 1)
            controls_group.setLayout(controls)
            layout.addWidget(controls_group)

            self.mtu_status_label = QLabel("Ready")
            self.mtu_status_label.setAlignment(Qt.AlignCenter)
            self.mtu_status_label.setStyleSheet(
                "QLabel { background: #eef2f7; color: #3c4043; border: 1px solid #b7c0cc; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )
            layout.addWidget(self.mtu_status_label)

            results_group = QGroupBox("Results")
            results = QGridLayout()
            results.setHorizontalSpacing(8)
            results.setVerticalSpacing(8)
            self.mtu_payload_field = self._readonly_result_field()
            self.mtu_estimated_field = self._readonly_result_field()
            self.mtu_result_status_field = self._readonly_result_field()
            results.addWidget(QLabel("Largest Payload"), 0, 0)
            results.addWidget(self.mtu_payload_field, 0, 1)
            results.addWidget(QLabel("Estimated MTU"), 0, 2)
            results.addWidget(self.mtu_estimated_field, 0, 3)
            results.addWidget(QLabel("Status"), 1, 0)
            results.addWidget(self.mtu_result_status_field, 1, 1, 1, 3)
            results.setColumnStretch(1, 1)
            results.setColumnStretch(3, 1)
            results_group.setLayout(results)
            layout.addWidget(results_group)

            raw_group = QGroupBox("Raw Ping Output")
            raw_layout = QVBoxLayout()
            self.mtu_raw_box = QTextEdit()
            self.mtu_raw_box.setReadOnly(True)
            self.mtu_raw_box.setLineWrapMode(QTextEdit.WidgetWidth)
            raw_layout.addWidget(self.mtu_raw_box)
            raw_group.setLayout(raw_layout)
            layout.addWidget(raw_group, 1)

            self.mtu_window.setLayout(layout)

        if self.mtu_target_input is not None and not self.mtu_target_input.text().strip():
            self.mtu_target_input.setText(self._default_network_scan_host() or self.host_input.text().strip())
        self.mtu_window.show()
        self.mtu_window.raise_()
        self.mtu_window.activateWindow()

    def start_mtu_test(self):
        if self.mtu_test_worker is not None and self.mtu_test_worker.isRunning():
            return
        target = self.mtu_target_input.text().strip() if self.mtu_target_input is not None else ""
        if not target:
            QMessageBox.warning(self, "MTU Test Error", "Enter a target.")
            return
        if self.mtu_start_spin.value() > self.mtu_max_spin.value():
            QMessageBox.warning(self, "MTU Test Error", "Start payload must be less than or equal to max payload.")
            return

        self.mtu_run_btn.setEnabled(False)
        self.mtu_payload_field.clear()
        self.mtu_estimated_field.clear()
        self.mtu_result_status_field.clear()
        self.mtu_raw_box.clear()
        self.mtu_status_label.setText("Running MTU test...")
        self.mtu_status_label.setStyleSheet(
            "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
        )

        self.mtu_test_worker = MtuTestWorker(
            target,
            start_size=self.mtu_start_spin.value(),
            max_size=self.mtu_max_spin.value(),
            timeout_ms=self.mtu_timeout_spin.value(),
        )
        self.mtu_test_worker.progress_ready.connect(self._set_mtu_progress)
        self.mtu_test_worker.result_ready.connect(self._set_mtu_result)
        self.mtu_test_worker.error_ready.connect(self._set_mtu_error)
        self.mtu_test_worker.finished.connect(self.mtu_test_worker.deleteLater)
        self.mtu_test_worker.finished.connect(lambda: setattr(self, "mtu_test_worker", None))
        self.mtu_test_worker.start()

    def _set_mtu_progress(self, message: str):
        if self.mtu_status_label is not None:
            self.mtu_status_label.setText(message)

    def _set_mtu_result(self, result: dict):
        if self.mtu_run_btn is not None:
            self.mtu_run_btn.setEnabled(True)
        self.mtu_payload_field.setText(str(result.get("payload", "N/A")))
        self.mtu_estimated_field.setText(str(result.get("mtu", "N/A")))
        self.mtu_result_status_field.setText(result.get("status", "N/A"))
        self.mtu_raw_box.setPlainText(result.get("raw", ""))
        success = result.get("payload") != "N/A"
        if self.mtu_status_label is not None:
            self.mtu_status_label.setText("MTU test completed." if success else "MTU test completed with no successful payload.")
            self.mtu_status_label.setStyleSheet(
                "QLabel { background: #e6f4ea; color: #137333; border: 1px solid #8abf9a; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
                if success else
                "QLabel { background: #fff4ce; color: #8a5a00; border: 1px solid #d8b756; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

    def _set_mtu_error(self, error: str):
        if self.mtu_run_btn is not None:
            self.mtu_run_btn.setEnabled(True)
        if self.mtu_status_label is not None:
            self.mtu_status_label.setText(error)
            self.mtu_status_label.setStyleSheet(
                "QLabel { background: #fce8e6; color: #a50e0e; border: 1px solid #d28b82; "
                "border-radius: 4px; padding: 8px; font-weight: bold; }"
            )

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

    def show_help_window(self):
        """Open the offline help and documentation window."""
        if self.help_window is None:
            self.help_window = QWidget(None, Qt.Window)
            self.help_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.help_window.setWindowTitle("Help")
            self.help_window.setMinimumSize(860, 700)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            self.help_text_box = QTextEdit()
            self.help_text_box.setReadOnly(True)
            self.help_text_box.setLineWrapMode(QTextEdit.WidgetWidth)
            self.help_text_box.setHtml(self._help_documentation_html())
            layout.addWidget(self.help_text_box, 1)
            self.help_window.setLayout(layout)

        self.help_window.show()
        self.help_window.raise_()
        self.help_window.activateWindow()

    def _help_documentation_html(self):
        return """
        <html>
        <head>
        <style>
            body { font-family: Segoe UI, Arial, sans-serif; font-size: 10pt; color: #202124; }
            h1 { font-size: 18pt; margin-bottom: 8px; }
            h2 { font-size: 13pt; margin-top: 18px; margin-bottom: 6px; color: #174ea6; }
            h3 { font-size: 11pt; margin-top: 12px; margin-bottom: 4px; }
            p { margin: 5px 0; }
            ul { margin-top: 4px; margin-bottom: 8px; }
            li { margin-bottom: 4px; }
            code { background: #f1f3f4; padding: 1px 4px; }
            .note { background: #eef2f7; border: 1px solid #b7c0cc; padding: 8px; margin: 8px 0; }
            .warn { background: #fff4ce; border: 1px solid #d8b756; padding: 8px; margin: 8px 0; }
        </style>
        </head>
        <body>
        <h1>PingerApp Help</h1>
        <p>PingerApp is a local network troubleshooting tool. It is designed for checking your own connection, devices, services, and ISP path.</p>

        <h2>Main Window</h2>
        <h3>Ping Panel</h3>
        <ul>
            <li><b>Host</b>: hostname or IP address used by the ping monitor and as the default target for tools.</li>
            <li><b>Reverse DNS</b>: hostname found for the current target IP when available.</li>
            <li><b>Start/Stop</b>: starts or stops the continuous ping session.</li>
            <li><b>Pause/Resume</b>: pauses the session timer and ping loop without clearing current stats.</li>
            <li><b>Live Latency</b>: most recent ping round-trip time. <code>Timeout</code> means the target did not reply before the ping timeout.</li>
            <li><b>Live Jitter</b>: difference between the latest successful ping and the previous successful ping.</li>
            <li><b>RTT Health</b>: rolling health view based on average latency and packet loss.</li>
            <li><b>Jitter Health</b>: rolling health view based on average jitter.</li>
            <li><b>Elapsed Time</b>: current ping session duration.</li>
        </ul>

        <h3>Alert Thresholds</h3>
        <ul>
            <li><b>Latency Alert</b>: logs an alert when a successful ping is higher than the selected millisecond value.</li>
            <li><b>Loss Alert</b>: logs an alert when session packet loss is higher than the selected percentage.</li>
            <li><b>Jitter Alert</b>: logs an alert when ping-to-ping variation is higher than the selected millisecond value.</li>
            <li><b>History</b>: number of recent ping samples kept in the graphs and report. Range is 10 to 100.</li>
            <li><b>Default</b>: resets the matching threshold or history value to the app default.</li>
            <li><b>Alert toggle buttons</b>: switch each alert type on or off without changing the threshold value.</li>
        </ul>

        <h3>Monitoring Boxes</h3>
        <ul>
            <li><b>Alert Counts</b>: count of latency and loss threshold breaches. Reset Stats clears counts, samples, graphs, and alert log.</li>
            <li><b>Latency Stats</b>: best 10 average, worst 10 average, and combined average for retained successful samples.</li>
            <li><b>Jitter Stats</b>: minimum, maximum, and average jitter from retained successful jitter samples.</li>
            <li><b>Host Info</b>: local hostname, local IP, gateway, public IP, ISP, and primary MAC address.</li>
        </ul>

        <h3>Graphs</h3>
        <ul>
            <li><b>Latency graph</b>: plots retained ping latency samples. Gaps indicate timeouts.</li>
            <li><b>Jitter graph</b>: plots retained jitter samples. Higher jitter usually means less stable timing.</li>
            <li><b>Auto-scale</b>: adjusts the graph range to current data and selected thresholds.</li>
            <li><b>Graph toolbar</b>: use pan, zoom, home, and save image controls from Matplotlib.</li>
        </ul>

        <h2>Reading Common Values</h2>
        <ul>
            <li><b>Low latency</b>: better for calls, games, remote desktop, and interactive work.</li>
            <li><b>High jitter</b>: timing is inconsistent even if average latency looks acceptable.</li>
            <li><b>Packet loss</b>: any repeated loss can cause freezes, retries, or dropped real-time traffic.</li>
            <li><b>Timeout</b>: can mean the host is down, blocks ping, is unreachable, or the network path dropped the packet.</li>
            <li><b>MAC address</b>: normally visible only for local network devices or the next-hop device in your ARP cache.</li>
        </ul>

        <h2>Tools</h2>
        <h3>Adapter Info</h3>
        <ul>
            <li>Shows the active Windows adapter, status, connection type, link speed, duplex setting, IPv4, gateway, DNS servers, MAC address, interface index, and interface counters.</li>
            <li><b>Link Speed</b> is the negotiated local connection rate between this PC and the connected router, switch, access point, dock, or adapter.</li>
            <li>If Link Speed is <code>100 Mbps</code>, speed tests cannot reach gigabit speeds from this PC. Check cable, wall socket, switch/router port, USB dock, adapter settings, and auto-negotiation.</li>
            <li>If Link Speed is <code>1 Gbps</code> or faster but internet speed is near 100 Mbps, check router WAN/LAN port speed, ISP profile, speed test server, or congestion.</li>
            <li><b>Receive/Transmit Errors</b> and <b>Discards</b> should normally stay at zero or stop increasing. Increasing values during tests can indicate cable, port, NIC, driver, or congestion issues.</li>
            <li><b>Counter Watch</b>: run this while a Speed Test or LAN Throughput test is active. It compares before/after counters and shows transfer, average rates, and error/discard increases.</li>
            <li>For Wi-Fi, link rate is not the same as real throughput. Signal, band, channel width, interference, and access point capability matter.</li>
        </ul>

        <h3>LAN Throughput</h3>
        <ul>
            <li>Uses iperf3 to measure local network throughput between two devices on your LAN.</li>
            <li>PingerApp includes iperf3 at <code>tools/iperf3/iperf3.exe</code> and can also use iperf3 from PATH.</li>
            <li>On one machine, open LAN Throughput and click <b>Start Server</b>. On the other machine, enter the server machine IP and click <b>Run LAN Test</b>.</li>
            <li>Do not use the gateway/router IP unless that device is actually running iperf3. Most home routers do not.</li>
            <li><b>Upload to server</b> sends traffic from this PC to the server. <b>Download from server</b> uses iperf3 reverse mode.</li>
            <li>A wired gigabit LAN usually lands near 900 Mbps or higher. A result around 100 Mbps points to cable, port, dock, adapter, or negotiation limits.</li>
            <li>If LAN throughput is gigabit-class but internet Speed Test is low, focus on router WAN, ISP profile, speed test server, or congestion.</li>
        </ul>

        <h3>Gateway Stability</h3>
        <ul>
            <li>Pings the default gateway or first-hop target repeatedly and tracks local first-hop latency, packet loss, jitter, and spikes.</li>
            <li><b>Samples</b> controls how many pings to send. <b>Interval</b> controls the delay between samples. <b>Timeout</b> controls how long each ping can wait.</li>
            <li><b>Spike over</b> counts any gateway reply above that latency threshold.</li>
            <li>Run it before and during heavy downloads, uploads, or Speed Test. If gateway latency spikes or drops packets under load, the local router, Wi-Fi, cable, switch, or adapter path is struggling.</li>
            <li>If the gateway stays stable while internet speed is poor, the problem is more likely beyond the local LAN, such as router WAN, ISP, route, or remote server.</li>
        </ul>

        <h3>Loaded Latency</h3>
        <ul>
            <li>Measures idle latency first, then runs a LibreSpeed test while continuing to ping a target such as <code>1.1.1.1</code>.</li>
            <li><b>Increase</b> is loaded average latency minus idle average latency. This is the main bufferbloat signal.</li>
            <li>A small increase is healthy. A large increase means traffic queues are building while the line is busy.</li>
            <li>Loaded packet loss can point to Wi-Fi instability, local saturation, router queue pressure, or ISP congestion.</li>
            <li>Use this when calls, games, or remote desktop get laggy while downloads, uploads, cloud sync, or speed tests are running.</li>
        </ul>

        <h3>Route Health</h3>
        <ul>
            <li>Runs LibreSpeed load while pinging the gateway, ISP first hop, and a public target.</li>
            <li><b>ISP hop</b> can be left blank; the tool will try to auto-detect it with a short traceroute.</li>
            <li>If the gateway degrades, investigate the local LAN path. If only the ISP hop degrades, investigate router WAN, modem/ONT, or ISP edge. If only the public target degrades, suspect upstream route or remote network conditions.</li>
            <li>Use this when raw speed, loaded latency, or gateway checks are not enough to locate where the slowdown starts.</li>
        </ul>

        <h3>Speed Test</h3>
        <ul>
            <li>Uses LibreSpeed CLI to measure download, upload, latency, and jitter.</li>
            <li><b>Server</b>: auto-selects by default, or choose a refreshed public server list.</li>
            <li><b>Duration</b>: longer tests can be more stable but use more bandwidth.</li>
            <li><b>Try share URL</b>: asks supported LibreSpeed servers for a shareable result URL.</li>
            <li><b>History</b>: stores the last 10 speed test runs locally.</li>
        </ul>

        <h3>Network Scanner</h3>
        <ul>
            <li>Performs TCP connect checks against one host or a selected IPv4 subnet.</li>
            <li><b>Target</b>: choose Single host for one target, or Subnet for a CIDR range around the entered IP.</li>
            <li><b>Port preset</b>: choose a named set, or select Manual ports for an exact custom check.</li>
            <li><b>Manual ports</b>: type one port or a list such as <code>443</code> or <code>80,443,8000-8010</code>.</li>
            <li><b>Parallel probes</b>: higher is faster, lower is gentler on small or fragile networks.</li>
            <li><b>Probe service banners</b>: tries light banner, HTTP, and TLS probes on open ports.</li>
            <li><b>Open</b>: TCP connection succeeded. <b>Closed</b>: host actively refused. <b>Filtered</b>: no response or dropped.</li>
        </ul>

        <h3>HTTP Test</h3>
        <ul>
            <li>Runs GET or HEAD against an HTTP/HTTPS URL.</li>
            <li><b>Follow redirects</b>: shows the final URL after redirects when enabled.</li>
            <li><b>Ignore TLS certificate errors</b>: useful for local HTTPS services with self-signed certificates.</li>
            <li>Review status code, response time, redirect count, TLS summary, headers, and error details.</li>
        </ul>

        <h3>DNS / WHOIS</h3>
        <ul>
            <li>Runs forward or reverse DNS lookups.</li>
            <li><b>Record</b>: choose A, AAAA, MX, NS, TXT, CNAME, SOA, or ANY.</li>
            <li><b>Include IP / ASN / ISP</b>: adds ownership metadata for resolved IP addresses when available.</li>
        </ul>

        <h3>DNS Compare</h3>
        <ul>
            <li>Compares answers and response times across System DNS, Cloudflare, Google, and Quad9.</li>
            <li>Useful when one resolver gives stale, missing, or different answers.</li>
            <li>Errors in one resolver do not necessarily mean the target hostname is broken everywhere.</li>
        </ul>

        <h3>MTU Test</h3>
        <ul>
            <li>Finds the largest ping payload that can pass without fragmentation.</li>
            <li><b>Estimated MTU</b> is the successful payload plus IP/ICMP header overhead.</li>
            <li>Repeated failures can mean ICMP is blocked, the target is unreachable, or the path blocks non-fragmenting probes.</li>
        </ul>

        <h3>Traceroute</h3>
        <ul>
            <li>Shows the network hops between this PC and the target.</li>
            <li><b>*</b> or missing latency can mean a hop ignores traceroute probes while still forwarding traffic.</li>
            <li>Problems near the first hops usually point to local/router/ISP access issues. Problems only near the end may be remote-side routing.</li>
        </ul>

        <h3>Alerts</h3>
        <ul>
            <li>Shows timestamped latency, packet loss, and jitter threshold breaches.</li>
            <li>The Alerts button gets an asterisk when new alerts arrive while the alert window is closed.</li>
        </ul>

        <h3>Report</h3>
        <ul>
            <li>Builds a plain text troubleshooting snapshot from selected sections.</li>
            <li>Use checkboxes to include or exclude Host Info, Adapter Info, ping stats, LAN Throughput, Gateway Stability, Loaded Latency, Route Health, Speed Test history, DNS lookup, traceroute, and Network Scanner results.</li>
            <li><b>Refresh Preview</b> rebuilds the snapshot from current app data.</li>
            <li><b>Save as TXT</b> writes the current report to a text file.</li>
        </ul>

        <div class="warn">
            Run diagnostic scans only on networks, hosts, and services you own or are authorized to troubleshoot.
        </div>
        </body>
        </html>
        """

    def show_report_window(self):
        """Open the troubleshooting report builder."""
        if self.report_window is None:
            self.report_window = QWidget(None, Qt.Window)
            self.report_window.setAttribute(Qt.WA_DeleteOnClose, False)
            self.report_window.setWindowTitle("Report")
            self.report_window.setMinimumSize(820, 640)

            layout = QVBoxLayout()
            layout.setContentsMargins(12,12,12,12)
            layout.setSpacing(10)

            sections_group = QGroupBox("Sections")
            sections_grid = QGridLayout()
            sections_grid.setContentsMargins(10,10,10,10)
            sections_grid.setHorizontalSpacing(16)
            sections_grid.setVerticalSpacing(8)
            section_defs = [
                ("host_info", "Host Info"),
                ("adapter_info", "Adapter info"),
                ("ping_stats", "Ping stats"),
                ("lan_throughput", "LAN Throughput"),
                ("gateway_stability", "Gateway Stability"),
                ("loaded_latency", "Loaded Latency"),
                ("route_health", "Route Health"),
                ("speedtest_history", "Speed Test history"),
                ("dns_lookup", "Last DNS lookup"),
                ("traceroute", "Last traceroute"),
                ("network_scanner", "Network Scanner results"),
            ]
            self.report_checkboxes = {}
            for index, (key, label) in enumerate(section_defs):
                checkbox = QCheckBox(label)
                checkbox.setChecked(True)
                checkbox.toggled.connect(self.update_report_preview)
                self.report_checkboxes[key] = checkbox
                sections_grid.addWidget(checkbox, index // 2, index % 2)
            sections_grid.setColumnStretch(0, 1)
            sections_grid.setColumnStretch(1, 1)
            sections_group.setLayout(sections_grid)
            layout.addWidget(sections_group)

            action_row = QHBoxLayout()
            refresh_btn = QPushButton("Refresh Preview")
            refresh_btn.clicked.connect(self.update_report_preview)
            save_btn = QPushButton("Save as TXT")
            save_btn.clicked.connect(self.save_report)
            action_row.addWidget(refresh_btn)
            action_row.addWidget(save_btn)
            action_row.addStretch(1)
            layout.addLayout(action_row)

            self.report_preview_box = QTextEdit()
            self.report_preview_box.setReadOnly(True)
            self.report_preview_box.setLineWrapMode(QTextEdit.NoWrap)
            self.report_preview_box.setPlaceholderText("Report preview will appear here.")
            layout.addWidget(self.report_preview_box, 1)

            self.report_window.setLayout(layout)

        self.update_report_preview()
        self.report_window.show()
        self.report_window.raise_()
        self.report_window.activateWindow()

    def update_report_preview(self):
        if self.report_preview_box is not None:
            self.report_preview_box.setPlainText(self.build_report_text())

    def save_report(self):
        report_text = self.build_report_text()
        if self.report_preview_box is not None:
            self.report_preview_box.setPlainText(report_text)

        root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
        default_name = f"PingerApp_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        default_path = os.path.join(root, "data", default_name)
        path, _ = QFileDialog.getSaveFileName(
            self.report_window or self,
            "Save Report",
            default_path,
            "Text Files (*.txt);;All Files (*)",
        )
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += ".txt"
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(report_text)
        except OSError as e:
            QMessageBox.critical(self.report_window or self, "Report Error", f"Could not save report:\n{e}")
            return
        QMessageBox.information(self.report_window or self, "Report Saved", f"Saved report to:\n{path}")

    def _report_section_enabled(self, key: str):
        checkbox = self.report_checkboxes.get(key)
        return checkbox is None or checkbox.isChecked()

    def build_report_text(self):
        lines = [
            "PingerApp Troubleshooting Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {self.host_input.text().strip() or 'N/A'}",
            "",
        ]

        sections = [
            ("host_info", "Host Info", self._report_host_info_lines),
            ("adapter_info", "Adapter Info", self._report_adapter_info_lines),
            ("ping_stats", "Ping Stats", self._report_ping_stats_lines),
            ("lan_throughput", "LAN Throughput", self._report_lan_throughput_lines),
            ("gateway_stability", "Gateway Stability", self._report_gateway_stability_lines),
            ("loaded_latency", "Loaded Latency", self._report_loaded_latency_lines),
            ("route_health", "Route Health", self._report_route_health_lines),
            ("speedtest_history", "Speed Test History", self._report_speedtest_history_lines),
            ("dns_lookup", "Last DNS Lookup", self._report_dns_lookup_lines),
            ("traceroute", "Last Traceroute", self._report_traceroute_lines),
            ("network_scanner", "Network Scanner Results", self._report_network_scanner_lines),
        ]
        for key, title, builder in sections:
            if not self._report_section_enabled(key):
                continue
            self._append_report_section(lines, title, builder())
        return "\n".join(lines).rstrip() + "\n"

    def _append_report_section(self, lines, title, body_lines):
        lines.extend([title, "-" * len(title)])
        lines.extend(body_lines or ["No data available."])
        lines.append("")

    def _label_text(self, label):
        if label is None:
            return "N/A"
        value = label.text().strip()
        return value if value else "N/A"

    def _report_host_info_lines(self):
        return [
            f"Hostname: {self._label_text(self.hostname_label)}",
            f"Local IP: {self._label_text(self.host_ip_label)}",
            f"Gateway: {self._label_text(self.gateway_label)}",
            f"Public IP: {self._label_text(self.public_ip_label)}",
            f"ISP: {self._label_text(self.public_isp_label)}",
            f"MAC: {self._label_text(self.host_mac_label)}",
        ]

    def _report_adapter_info_lines(self):
        if not self.adapter_labels:
            return ["Adapter Info has not been opened or refreshed yet."]
        rows = [
            ("Adapter", "adapter"),
            ("Description", "description"),
            ("Status", "status"),
            ("Type", "connection_type"),
            ("Link Speed", "link_speed"),
            ("Duplex / Setting", "duplex"),
            ("IPv4", "ipv4"),
            ("Gateway", "gateway"),
            ("DNS Servers", "dns_servers"),
            ("MAC", "mac"),
            ("Interface Index", "interface_index"),
        ]
        lines = [f"{label}: {self._label_text(self.adapter_labels.get(key))}" for label, key in rows]
        counter_rows = [
            ("Counter Source", "counter_source"),
            ("Received", "rx_traffic"),
            ("Sent", "tx_traffic"),
            ("Receive Errors", "rx_errors"),
            ("Transmit Errors", "tx_errors"),
            ("Receive Discards", "rx_discards"),
            ("Transmit Discards", "tx_discards"),
        ]
        lines.extend(["", "Interface Counters:"])
        lines.extend(f"{label}: {self._label_text(self.adapter_labels.get(key))}" for label, key in counter_rows)
        if self.adapter_watch_labels:
            watch_rows = [
                ("Duration", "duration"),
                ("Received During Watch", "received_delta"),
                ("Sent During Watch", "sent_delta"),
                ("Avg Receive Rate", "receive_rate"),
                ("Avg Send Rate", "send_rate"),
                ("Error Increase", "error_delta"),
                ("Discard Increase", "discard_delta"),
            ]
            lines.extend(["", "Counter Watch:"])
            lines.extend(f"{label}: {self._label_text(self.adapter_watch_labels.get(key))}" for label, key in watch_rows)
        if self.adapter_diagnosis_box is not None:
            diagnosis = self.adapter_diagnosis_box.toPlainText().strip()
            if diagnosis:
                lines.extend(["", "Diagnosis:", diagnosis])
        return lines

    def _report_ping_stats_lines(self):
        retained_latencies = list(self.latencies)
        retained_jitters = list(self.jitters)
        valid_latencies = self._valid_values(retained_latencies)
        valid_jitters = self._valid_values(retained_jitters)
        timeout_count = retained_latencies.count(None)
        rolling_loss = 0.0 if not retained_latencies else (timeout_count / len(retained_latencies)) * 100

        def sample_text(values):
            if not values:
                return "N/A"
            formatted = ["Timeout" if value is None else f"{value:.1f}" for value in values]
            return ", ".join(formatted)

        return [
            f"Ping target: {self.host_input.text().strip() or 'N/A'}",
            f"Reverse DNS: {self.reverse_dns_disp.text().strip() or 'N/A'}",
            f"Session elapsed: {self.elapsed_display.text().strip() or '00:00'}",
            f"Total pings: {self.ping_count}",
            f"Total timeouts: {self.timeouts}",
            f"Current packet loss: {self.loss_value_label.text().strip() or '0.0%'}",
            f"Rolling retained samples: {len(retained_latencies)}",
            f"Rolling retained loss: {rolling_loss:.1f}%",
            f"Live latency: {self.live_latency.text().strip() or 'N/A'}",
            f"Live jitter: {self.live_jitter.text().strip() or 'N/A'}",
            f"RTT health: {self.rtt_health_label.text().strip() or 'N/A'}",
            f"Jitter health: {self.jitter_health_label.text().strip() or 'N/A'}",
            f"Latency threshold: {self.lat_thresh_input.text().strip() or 'N/A'} ms",
            f"Loss threshold: {self.loss_thresh_input.text().strip() or 'N/A'}%",
            f"Jitter threshold: {self.jit_thresh_input.text().strip() or 'N/A'} ms",
            f"Latency breaches: {self.lat_count_label.text().strip() or '0'}",
            f"Loss breaches: {self.loss_count_label.text().strip() or '0'}",
            f"Avg best 10: {self.avg_low_label.text().strip() or 'N/A'}",
            f"Avg worst 10: {self.avg_high_label.text().strip() or 'N/A'}",
            f"Avg combined: {self.avg_comb_label.text().strip() or 'N/A'}",
            f"Min jitter: {self.jit_low_label.text().strip() or 'N/A'}",
            f"Max jitter: {self.jit_high_label.text().strip() or 'N/A'}",
            f"Avg jitter: {self.jit_avg_label.text().strip() or 'N/A'}",
            f"Retained latency samples (ms): {sample_text(retained_latencies)}",
            f"Retained jitter samples (ms): {sample_text(retained_jitters)}",
            f"Successful retained latency samples: {len(valid_latencies)}",
            f"Successful retained jitter samples: {len(valid_jitters)}",
        ]

    def _report_lan_throughput_lines(self):
        if not self.lan_last_result:
            return ["No LAN Throughput result available."]
        result = self.lan_last_result
        return [
            f"Server: {result.get('host', 'N/A')}:{result.get('port', 'N/A')}",
            f"Direction: {result.get('direction', 'N/A')}",
            f"Throughput: {result.get('throughput', 'N/A')}",
            f"Duration: {result.get('seconds', 'N/A')}",
            f"Transferred: {result.get('transferred', 'N/A')}",
            f"Retransmits: {result.get('retransmits', 'N/A')}",
            "",
            "Diagnosis:",
            result.get("diagnosis", "N/A"),
        ]

    def _report_gateway_stability_lines(self):
        if not self.gateway_last_stats:
            return ["No Gateway Stability result available."]
        stats = self.gateway_last_stats
        def ms_value(key, empty="N/A"):
            value = stats.get(key)
            return empty if value is None else f"{value:.1f} ms"
        return [
            f"Target: {stats.get('target', 'N/A')}",
            f"Sent: {stats.get('sent', 0)}",
            f"Received: {stats.get('received', 0)}",
            f"Lost: {stats.get('lost', 0)}",
            f"Packet Loss: {stats.get('loss_pct', 0):.1f}%",
            f"Current: {ms_value('current_ms', 'Timeout')}",
            f"Average: {ms_value('avg_ms')}",
            f"Maximum: {ms_value('max_ms')}",
            f"Jitter: {ms_value('jitter_ms')}",
            f"Spikes: {stats.get('spike_count', 0)} over {stats.get('spike_threshold_ms', 0):.0f} ms",
            "",
            "Diagnosis:",
            stats.get("diagnosis", "N/A"),
        ]

    def _report_loaded_latency_lines(self):
        if not self.loaded_last_result:
            return ["No Loaded Latency result available."]
        result = self.loaded_last_result
        idle = result.get("idle", {})
        loaded = result.get("loaded", {})
        increase = result.get("increase_ms")
        def ms_value(data, key):
            value = data.get(key)
            return "N/A" if value is None else f"{value:.1f} ms"
        return [
            f"Ping Target: {result.get('target', 'N/A')}",
            f"Idle Avg: {ms_value(idle, 'avg_ms')}",
            f"Loaded Avg: {ms_value(loaded, 'avg_ms')}",
            f"Increase: {'N/A' if increase is None else f'+{increase:.1f} ms'}",
            f"Loaded Max: {ms_value(loaded, 'max_ms')}",
            f"Loaded Jitter: {ms_value(loaded, 'jitter_ms')}",
            f"Loaded Loss: {loaded.get('loss_pct', 0):.1f}%",
            f"Download: {result.get('download', 'N/A')}",
            f"Upload: {result.get('upload', 'N/A')}",
            "",
            "Diagnosis:",
            result.get("diagnosis", "N/A"),
        ]

    def _report_route_health_lines(self):
        if not self.route_last_result:
            return ["No Route Health result available."]
        result = self.route_last_result
        lines = [
            f"Download: {result.get('download', 'N/A')}",
            f"Upload: {result.get('upload', 'N/A')}",
            f"Detection: {result.get('note', 'N/A') or 'N/A'}",
            "",
            "Paths:",
        ]
        for key in ("gateway", "isp", "public"):
            stats = result.get("paths", {}).get(key, {})
            def ms_value(name):
                value = stats.get(name)
                return "N/A" if value is None else f"{value:.1f} ms"
            lines.extend([
                f"{stats.get('label', key)} ({stats.get('target', 'N/A')}):",
                f"  Sent/Received/Lost: {stats.get('sent', 0)}/{stats.get('received', 0)}/{stats.get('lost', 0)}",
                f"  Loss: {stats.get('loss_pct', 0):.1f}%",
                f"  Avg/Max/Jitter: {ms_value('avg_ms')} / {ms_value('max_ms')} / {ms_value('jitter_ms')}",
                f"  Spikes: {stats.get('spike_count', 0)} over {stats.get('spike_threshold_ms', 0):.0f} ms",
            ])
        lines.extend(["", "Diagnosis:", result.get("diagnosis", "N/A")])
        return lines

    def _report_speedtest_history_lines(self):
        rows = self._speedtest_history_rows()
        if not rows:
            path = self._speedtest_history_path()
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    loaded = json.load(handle)
            except (OSError, json.JSONDecodeError):
                loaded = []
            rows = [row for row in loaded if isinstance(row, list)]

        if not rows:
            return ["No Speed Test history available."]

        headers = ["Time", "Down", "Up", "Latency", "Jitter", "Server", "Data"]
        lines = [" | ".join(headers)]
        for row in rows[:10]:
            padded = [str(value) for value in row[:len(headers)]]
            padded.extend([""] * (len(headers) - len(padded)))
            lines.append(" | ".join(padded))
        return lines

    def _report_dns_lookup_lines(self):
        result = self.dns_result_box.toPlainText().strip()
        if not result or result == "Running lookup...":
            return ["No DNS lookup result available."]
        query = self.dns_input.text().strip() or "N/A"
        record = self.dns_record_combo.currentText() if self.dns_record_combo is not None else "A"
        return [f"Query: {query}", f"Record: {record}", "", result]

    def _report_traceroute_lines(self):
        rows = self._table_rows(self.tr_table)
        raw = self.trace_raw_box.toPlainText().strip() if self.trace_raw_box is not None else ""
        if not rows and not raw:
            return ["No traceroute result available."]

        target = self.trace_input.text().strip() if self.trace_input is not None else self.host_input.text().strip()
        lines = [f"Target: {target or 'N/A'}"]
        if rows:
            lines.append("Hop | IP | Host | Latency")
            lines.extend(" | ".join(row) for row in rows)
        if raw:
            lines.extend(["", "Raw output:", raw])
        return lines

    def _report_network_scanner_lines(self):
        if not self.port_scan_results:
            return ["No Network Scanner results available."]

        lines = [
            f"Hosts found: {self.port_scan_host_count}",
            f"Port rows: {self.port_scan_result_count}",
            f"Open ports: {self.port_scan_open_count}",
            f"Filtered/dropped: {self.port_scan_filtered_count}",
            "",
            "Host | Hostname | MAC | Port | Service | State | Latency | Details",
        ]
        for result in self.port_scan_results:
            latency = "N/A" if result.get("latency") is None else f"{result.get('latency'):.1f} ms"
            lines.append(
                " | ".join([
                    str(result.get("host", "")),
                    str(result.get("hostname", "N/A")),
                    str(result.get("mac", "N/A")),
                    "" if result.get("port") in (None, "") else str(result.get("port")),
                    str(result.get("service", "")),
                    str(result.get("status", "")),
                    latency,
                    clean_probe_text(str(result.get("error", "")), max_len=260),
                ])
            )
        return lines

    def _table_rows(self, table):
        rows = []
        if table is None:
            return rows
        for row in range(table.rowCount()):
            values = []
            for col in range(table.columnCount()):
                item = table.item(row, col)
                values.append(item.text() if item is not None else "")
            rows.append(values)
        return rows

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
        return format_mbps(value)

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
        if self.loaded_latency_worker is not None and self.loaded_latency_worker.isRunning():
            self.loaded_latency_worker.stop()
        if self.route_health_worker is not None and self.route_health_worker.isRunning():
            self.route_health_worker.stop()
        if self.gateway_stability_worker is not None and self.gateway_stability_worker.isRunning():
            self.gateway_stability_worker.stop()
        self.stop_lan_server()
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
