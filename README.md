# PingerApp

PyQt5 desktop tool for monitoring latency, packet loss, jitter, DNS lookups, and traceroute output.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\PingerApp\PingerApp.py
```

Raw ICMP ping can require elevated network privileges on some systems. If the app cannot create a raw socket, it will now show an error when pinging starts instead of failing before the window opens.

Host Info includes local hostname, local IP, first-hop gateway, public IP, public ISP, and primary MAC address. ISP metadata is looked up with a timeout-bound public IP metadata request and falls back to `N/A` if unavailable.

The right-side Tools panel opens separate diagnostic windows:

- Speed Test: LibreSpeed-based internet speed test with persistent history.
- Network Scanner: safe TCP connect scanning for one host or an IPv4 subnet, with grouped Target/Scan/Display controls, group-level help beside each section label, common CIDR size selection, named port presets with exact-port preview, stop control, grouped-by-host wrapped results, separate Host State, Open Ports, and Port State columns, result filtering, highlighted open/live rows, host discovery, full-port/specific-port presets, open/closed/filtered state reporting, service names, optional light service probes, progress, latency, and hostname/MAC lookup through reverse DNS, ARP, and Windows NetBIOS where available.

MAC addresses can only be discovered when the target exposes them on the local network path. Routed hosts usually show no MAC address, or only the next-hop device in the local ARP cache.
- DNS / WHOIS: forward/reverse lookup, selectable DNS record lookup through `nslookup`, and optional IP/ASN/ISP ownership metadata.
- Traceroute: target, max-hop, and timeout controls with structured hop output plus raw traceroute text.
- Alerts: threshold alert log.

## LibreSpeed Speed Test

The Speed Test window uses the bundled open-source LibreSpeed CLI at:

```text
tools/librespeed/librespeed-cli.exe
```

The app also falls back to `librespeed-cli` on `PATH` if the bundled executable is not present. The Speed Test window auto-loads the public server list, supports automatic server selection, manual server refresh/selection, configurable test duration, progress display, persistent history for the last 10 runs, data-used reporting, and optional share URL generation when the selected LibreSpeed server supports it.

The bundled binary is LibreSpeed CLI v1.0.13 for Windows x64. Its source release, checksum, and license are recorded in `tools/librespeed/VERSION.txt` and `tools/librespeed/LICENSE.librespeed-cli.txt`. LibreSpeed CLI is licensed under LGPL-3.0, so keep it replaceable as a separate executable in packaged builds.

## Packaging Notes

For a PC install, package the PyQt app with PyInstaller or a similar tool, then wrap the output with an installer such as Inno Setup. The installer should include:

- the PingerApp executable and Python runtime bundle,
- required Python libraries,
- bundled `tools/librespeed/librespeed-cli.exe`,
- LibreSpeed CLI license attribution,
- a Start Menu shortcut,
- a note that ICMP ping may require elevated permissions depending on the machine.
