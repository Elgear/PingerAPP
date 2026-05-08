# PingerApp

PyQt5 desktop tool for monitoring latency, packet loss, jitter, DNS lookups, and traceroute output.

The Ping Panel supports saved Host presets so common gateways, public targets, and service IPs can be reused without retyping.

## Download

Windows builds are published from GitHub Releases:

```text
https://github.com/Elgear/PingerAPP/releases
```

For version `0.1.0`, download `PingerAppSetup-0.1.0.exe` and verify the checksum:

```text
SHA256 F27DD934522CE6BCD09F4198D50D78094D54023C5320B10AF443292E8B9BB340
```

The installer is currently unsigned, so Windows SmartScreen may show a warning.

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
- Adapter Info: active adapter link speed, status, type, IP, gateway, DNS, MAC, duplex setting where available, interface error/discard counters where Windows exposes them, timed Counter Watch transfer/error delta testing, and diagnosis for 100 Mbps vs gigabit negotiation or suspicious counters.
- LAN Throughput: bundled iperf3 client/server tool for testing local network throughput separately from internet speed.
- Gateway Stability: repeated first-hop ping monitor for gateway latency, packet loss, jitter, and spikes.
- Loaded Latency: bufferbloat check that compares idle ping latency with latency while LibreSpeed load is running.
- Route Health: LibreSpeed load plus simultaneous gateway, ISP first-hop, and public-target ping health checks to locate where slowdown starts.
- Wi-Fi Diagnostics: Windows Wi-Fi SSID, BSSID, signal, band, channel, protocol, link rates, authentication, cipher, and diagnosis for wireless speed limits.
- Speed Targets: select and compare LibreSpeed servers with short tests to detect poor speed test server/CDN target selection.
- Network Scanner: safe TCP connect scanning for one host or an IPv4 subnet, with grouped Target/Scan/Display controls, section header help beside each section label, common CIDR size selection, named port presets plus a manual port entry field with exact-port preview, stop control, grouped-by-host wrapped results, separate Host State, Open Ports, and Port State columns, result filtering, highlighted open/live rows, host discovery, full-port/specific-port presets, open/closed/filtered state reporting, service names, optional light service probes, progress, latency, and hostname/MAC lookup through reverse DNS, ARP, and Windows NetBIOS where available.
- HTTP Test: HTTP/HTTPS request diagnostics with GET/HEAD, redirect control, optional self-signed certificate allowance for local HTTPS tests, timing, final URL, TLS certificate summary, headers, and error details.
- DNS / WHOIS: forward/reverse lookup, selectable DNS record lookup through `nslookup`, and optional IP/ASN/ISP ownership metadata.
- DNS Compare: compare DNS answers and response times across System DNS, Cloudflare, Google, and Quad9 using `nslookup`.
- MTU Test: find the largest non-fragmenting ping payload and estimated path MTU, with raw ping output details.
- Traceroute: target, max-hop, and timeout controls with structured hop output plus raw traceroute text.
- Alerts: threshold alert log.
- Report: selectable troubleshooting report with preview, `.txt` export, and spreadsheet-friendly `.csv` export for Host Info, Adapter Info, ping stats, LAN Throughput, Gateway Stability, Loaded Latency, Route Health, Wi-Fi Diagnostics, Speed Targets, Speed Test history, last DNS lookup, last traceroute, and Network Scanner results.
- Help: offline field guide explaining the main panels, controls, graph readings, tool workflows, report output, and common diagnostic meanings.

MAC addresses can only be discovered when the target exposes them on the local network path. Routed hosts usually show no MAC address, or only the next-hop device in the local ARP cache.

## Security And Privacy

PingerApp is a local troubleshooting tool and does not require accounts, API keys, or secrets. Some diagnostics intentionally contact selected targets, public DNS resolvers, public IP metadata services, or public LibreSpeed servers when those tools are run.

Only run Network Scanner against networks and hosts you own or are authorized to troubleshoot. Security reporting guidance is in `SECURITY.md`.

## License

PingerApp source code is licensed under GPL-3.0-only. This matches the GPL distribution path for PyQt5. Third-party components remain under their own licenses; see `THIRD_PARTY_NOTICES.md`.

## LibreSpeed Speed Test

The Speed Test window uses the bundled open-source LibreSpeed CLI at:

```text
tools/librespeed/librespeed-cli.exe
```

The app also falls back to `librespeed-cli` on `PATH` if the bundled executable is not present. The Speed Test window auto-loads the public server list, supports automatic server selection, manual server refresh/selection, configurable test duration, progress display, persistent history for the last 10 runs, data-used reporting, and optional share URL generation when the selected LibreSpeed server supports it.

The bundled binary is LibreSpeed CLI v1.0.13 for Windows x64. Its source release, checksum, and license are recorded in `tools/librespeed/VERSION.txt` and `tools/librespeed/LICENSE.librespeed-cli.txt`. LibreSpeed CLI is licensed under LGPL-3.0, so keep it replaceable as a separate executable in packaged builds.

## LAN Throughput

The LAN Throughput window uses the bundled iperf3 executable at:

```text
tools/iperf3/iperf3.exe
```

The app also falls back to `iperf3` on `PATH` if the bundled executable is not present. Run the iperf3 server on one local machine and the client test from another machine to separate LAN, cable, switch, Wi-Fi, or adapter bottlenecks from ISP/WAN speed problems. Do not use the gateway/router IP unless that device is actually running iperf3; most home routers do not.

The bundled Windows build is iperf3 3.21 and includes `cygwin1.dll`. Source, license, and checksum records are in `tools/iperf3/VERSION.txt`, `tools/iperf3/CHECKSUMS.txt`, and the `tools/iperf3/LICENSE.*.txt` files.

## Packaging Notes

For a local Windows build, use the PyInstaller wrapper script:

```powershell
.\scripts\setup_packaging_env.ps1
.\scripts\build_windows.ps1 -Clean
```

The build output is written to `dist\PingerApp\PingerApp.exe`. Full packaging notes are in `PACKAGING.md`. Packaging should use the dedicated `.packaging-venv` created from stable Python 3.13; do not build the release installer from the older prerelease virtual environments.

For a PC install, build the PyInstaller output and then run the Inno Setup wrapper:

```powershell
.\scripts\build_windows.ps1 -Clean
.\scripts\build_installer.ps1
```

The installer script is `installer\PingerApp.iss`, and the generated setup executable is written to `installer_output\PingerAppSetup-0.1.0.exe`. The installer includes:

- the PingerApp executable and Python runtime bundle,
- required Python libraries,
- bundled `tools/librespeed/librespeed-cli.exe`,
- LibreSpeed CLI license attribution,
- bundled `tools/iperf3/iperf3.exe` and `tools/iperf3/cygwin1.dll`,
- iperf3, Windows build, and Cygwin license attribution,
- a Start Menu shortcut,
- an optional desktop shortcut,
- a note that ICMP ping may require elevated permissions depending on the machine.
