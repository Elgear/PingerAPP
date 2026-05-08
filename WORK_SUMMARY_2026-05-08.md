# Work Summary - 2026-05-08

## Completed Today

- Reworked the main layout into clearer sections: Ping Panel, Monitoring, Graphs, DNS Lookup, Traceroute, Alert Log, and Speed Test.
- Widened the app window baseline to give the graphs and right-side tools more room.
- Widened and aligned the right-side DNS Lookup, Traceroute, and Alert Log frames.
- Moved the Speed Test button into the top Ping Panel next to Session.
- Improved Ping Panel spacing, including clearer Start/Stop and Pause/Resume spacing.
- Added Live Jitter beside Live Latency.
- Split health status into separate RTT Health and Jitter Health indicators.
- Changed graph history default to 30 pings, with a 10-100 range.
- Set the graph x-axis to show each ping count in increments of 1.
- Improved graph autoscaling and tick detail for latency and jitter.
- Added Default buttons for alert thresholds and history.
- Changed alert behavior from popups to an Alert Log window.
- Updated Alert Log behavior so every breached ping sample is recorded while its alert toggle is enabled.
- Added a separate Speed Test window using optional CLI JSON output.
- Restyled the Speed Test window and fixed its initial sizing.
- Added documentation for expected bundled LibreSpeed CLI location: `tools/librespeed/librespeed-cli.exe`.
- Reviewed Ookla Speedtest CLI redistribution terms and switched the planned packaged integration to LibreSpeed CLI.
- Updated the Speed Test worker to call LibreSpeed CLI JSON output with telemetry disabled.
- Bundled LibreSpeed CLI v1.0.13 for Windows x64 with checksum and LGPL-3.0 attribution notes.
- Added LibreSpeed server refresh/selection, configurable duration, optional share URL generation, test timestamp, data used, and server URL display.
- Removed the LibreSpeed packet-loss row, added Speed Test run history, and added a duration-based running progress bar.
- Auto-loaded the LibreSpeed server list on Speed Test open and added clearer handling for selected servers that return no result.
- Added public ISP lookup, hostname, and primary MAC address to Host Info, and reused the ISP lookup in Speed Test results when LibreSpeed omits ISP data.
- Persisted the last 10 Speed Test history rows to local runtime data.
- Replaced embedded DNS and Traceroute side panels with Tools launcher buttons and separate DNS / WHOIS and Traceroute diagnostic windows.
- Expanded DNS / WHOIS with record lookup, reverse lookup, and optional IP/ASN/ISP metadata.
- Expanded Traceroute with target, max-hop, timeout, structured hop table, and raw output controls.
- Moved Speed Test from the Ping Panel into the Tools launcher.
- Added a Port Check tool window for TCP connectivity checks across one or more ports with latency and error details.
- Upgraded Port Check into a safe TCP Port Scanner with presets, port ranges, service names, progress, and open-only display.
- Expanded Port Scanner into a Network Scanner with CIDR host discovery, concurrent TCP scanning, open/closed/filtered state reporting, full-port scan support for single hosts, optional light service probes, and local MAC lookup where available.
- Added Network Scanner stop control, clearer Single host/Subnet target controls with common CIDR sizes, inline guidance for parallel probes, result filtering, and full-row highlighting for scan states.
- Grouped Network Scanner results by host, carried hostname/MAC identity into port rows, added reverse DNS/ARP/Windows NetBIOS identity lookup, and replaced the wide guidance banner with per-control help buttons.
- Reworked Network Scanner layout into Target, Scan, and Display groups with one help button per group, named port presets plus exact-port preview, wrapped grouped results, and separate Host State and Port State columns.
- Moved Network Scanner group help beside section labels and split host summaries into separate Host State and Open Ports columns before per-port details.
- Moved Network Scanner section labels and help buttons outside the framed control contents so the boxes contain only controls.
- Added extra cell and header padding to the Network Scanner results table so auto-sized columns are easier to read.
- Wrapped long Network Scanner Details text across multiple lines while preserving the full text in the tooltip.
- Defaulted the Network Scanner host field from Host Info, preferring the gateway and falling back to the first host in the local IP range.
- Updated the roadmap around the Tools model, marking Network Scanner as the Port Check replacement and putting HTTP Test, DNS Compare, MTU Test, and Report next.
- Added an HTTP Test tool window with GET/HEAD requests, redirect control, timeout, status, response timing, final URL, TLS certificate summary, headers, and error details.
- Added an HTTP Test option to ignore TLS certificate errors for local HTTPS services using self-signed certificates.
- Added a DNS Compare tool window using `nslookup` to compare System DNS, Cloudflare, Google, and Quad9 answers and response times.
- Added an MTU Test tool window that probes non-fragmenting ping payload sizes and reports estimated path MTU with raw output details.
- Added a Report tool with selectable sections, preview, and `.txt` export for Host Info, Adapter Info, ping stats, Speed Test history, last DNS lookup, last traceroute, and Network Scanner results.
- Added an offline Help window explaining main controls, threshold sliders, monitoring boxes, graphs, diagnostic tools, report generation, and common result meanings.
- Added an Adapter Info tool for active adapter link speed, connection type, IPv4, gateway, DNS servers, MAC address, duplex setting where available, and 100 Mbps vs gigabit diagnosis.
- Added Adapter Info to the Report tool and Help documentation.
- Added a LAN Throughput tool using bundled iperf3 client/server mode to test local network speed separately from internet speed.
- Added LAN Throughput to the Report tool, Help documentation, README, and packaging notes.
- Bundled iperf3 3.21 for Windows x64 with Cygwin runtime DLL, checksums, source records, and license notices.
- Improved LAN Throughput guidance and iperf3 connection errors so users enter another PC running iperf3 instead of assuming the gateway/router is a valid server.
- Added a Gateway Stability tool for repeated first-hop ping monitoring with latency, packet loss, jitter, spike counts, raw ping log, diagnosis, Help, and Report support.
- Added packaging notes in `README.md`.
- Kept changes tracked in `CHANGELOG.md` and future work in `ROADMAP.md`.

## Current State

- The app runs as a PyQt5 desktop tool from `PingerApp/PingerApp.py`.
- Ping monitoring shows RTT latency, jitter, packet loss, rolling stats, health indicators, and graphs.
- DNS lookup and traceroute are available in the right-side panel.
- Traceroute uses the current Host field and shows a target label.
- Alert Log opens in a separate window from the right-side Alert Log button.
- Speed Test opens in a separate window from the top Ping Panel button.
- Speed Test uses the bundled LibreSpeed CLI at `tools/librespeed/librespeed-cli.exe`, with `librespeed-cli` on PATH as a fallback.
- Speed Test can auto-select a server or use a refreshed LibreSpeed server list for manual selection.
- Report opens from the Tools launcher and can save a plain text troubleshooting snapshot.
- Help opens from the Tools launcher and provides built-in offline documentation.
- Adapter Info opens from the Tools launcher and helps identify local 100 Mbps link negotiation before blaming ISP speed.
- LAN Throughput opens from the Tools launcher and uses bundled `tools/iperf3/iperf3.exe`, with `iperf3` on PATH as a fallback.
- Gateway Stability opens from the Tools launcher and defaults to the detected gateway when available.

## Verification Used

- Repeated syntax checks with:

```powershell
python -m py_compile PingerApp\PingerApp.py check_qt.py
```

- Repeated offscreen Qt checks for layout, widget state, alert logging, graph redraws, Speed Test parsing, and window behavior.
- Cleaned generated `__pycache__` folders after checks.

## Open Decisions

- Make sure the bundled LibreSpeed CLI and license files are included in the installer.
- Make sure bundled iperf3 runtime and license files are included in the installer.
- Decide installer approach for Windows PCs.
- Decide whether the app should require administrator privileges for raw ICMP ping or use another ping backend.

## Recommended Next Work

- Create a PyInstaller build configuration.
- Test a packaged build on a clean Windows PC.
- Add the bundled LibreSpeed CLI and license files to the installer.
- Add bundled iperf3 runtime and license files to the installer.
- Split the large `PingerApp.py` file into focused modules once layout and behavior settle.
- Extract latency, loss, jitter, health, and alert calculations into testable functions.
- Add saved host presets.
- Add CSV export for ping history and alert logs.
- Add a selectable ping interval.
