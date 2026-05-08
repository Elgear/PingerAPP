# Roadmap

## Product Direction

Keep the main window focused on live ping monitoring:

- Ping Panel
- Monitoring
- Graphs
- Host Info
- Tools launcher

All secondary diagnostics should open as separate non-modal tool windows from the Tools launcher.

## Tools Model

Current tools:

- Speed Test
- Adapter Info
- LAN Throughput
- Gateway Stability
- Loaded Latency
- Route Health
- Wi-Fi Diagnostics
- Speed Targets
- Network Scanner
- HTTP Test
- DNS / WHOIS
- DNS Compare
- MTU Test
- Traceroute
- Alerts
- Report
- Help

Network Scanner replaces the original Port Check idea. Do not add a separate Port Check unless we later want a small quick-check shortcut for one host and one port.

## Next Features

1. Packaging
   - Test packaged build on a clean Windows PC.
   - Create an installer, likely with Inno Setup.

## Completed Tool Milestones

- HTTP Test: URL input, GET/HEAD, redirect control, optional self-signed certificate allowance for local HTTPS tests, timeout, status code, response time, final URL, redirect count, TLS certificate summary, headers, and error details.
- DNS Compare: hostname input, record type selector, System/Cloudflare/Google/Quad9 resolver comparison, response timing, answers, and error details using `nslookup`.
- MTU Test: target input, start/max payload, Windows-first `ping -f -l` probing, largest non-fragmenting payload, estimated MTU, and raw ping output/details.
- Report: selectable sections for Host Info, Adapter Info, ping stats, LAN Throughput, Gateway Stability, Loaded Latency, Speed Test history, last DNS lookup, last traceroute, and Network Scanner results, with preview and `.txt` save.
- Help: offline guide covering the main controls, threshold sliders, monitoring boxes, graphs, diagnostic tools, report builder, and common result interpretation.
- Adapter Info: active adapter status, link speed, connection type, IPv4, gateway, DNS servers, MAC address, duplex setting where available, interface error/discard counters where available, timed Counter Watch transfer/error delta testing, and 100 Mbps vs gigabit/counter diagnosis.
- LAN Throughput: bundled iperf3 client/server mode to separate local LAN throughput issues from internet, router WAN, ISP profile, or speed test server issues.
- Gateway Stability: repeated first-hop ping monitor for gateway latency, packet loss, jitter, spikes, raw ping log, and local-vs-upstream diagnosis.
- Loaded Latency: bufferbloat check that captures idle ping baseline, runs LibreSpeed load, measures loaded ping latency/loss/jitter, and reports latency increase under load.
- Route Health: LibreSpeed load plus gateway, ISP first-hop, and public-target ping health checks to identify whether slowdown starts locally, at the ISP edge, or farther upstream.
- Wi-Fi Diagnostics: Windows Wi-Fi SSID, BSSID, signal, band, channel, protocol, link rates, security details, and diagnosis for wireless speed limits.
- Speed Targets: selectable short LibreSpeed comparisons across multiple servers to catch poor server/CDN target selection or routing differences.

## Packaging

- PyInstaller spec and Windows build script are in place.
- Local PyInstaller one-folder build has been run and smoke-tested.
- Build includes bundled `tools/librespeed/librespeed-cli.exe`.
- Build includes LibreSpeed CLI license and attribution files.
- Build includes bundled `tools/iperf3/iperf3.exe`, `tools/iperf3/cygwin1.dll`, and related license files.
- Test a packaged build on a clean Windows PC.
- Create an installer, likely with Inno Setup.

## Refactor Plan

The current `PingerApp.py` is large. Do not split it before the next tool unless it starts slowing development down. After HTTP Test or DNS Compare, split along clear tool boundaries:

- `main.py`
- `workers.py`
- `speedtest_tool.py`
- `network_scanner_tool.py`
- `dns_tool.py`
- `traceroute_tool.py`
- `http_tool.py`

Also extract latency, loss, jitter, health, and alert calculations into testable functions/modules.

## Later Ideas

- Saved target presets.
- CSV export for ping history, alert logs, speed test history, and scanner results.
- Selectable ping interval.
- Compact always-on-top monitor mode.
