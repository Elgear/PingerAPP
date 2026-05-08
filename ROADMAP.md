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

1. Gateway Stability Test
   - Ping the default gateway during a speed test.
   - If gateway latency spikes or drops packets under load, the local router, Wi-Fi, or cable path is struggling.

2. Bufferbloat / Loaded Latency Test
   - Measure ping latency while download or upload is saturated.
   - Show whether the line gets slow or unstable under load, even if raw speed is acceptable.

3. Interface Error Counters
   - Show adapter errors and discards where available.
   - Cable or port issues often show CRC errors, renegotiation, packet drops, or unstable link state.

4. Route / Hop Health During Speed Test
   - Run continuous pings to gateway, ISP first hop, and a public target such as 1.1.1.1.
   - Identify whether slowdown starts locally, at the ISP edge, or further out.

5. Wi-Fi Diagnostics
   - Show SSID, band, channel, signal strength, link rate, and protocol such as Wi-Fi 4/5/6/7.
   - Important because 1 Gbps internet over weak 2.4 GHz Wi-Fi may never show 1 Gbps.

6. DNS / CDN Target Check
   - Compare multiple speed test servers and show server distance/provider where available.
   - Some speed tests are limited by a poor server or CDN target selection.

7. Packaging
   - PyInstaller build configuration.
   - Include bundled LibreSpeed CLI and license files.
   - Include bundled iperf3 runtime and license files.
   - Test packaged build on a clean Windows PC.

## Completed Tool Milestones

- HTTP Test: URL input, GET/HEAD, redirect control, optional self-signed certificate allowance for local HTTPS tests, timeout, status code, response time, final URL, redirect count, TLS certificate summary, headers, and error details.
- DNS Compare: hostname input, record type selector, System/Cloudflare/Google/Quad9 resolver comparison, response timing, answers, and error details using `nslookup`.
- MTU Test: target input, start/max payload, Windows-first `ping -f -l` probing, largest non-fragmenting payload, estimated MTU, and raw ping output/details.
- Report: selectable sections for Host Info, Adapter Info, ping stats, LAN Throughput, Speed Test history, last DNS lookup, last traceroute, and Network Scanner results, with preview and `.txt` save.
- Help: offline guide covering the main controls, threshold sliders, monitoring boxes, graphs, diagnostic tools, report builder, and common result interpretation.
- Adapter Info: active adapter status, link speed, connection type, IPv4, gateway, DNS servers, MAC address, duplex setting where available, and 100 Mbps vs gigabit diagnosis.
- LAN Throughput: bundled iperf3 client/server mode to separate local LAN throughput issues from internet, router WAN, ISP profile, or speed test server issues.

## Packaging

- Create a PyInstaller build configuration.
- Include bundled `tools/librespeed/librespeed-cli.exe`.
- Include LibreSpeed CLI license and attribution files.
- Include bundled `tools/iperf3/iperf3.exe`, `tools/iperf3/cygwin1.dll`, and related license files.
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
