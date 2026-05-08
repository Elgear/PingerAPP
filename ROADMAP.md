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
- Network Scanner
- HTTP Test
- DNS / WHOIS
- DNS Compare
- MTU Test
- Traceroute
- Alerts

Network Scanner replaces the original Port Check idea. Do not add a separate Port Check unless we later want a small quick-check shortcut for one host and one port.

## Next Features

1. Report
   - Checkboxes for sections:
     - Host Info
     - Ping stats
     - Speed Test history
     - Last DNS lookup
     - Last traceroute
     - Network Scanner results
   - Preview.
   - Save as `.txt`.

## Completed Tool Milestones

- HTTP Test: URL input, GET/HEAD, redirect control, optional self-signed certificate allowance for local HTTPS tests, timeout, status code, response time, final URL, redirect count, TLS certificate summary, headers, and error details.
- DNS Compare: hostname input, record type selector, System/Cloudflare/Google/Quad9 resolver comparison, response timing, answers, and error details using `nslookup`.
- MTU Test: target input, start/max payload, Windows-first `ping -f -l` probing, largest non-fragmenting payload, estimated MTU, and raw ping output/details.

## Packaging

- Create a PyInstaller build configuration.
- Include bundled `tools/librespeed/librespeed-cli.exe`.
- Include LibreSpeed CLI license and attribution files.
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
