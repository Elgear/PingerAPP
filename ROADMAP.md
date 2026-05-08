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
- DNS / WHOIS
- Traceroute
- Alerts

Network Scanner replaces the original Port Check idea. Do not add a separate Port Check unless we later want a small quick-check shortcut for one host and one port.

## Next Features

1. HTTP Test
   - URL input.
   - Method: GET / HEAD.
   - Follow redirects checkbox.
   - Timeout.
   - Results: status code, response time, final URL, redirect count, TLS certificate summary for HTTPS, server/header summary, and error details.

2. DNS Compare
   - Hostname input.
   - Record type.
   - Compare resolvers: System, Cloudflare, Google, Quad9.
   - Results: resolver, response time, answers, and error.
   - Start with `nslookup` subprocesses before adding dependencies.

3. MTU Test
   - Target.
   - Start/max size.
   - Windows-first implementation using `ping -f -l`.
   - Results: largest non-fragmenting payload, estimated MTU, and raw command output/details.

4. Report
   - Checkboxes for sections:
     - Host Info
     - Ping stats
     - Speed Test history
     - Last DNS lookup
     - Last traceroute
     - Network Scanner results
   - Preview.
   - Save as `.txt`.

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
