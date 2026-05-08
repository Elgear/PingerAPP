# PingerApp 0.1.0

Initial public Windows release candidate.

## Installer

Download from the GitHub release assets:

```text
PingerAppSetup-0.1.0.exe
```

SHA256:

```text
F27DD934522CE6BCD09F4198D50D78094D54023C5320B10AF443292E8B9BB340
```

The installer was built with:

- Python 3.13.7
- PyInstaller 6.20.0
- Inno Setup 6.7.1

## Included Tools

- Live ping latency, jitter, packet-loss monitoring, graphs, alerts, and saved host presets.
- Speed Test and Speed Targets using bundled LibreSpeed CLI.
- Adapter Info with link speed, gateway, DNS, duplex where available, interface counters, and Counter Watch.
- LAN Throughput using bundled iperf3.
- Gateway Stability, Loaded Latency, Route Health, and Wi-Fi Diagnostics.
- Network Scanner with host discovery, manual port entry, presets, service names, and optional light probes.
- HTTP Test, DNS / WHOIS, DNS Compare, MTU Test, and Traceroute.
- Help window and Report builder with TXT and CSV export.

## Validation

Tested locally:

- Installer creates and removes the app successfully.
- Packaged app opens the main `Home Pinger` window.
- Most diagnostic modules were manually checked on Windows.
- Bundled LibreSpeed, iperf3, and third-party notices are included.

## Notes

- The installer is unsigned, so Windows SmartScreen may show a warning.
- Raw ICMP ping can require elevated network permissions on some systems.
- Only run Network Scanner against networks and hosts you own or are authorized to troubleshoot.
- Keep `THIRD_PARTY_NOTICES.md` with the release.
- PingerApp source code is GPL-3.0-only because the packaged app uses the GPL distribution path for PyQt5.
