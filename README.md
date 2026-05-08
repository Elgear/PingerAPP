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

## Optional Speed Test CLI

The Speed Test window uses the official Ookla Speedtest CLI when available. Put the Windows binary at:

```text
tools/speedtest/speedtest.exe
```

The app also falls back to `speedtest` on `PATH`. Do not commit or redistribute the Ookla binary until its EULA/redistribution terms are reviewed for the intended use.

## Packaging Notes

For a PC install, package the PyQt app with PyInstaller or a similar tool, then wrap the output with an installer such as Inno Setup. The installer should include:

- the PingerApp executable and Python runtime bundle,
- required Python libraries,
- optional bundled tools such as `tools/speedtest/speedtest.exe` if redistribution is allowed,
- a Start Menu shortcut,
- a note that ICMP ping may require elevated permissions depending on the machine.
