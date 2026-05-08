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

## LibreSpeed Speed Test

The Speed Test window uses the bundled open-source LibreSpeed CLI at:

```text
tools/librespeed/librespeed-cli.exe
```

The app also falls back to `librespeed-cli` on `PATH` if the bundled executable is not present. The Speed Test window supports automatic server selection, manual server refresh/selection, configurable test duration, progress display, run history, data-used reporting, and optional share URL generation when the selected LibreSpeed server supports it.

The bundled binary is LibreSpeed CLI v1.0.13 for Windows x64. Its source release, checksum, and license are recorded in `tools/librespeed/VERSION.txt` and `tools/librespeed/LICENSE.librespeed-cli.txt`. LibreSpeed CLI is licensed under LGPL-3.0, so keep it replaceable as a separate executable in packaged builds.

## Packaging Notes

For a PC install, package the PyQt app with PyInstaller or a similar tool, then wrap the output with an installer such as Inno Setup. The installer should include:

- the PingerApp executable and Python runtime bundle,
- required Python libraries,
- bundled `tools/librespeed/librespeed-cli.exe`,
- LibreSpeed CLI license attribution,
- a Start Menu shortcut,
- a note that ICMP ping may require elevated permissions depending on the machine.
