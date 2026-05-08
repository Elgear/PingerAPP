# Packaging

PingerApp uses PyInstaller for the first Windows distributable build.

## Build

Use the repository root as the working directory:

```powershell
.\scripts\build_windows.ps1 -Clean
```

The script uses `.\venv\Scripts\python.exe` by default because that local environment currently has PyInstaller available. To use another environment:

```powershell
.\scripts\build_windows.ps1 -Python .\PingerApp\env\Scripts\python.exe -Clean
```

That environment must have PyInstaller plus the app dependencies from `requirements.txt`.

## Output

The one-folder build is written to:

```text
dist\PingerApp\
```

The executable is:

```text
dist\PingerApp\PingerApp.exe
```

With PyInstaller 6, bundled runtime data is placed below:

```text
dist\PingerApp\_internal\
```

The app searches PyInstaller's runtime bundle path, so bundled tools under `_internal\tools` are found automatically.

## Bundled Runtime Tools

The PyInstaller spec includes:

- `tools\librespeed\librespeed-cli.exe`
- `tools\librespeed\LICENSE.librespeed-cli.txt`
- `tools\librespeed\VERSION.txt`
- `tools\iperf3\iperf3.exe`
- `tools\iperf3\cygwin1.dll`
- `tools\iperf3\LICENSE.*.txt`
- `tools\iperf3\VERSION.txt`
- `tools\iperf3\CHECKSUMS.txt`
- `THIRD_PARTY_NOTICES.md`

Do not bundle `tools\speedtest\speedtest.exe`; the app uses LibreSpeed CLI instead.

## Smoke Test

After building, run:

```powershell
.\dist\PingerApp\PingerApp.exe
```

Check at minimum:

- main window starts
- Help opens
- Report opens
- Speed Test finds bundled LibreSpeed CLI
- Speed Targets can refresh LibreSpeed targets
- LAN Throughput finds bundled iperf3
- Adapter Info opens on Windows

## Installer

The next packaging step is an installer, likely Inno Setup, that installs the `dist\PingerApp` folder, creates a Start Menu shortcut, and includes `THIRD_PARTY_NOTICES.md`.
