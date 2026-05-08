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

PingerApp has an Inno Setup script at:

```text
installer\PingerApp.iss
```

To build the installer after creating the PyInstaller output:

```powershell
.\scripts\build_installer.ps1
```

To rebuild the PyInstaller output and then build the installer:

```powershell
.\scripts\build_installer.ps1 -BuildApp
```

The script looks for `ISCC.exe` on `PATH`, in the winget per-user install location, and in the default Inno Setup 6 machine install locations. If Inno Setup is installed somewhere else, pass the compiler path:

```powershell
.\scripts\build_installer.ps1 -InnoSetupCompiler "C:\Path\To\ISCC.exe"
```

The installer output is written to:

```text
installer_output\PingerAppSetup-0.1.0.exe
```

The local installer build has been verified with Inno Setup 6.7.1. The latest generated installer hash was:

```text
SHA256 D6DEBCC685E6B1DA27A2B6766FE65D0F19DC20AE87369F42DDB6DCCDECAA3AB1
```

The installer copies the full `dist\PingerApp` folder, adds a Start Menu shortcut, offers an optional desktop shortcut, and copies `README.md` plus `THIRD_PARTY_NOTICES.md` to the install root.

## Clean PC Test

Before calling the installer complete, test it on a Windows PC or VM that does not have the development environment installed. Check:

- app installs and launches from the Start Menu
- Help and Report open
- Speed Test finds bundled LibreSpeed CLI
- Speed Targets can refresh LibreSpeed targets
- LAN Throughput finds bundled iperf3
- Adapter Info opens and reports adapter data
- uninstall removes the app folder and shortcuts
