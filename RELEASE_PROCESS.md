# Release Process

Use this checklist when publishing a Windows release.

## 1. Build

```powershell
.\scripts\setup_packaging_env.ps1
.\scripts\build_windows.ps1 -Clean
.\scripts\build_installer.ps1
```

## 2. Verify

```powershell
Get-FileHash .\installer_output\PingerAppSetup-0.1.0.exe -Algorithm SHA256
```

Smoke-test:

- `dist\PingerApp\PingerApp.exe` opens the real `Home Pinger` window.
- Installer completes.
- Start Menu shortcut launches the app.
- Help and Report open.
- Speed Test finds LibreSpeed.
- LAN Throughput finds iperf3.
- Adapter Info opens.
- Uninstall works.

## 3. Commit Release Notes

Update:

- `CHANGELOG.md`
- `RELEASE_NOTES_*.md`
- `checksums\*.sha256`
- `PACKAGING.md` if the build process changed.

## 4. Tag

```powershell
git tag v0.1.0
git push origin v0.1.0
```

## 5. Publish On GitHub

Open:

```text
https://github.com/Grzybkins/PingerAPP/releases/new
```

Create the release:

- Tag: `v0.1.0`
- Title: `PingerApp 0.1.0`
- Description: paste from `RELEASE_NOTES_0.1.0.md`
- Assets:
  - `installer_output\PingerAppSetup-0.1.0.exe`
  - `checksums\PingerAppSetup-0.1.0.sha256`

If the installer is unsigned or not widely tested, mark the release as a pre-release.
