# Security Policy

## Supported Versions

Security fixes are handled on the latest published release unless a newer policy is added.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a Vulnerability

If the repository has GitHub private vulnerability reporting enabled, use that first. Otherwise, contact the maintainer privately before opening a public issue for a security-sensitive bug.

For non-sensitive bugs, use a normal GitHub issue.

Please include:

- PingerApp version.
- Windows version.
- Whether you used the installer or ran from source.
- Steps to reproduce.
- Any relevant screenshots or log output.

## Security And Privacy Notes

PingerApp is a local network troubleshooting tool. It does not require accounts, API keys, or secrets.

Some tools intentionally send network traffic:

- Ping, traceroute, DNS lookup, MTU test, gateway stability, route health, and loaded latency send diagnostic traffic to the selected targets.
- Network Scanner performs TCP connect probes against the host or subnet you enter. Only scan systems and networks you own or are authorized to troubleshoot.
- Speed Test and Speed Targets use public LibreSpeed servers when run.
- Host Info can call public IP metadata services to show public IP, ISP, ASN, and rough location.
- DNS Compare sends the entered hostname to the selected resolvers.

Local data such as speed-test history, saved target presets, and exported reports is stored under the local `data` directory when running from source or beside the installed app/runtime path depending on the packaged build.

## Distribution Notes

The Windows installer is currently unsigned. Windows SmartScreen may warn users until the project uses code signing and builds release trust over time.

Before publishing a release:

- Build with `.\scripts\setup_packaging_env.ps1` and `.\scripts\build_windows.ps1 -Clean`.
- Build the installer with `.\scripts\build_installer.ps1`.
- Smoke-test the packaged executable.
- Test install and uninstall on a clean Windows PC or VM.
- Publish the installer checksum with the release.
- Keep `THIRD_PARTY_NOTICES.md` with the installer and repository.
