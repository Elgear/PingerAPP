# Third-Party Notices

## PyQt5 and Qt

PingerApp uses PyQt5 for its Windows desktop interface.

- PyQt project: https://riverbankcomputing.com/software/pyqt
- PyQt license path used here: GNU General Public License v3.0
- Qt runtime: bundled through PyQt5 wheels for packaged Windows builds
- Purpose: desktop user interface framework

PyQt is dual licensed under GPL v3 and a Riverbank commercial license. PingerApp is distributed under GPL-3.0-only to align with the GPL PyQt5 distribution path.

## LibreSpeed CLI

PingerApp can use LibreSpeed CLI for internet speed tests.

- Project: https://github.com/librespeed/speedtest-cli
- Bundled version: v1.0.13 for Windows x64
- License: GNU Lesser General Public License v3.0
- Purpose: download, upload, ping, and jitter measurements through LibreSpeed-compatible servers

PingerApp bundles LibreSpeed CLI as a separate replaceable executable at `tools/librespeed/librespeed-cli.exe`. The release source and checksum are recorded in `tools/librespeed/VERSION.txt`, and the LGPL-3.0 license text is included at `tools/librespeed/LICENSE.librespeed-cli.txt`.

## iperf3 for Windows

PingerApp uses iperf3 for local LAN throughput tests.

- Upstream project: https://github.com/esnet/iperf
- Windows build: https://github.com/ar51an/iperf3-win-builds
- Bundled version: iperf3 3.21 for Windows x64
- Bundled runtime: Cygwin `cygwin1.dll` 3.6.7-1.x86_64
- Purpose: LAN client/server throughput measurement

PingerApp bundles iperf3 as separate replaceable runtime files at `tools/iperf3/iperf3.exe` and `tools/iperf3/cygwin1.dll`.

License files are included in `tools/iperf3`:

- `LICENSE.iperf3.txt` for upstream iperf3 and its bundled source notices.
- `LICENSE.iperf3-win-builds.txt` for the Windows build repository.
- `LICENSE.cygwin-lgpl-3.0.txt` for the Cygwin runtime.

Version and checksum records are included at `tools/iperf3/VERSION.txt` and `tools/iperf3/CHECKSUMS.txt`.
