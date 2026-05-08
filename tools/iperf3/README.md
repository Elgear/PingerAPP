# Bundled iperf3

This folder contains iperf3 3.21 for Windows x64 from:

https://github.com/ar51an/iperf3-win-builds/releases/tag/3.21

Included runtime files:

- `iperf3.exe`
- `cygwin1.dll`

License and notice files:

- `LICENSE.iperf3.txt`: upstream iperf3 license and bundled-source notices.
- `LICENSE.iperf3-win-builds.txt`: license for the Windows build repository.
- `LICENSE.cygwin-lgpl-3.0.txt`: LGPL-3.0 license text for the Cygwin runtime.
- `VERSION.txt`: version, source, and archive checksum record.
- `CHECKSUMS.txt`: local binary checksums.

Keep `iperf3.exe` and `cygwin1.dll` together. The LAN Throughput tool expects `iperf3.exe` at this path and the Windows binary needs the Cygwin runtime DLL beside it.
