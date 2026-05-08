# Changelog

## 2026-05-08

- Reviewed Ookla Speedtest CLI redistribution terms and documented that PingerApp should not bundle the Ookla binary by default.
- Selected LibreSpeed CLI as the open-source speed test path for future packaged builds.
- Switched the Speed Test integration from Ookla Speedtest CLI to LibreSpeed CLI using JSON output with telemetry disabled.
- Updated packaging notes to use `tools/librespeed/librespeed-cli.exe` and include LibreSpeed LGPL-3.0 attribution when bundled.
- Bundled LibreSpeed CLI v1.0.13 for Windows x64 with its license and checksum record.

## 2026-05-07

- Deferred raw ICMP socket creation until ping start and added socket cleanup on stop/close.
- Treated ping timeouts as missing latency samples so latency averages and jitter are not skewed by fake `0 ms` values.
- Made latency, loss, and jitter alert toggles control the corresponding alert behavior.
- Moved host information refresh to a background worker so startup is less likely to freeze.
- Added `.gitignore`, `requirements.txt`, and `README.md`.
- Added this changelog and a roadmap file to track changes and ideas.
- Moved DNS lookup and Start-button target resolution into background workers.
- Capped latency/history slider widths so graphs expand with the window while controls stay aligned.
- Capped the reset button width so it no longer stretches when the window grows.
- Renamed the reset button to `Reset Stats`, moved it into the Alert Counts panel, and made stats/jitter toggle labels switch between ON and OFF.
- Widened the alert/stats panels to prevent clipped toggle text and reduced threshold breach marker sizes on the graphs.
- Added Live Jitter to the Ping Panel and rebuilt alert/history controls into consistent number-box plus slider rows with tooltips and synced values.
- Equalized alert toggle button widths and wrapped threshold/history sliders in a fixed-width `Alert Thresholds` panel.
- Tightened the `Alert Thresholds` panel width and allowed sliders to expand within their rows.
- Raised the minimum window width to prevent panel overlap at narrow sizes and initialized empty graph axes with readable ranges.
- Raised the minimum window height, gave the graph canvas a minimum height, and made the `Alert Thresholds` panel taller.
- Removed the top graph x-axis label and increased subplot spacing to prevent latency/jitter label overlap.
- Removed the remaining bottom `Ping #` graph label so the plots rely on tick numbers without a floating footer label.
- Framed the graph toolbar/canvas in a `Graphs` panel and split the Ping Panel into `Target` and `Live Status` sub-panels.
- Matched the Host input width to the Reverse DNS input width in the Target panel.
- Wrapped alert thresholds, alert counts, latency stats, jitter stats, and host info into a single `Monitoring` panel.
- Made Monitoring child panels expand to fill the wrapper and reduced vertical overhead so the graph area is not clipped.
- Added Default buttons for alert/history controls and increased graph figure bottom padding.
- Renamed graph titles to `Ping Latency over Time` and `Ping Jitter over Time`, and raised minimum window height to prevent the bottom graph from being clipped.
- Extended the `Alert Thresholds` frame to align with the lower summary panels and increased minimum graph height.
- Expanded the reset button, tightened Target button spacing, widened Target action buttons slightly, and made graph autoscaling/ticks more detailed.
- Capped graph history at 100 pings and made ping-count x-axis ticks predictable.
- Changed the graph x-axis to count every ping in increments of 1.
- Changed the default graph history length to 30 pings.
- Added rolling connection health guidance based on RTT, jitter, and packet loss.
- Moved connection health into the Ping Panel and lowered the DNS/traceroute side tools.
- Extended the Ping Panel across the window, matched Connection Health to Live Status width, and replaced threshold popups with an Alert Log.
- Replaced the embedded Alert Log with an Alerts button that opens a separate non-modal log window.
- Split connection health into RTT Health and Jitter Health beside the live readings, and made the alert log open as a top-level window.
- Moved the Alert Log button into a framed box below Traceroute and sized it to about half the side-panel width.
- Improved Ping Panel spacing, pushed Session to the right edge, and clarified Traceroute with a target label and single hop numbering.
- Added speed test support as a tracked roadmap idea.
- Changed alert logging to record each new threshold crossing instead of only the first alert per session.
- Changed the Alert Log to record every breached ping sample while an alert toggle is enabled.
- Added a Speed Test button and separate Speed Test window backed by optional Ookla Speedtest CLI JSON output.
- Documented the expected bundled Speedtest CLI path and initial PC packaging approach.
- Restyled the Speed Test window with a status banner and grouped result sections.
- Fixed Speed Test window initial sizing so result fields open fully expanded.
- Widened the main app window, widened DNS/traceroute side tools, and moved the Speed Test button into the top Ping Panel.
- Aligned the right-side DNS, Traceroute, and Alert Log frames to a shared wider width.
