# Changelog

All notable changes to Sentry are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

## [1.2.0] - 2026-07-05

### Added
- **Advanced Hardening stage** added to `system_Audit`, covering four new areas:
  - **Microsoft Defender / AV health** — real-time protection, signature age, tamper protection.
  - **Configuration hardening** — SMBv1, Remote Desktop (RDP) + Network Level Authentication,
    UAC (EnableLUA), automatic logon, Remote Registry service, and BitLocker on the OS drive.
  - **Network share audit** — flags non-default SMB shares, and shares exposed to `Everyone`.
  - **Installed-software inventory** — enumerates installed programs and flags known
    end-of-life / high-risk software (Flash, old Java, WinRAR < 6.23, QuickTime, remote-access tools).
- **Expanded system profile** in the System Information header — now a full asset
  fingerprint: FQDN, OS edition/feature-version/build, install date, last boot & uptime,
  manufacturer/model, serial number, BIOS version, CPU model with core/thread count, RAM,
  per-drive capacity/usage, primary IPv4 + MAC, and Secure Boot / TPM status. Shown both
  on screen and in every report header.
- **Self-exclusion** in `process_Scan`: the hunters now skip Sentry's own process, so the
  standalone `Sentry.exe` is never flagged as unsigned / DLL-injected / suspicious-path
  (a false positive caused by PyInstaller's one-file bootloader loading DLLs from `%TEMP%`).
- Software inventory now points the user to where Windows lists installed apps
  (Settings > Apps > Installed apps, or `appwiz.cpl` / `ms-settings:appsfeatures`).
- **Graphical (GUI) front-end** (`Sentry_GUI.py` / `Sentry-GUI.exe`) — a windowed
  Tkinter app that drives the same engine: buttons for System Audit / Process Scan /
  Full Sweep, a live security-score header, sortable result tables (colour-coded by
  severity), a System Information panel, a click-to-kill process manager
  (Kill Selected / Kill All HIGH / Rescan), one-click report export, and a
  "Run as Admin" relaunch. The terminal version remains fully supported.
- Child processes now launch with `CREATE_NO_WINDOW`, so the GUI never flashes
  console windows while running its PowerShell/CLI probes.
- Rebuilt standalone `Sentry.exe` (console) and `Sentry-GUI.exe` (windowed) for this release.

### Changed
- `system_Audit` and the combined full sweep now run the Advanced Hardening stage; the
  security score, on-screen tables, and TXT report all include the new findings.
- Output is forced to UTF-8 so the banner and tables render correctly even when the
  output is redirected to a file or run in a legacy code-page console.
- Version bumped to `v1.2.0` across the banner and report footers.

### Notes
- New checks degrade gracefully without Administrator rights (e.g. BitLocker/Defender status
  may be limited); run elevated for full coverage.

## [1.0.0] - 2026-05-25

### Added
- Initial release.
- **system_Audit** — 7 modules (network connections, open ports, event logs, startup programs,
  password policy, firewall, patch status), scored A–F, mapped to NIST SP 800-53.
- **process_Scan** — 5 threat hunts (hidden/suspended, fileless, injection, unsigned,
  suspicious paths), mapped to MITRE ATT&CK, with an interactive kill manager.
- **Full sweep** — combined audit + hunt with one score and one report.
- Timestamped TXT reports and a standalone `Sentry.exe` build.
