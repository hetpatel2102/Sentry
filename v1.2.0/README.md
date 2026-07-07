# Sentry — Windows Security Suite

**Version:** 1.2.0  |  **Author:** Het Patel | [github.com/hetpatel2102](https://github.com/hetpatel2102)

A terminal-based Windows security suite: a scored **system audit** (NIST SP 800-53) and a
live **process threat hunt** (MITRE ATT&CK) with an interactive kill manager — in one tool.

> See [`CHANGELOG.md`](CHANGELOG.md) for what's new. **1.2.0** adds an *Advanced Hardening*
> stage: Microsoft Defender health, configuration hardening, network-share, and installed-software checks.

---

## Quick start — run the executable

Two ready-to-run builds are provided (no Python, no pip, no setup):

| Executable | Interface |
|---|---|
| **`Sentry-GUI.exe`** | Graphical app — buttons, tables, click-to-kill process manager (opens in its own window) |
| **`Sentry.exe`** | Classic terminal / console interface |

1. Grab the executable you want from the [Releases](https://github.com/hetpatel2102/Sentry/releases) page (or the repo).
2. Right-click it → **Run as Administrator** (for full results — Defender, BitLocker, TPM, process-kill).
3. That's it.

### Graphical version (`Sentry-GUI.exe`)

A windowed Tkinter app over the same engine:
- Sidebar buttons: **System Audit**, **Process Scan**, **Full Sweep**
- Live **security-score** header and a full **System Information** panel
- **Security Findings** table, colour-coded by severity (HIGH / MEDIUM / LOW / INFO)
- **Processes** tab with a click-to-kill manager (*Kill Selected*, *Kill All HIGH*, *Rescan*)
- **Save Report** to a timestamped `.txt`, and a **Run as Admin** relaunch button

> **Note:** Windows Defender may warn on first run since this is an unsigned executable.
> Click **More info → Run anyway**. This is normal for self-built `.exe` files.

## Run from source

**Requirements**
- Windows 10 / 11
- Python 3.10+
- Run as **Administrator** for full results

```bash
pip install -r requirements.txt      # rich, psutil, pywin32
python Sentry.py                      # terminal version  (Run PowerShell as Administrator)
python Sentry_GUI.py                  # graphical version  (Tkinter — ships with Python)
```

---

## Menu

```
[ 1 ]   system_Audit    full system security audit
[ 2 ]   process_Scan    hunt for malicious processes
[ 3 ]   both            full sweep — one score, one report
[ q ]   Quit            exit Sentry
```

---

## Tool 1 — system_Audit

A full Windows security audit. Each check is scored and risk-rated.

| Module | What It Does | Why It Matters |
|---|---|---|
| Network Connections | All active TCP connections, flags suspicious ports | Catch malware phoning home |
| Open Ports | Scans common ports on localhost | Find open doors an attacker can walk through |
| Event Logs | Failed logons (4625), lockouts (4740), audit changes (4719) | Detect brute-force and insider threats |
| Startup Programs | Registry Run keys (HKCU + HKLM) | Catch malware set to auto-start |
| Password Policy | Length, age, lockout threshold, history | Enforce strong password standards |
| Firewall Rules | All 3 Windows firewall profiles + inbound rule count | Ensure the perimeter is up |
| Patch Status | Installed hotfixes via `Get-HotFix` | Unpatched systems are easy targets |
| **Advanced Hardening** *(new in 1.2.0)* | **Defender health, config hardening, shares, software inventory** | **Close common misconfigurations & entry points** |

### Advanced Hardening (new in 1.2.0)

| Area | Checks |
|---|---|
| **Microsoft Defender** | Real-time protection, signature age, tamper protection |
| **Configuration** | SMBv1, RDP + Network Level Authentication, UAC (EnableLUA), automatic logon, Remote Registry, BitLocker (OS drive) |
| **Network Shares** | Non-default SMB shares; flags shares exposed to `Everyone` |
| **Installed Software** | Inventory + heuristic flags for end-of-life / high-risk apps (Flash, old Java, WinRAR < 6.23, QuickTime, remote-access tools) |

### Security Score

| Score | Grade | Meaning |
|---|---|---|
| 80–100 | A | Solid security posture |
| 65–79  | B | A few things to tighten |
| 50–64  | C | Notable gaps — address soon |
| < 50   | F | High risk — act immediately |

Each HIGH finding deducts 15 points. Each MEDIUM deducts 5.

### NIST SP 800-53 Alignment

| Module | Control |
|---|---|
| Startup / Event Logs | AC-2 — Account Management |
| Password Policy | IA-5 — Authenticator Management |
| Firewall | SC-7 — Boundary Protection |
| Patch Status | SI-2 — Flaw Remediation |
| Event Logs | AU-2 — Audit Events |
| Defender health *(1.2.0)* | SI-3 — Malicious Code Protection |
| Config hardening *(1.2.0)* | CM-6 / CM-7 — Configuration Settings / Least Functionality |
| BitLocker *(1.2.0)* | SC-28 — Protection of Information at Rest |
| Network shares *(1.2.0)* | AC-3 / AC-6 — Access Enforcement / Least Privilege |
| Software inventory *(1.2.0)* | CM-8 — System Component Inventory |

### Report Output

Saves to: `sentry_system_audit_YYYYMMDD_HHMMSS.txt`

---

## Tool 2 — process_Scan

A threat-hunting tool that detects hidden, fileless, injected, unsigned, and suspicious
processes — with an interactive kill manager after every scan.

| Module | What It Looks For | MITRE ATT&CK |
|---|---|---|
| Hidden / Suspended | Processes invisible to Task Manager | T1564 — Hide Artifacts |
| Fileless | Processes with no binary on disk | T1055.001 — Process Injection |
| Process Injection | Suspicious parent→child combos, DLLs from temp paths | T1055 — Process Injection |
| Unsigned Executables | No valid Authenticode signature | T1553.002 — Subvert Trust Controls |
| Suspicious Paths | Processes running from Temp, Downloads, Recycle Bin | T1036 — Masquerading |

### Interactive Process Manager

| Command | Action |
|---|---|
| `#` | Kill process by number — shows full detail first |
| `a` | Kill ALL flagged processes — requires `YES` confirmation |
| `r` | Rescan — refresh which PIDs are still alive |
| `q` | Quit and print full session action log |
| `!h` | *(Admin only)* Kill ALL HIGH risk processes instantly |

### Report Output

Saves to: `sentry_process_scan_YYYYMMDD_HHMMSS.txt`

---

## Tool 3 — Both (Full Sweep)

Runs system_Audit and process_Scan together as one co-dependent session: one combined
progress bar, one combined security score, one unified report, and one process manager
at the end.

Saves to: `sentry_fullsweep_YYYYMMDD_HHMMSS.txt`

---

## Risk Level Reference

| Level | Meaning |
|---|---|
| HIGH | Immediate attention required |
| MEDIUM | Should be investigated |
| LOW | Normal / expected behavior |
| INFO | Informational only |

---

## Files in This Repo

| File | Description |
|---|---|
| `Sentry.py` | Scan engine + terminal interface (single file) |
| `Sentry_GUI.py` | Graphical (Tkinter) front-end over the engine |
| `requirements.txt` | Python dependencies (`rich`, `psutil`, `pywin32`; Tkinter ships with Python) |
| `CHANGELOG.md` | Version history |
| `Sentry.exe` | Standalone console executable (PyInstaller) |
| `Sentry-GUI.exe` | Standalone graphical executable (PyInstaller) |
| `README.md` | This file |

---

## Background

Built to demonstrate real-world Windows security skills — network defense, identity and
access management, firewall configuration, patch compliance, configuration hardening, and
live threat hunting — mapped to NIST SP 800-53 and MITRE ATT&CK.

---

*Sentry v1.2.0 — github.com/hetpatel2102*
