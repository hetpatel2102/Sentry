# Sentry — Windows Security Suite


**Author:** Het Patel | [github.com/hetpatel2102](https://github.com/hetpatel2102)

---

Just want to run it? Download the executable and go:

1. Download `Sentry.exe` directly from the repo
2. Right-click `Sentry.exe` → **Run as Administrator**
3. That's it — no Python, no pip, no setup

> **Note:** Windows Defender or antivirus may show a warning on first run since this is an unsigned executable. Click **More info → Run anyway** to proceed. This is normal for self-built `.exe` files.

---

## Run from Source — Python Required

If you prefer to run the source code directly:

**Requirements**
- Windows 10 / 11
- Python 3.10+
- Run as **Administrator** for full results

**Install dependencies**

```bash
pip install rich psutil pywin32
```

**Run**

```bash
# Right-click PowerShell → Run as Administrator
python Sentry_1.0.0.py
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

A full Windows security audit across 7 areas. Each check is scored and risk-rated.

| Module | What It Does | Why It Matters |
|---|---|---|
| Network Connections | All active TCP connections, flags suspicious ports | Catch malware phoning home |
| Open Ports | Scans common ports on localhost | Find open doors hackers can walk through |
| Event Logs | Failed logons (4625), lockouts (4740), audit changes (4719) | Detect brute-force and insider threats |
| Startup Programs | Registry Run keys (HKCU + HKLM) | Catch malware set to auto-start |
| Password Policy | Length, age, lockout threshold, history | Enforce strong password standards |
| Firewall Rules | All 3 Windows firewall profiles + inbound rule count | Ensure the perimeter is up |
| Patch Status | Installed hotfixes via PowerShell Get-HotFix | Unpatched systems are easy targets |

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

### Report Output

Saves to: `sentry_system_audit_YYYYMMDD_HHMMSS.txt`

---

## Tool 2 — process_Scan

A threat hunting tool that detects hidden, fileless, injected, unsigned, and suspicious processes — with an interactive kill manager after every scan.

| Module | What It Looks For | MITRE ATT&CK |
|---|---|---|
| Hidden / Suspended | Processes invisible to Task Manager | T1564 — Hide Artifacts |
| Fileless | Processes with no binary on disk | T1055.001 — Process Injection |
| Process Injection | Suspicious parent→child combos, DLLs from temp paths | T1055 — Process Injection |
| Unsigned Executables | No valid Authenticode signature | T1553.002 — Subvert Trust Controls |
| Suspicious Paths | Processes running from Temp, Downloads, Recycle Bin | T1036 — Masquerading |

### Smart Whitelisting

Common Windows processes that are legitimately suspended or have no disk binary are automatically flagged LOW — not false positives:

`backgroundTaskHost.exe`, `RuntimeBroker.exe`, `ShellExperienceHost.exe`, `LockApp.exe`, `MemCompression`, `Registry`, `RtkUWP.exe`, `AdobeNotificationClient.exe`

### Threat Score

| Score | Grade | Meaning |
|---|---|---|
| 80–100 | A | System looks clean |
| 65–79  | B | A few things to investigate |
| 50–64  | C | Notable threats — review findings |
| < 50   | F | Active threats likely — act now |

Each HIGH finding deducts 12 points. Each MEDIUM deducts 4.

### Interactive Process Manager

After every scan, Sentry stays open and lets you act on findings directly from the terminal:

| Command | Action |
|---|---|
| `#` | Kill process by number — shows full detail first |
| `a` | Kill ALL flagged processes — requires `YES` confirmation |
| `r` | Rescan — refresh which PIDs are still alive |
| `q` | Quit and print full session action log |
| `!h` | *(Admin only)* Kill ALL HIGH risk processes instantly |

In **admin mode**, single kills require typing `KILL` instead of `y` to prevent accidents.

### Report Output

Saves to: `sentry_process_scan_YYYYMMDD_HHMMSS.txt`

---

## Tool 3 — Both (Full Sweep)

Runs system_Audit and process_Scan together as one co-dependent session.

- One combined progress bar across all 13 checks
- Phase 1 results printed, then Phase 2 results
- One combined security score with breakdown by tool
- One unified report file
- One process manager at the end for any threats found

### Report Output

Saves to: `sentry_fullsweep_YYYYMMDD_HHMMSS.txt`

---

## Risk Level Reference

| Level | Color | Meaning |
|---|---|---|
| HIGH | Red | Immediate attention required |
| MEDIUM | Yellow | Should be investigated |
| LOW | Dark green | Normal / expected behavior |
| INFO | Blue | Informational only |

---

## Files in This Repo

| File | Description |
|---|---|
| `Sentry.exe` | Standalone executable — just download and run |
| `Sentry_1.0.0.py` | Full source code |
| `README.md` | This file |

---

## Background

Built to demonstrate real-world Windows security skills — network defense, identity and access management, firewall configuration, patch compliance, and live threat hunting — all mapped to NIST SP 800-53 and MITRE ATT&CK.

Relevant experience: IAM automation at Wells Fargo (Azure AD, NIST AC-2/AC-5/AC-6), network security at Allot Technologies (FortiGate NGFW), and a NIST SP 800-53 compliant access review automation tool at Mobile Heartbeat.

---

*Sentry v1.0.0 — github.com/hetpatel2102*
