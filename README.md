# 🛡️ Sentry — Windows Security Suite

A Windows security auditor: a scored **system audit** (mapped to NIST SP 800-53) and a
live **process threat hunt** (mapped to MITRE ATT&CK), available as both a terminal tool
and a graphical desktop app.

**Author:** Het Patel · [github.com/hetpatel2102](https://github.com/hetpatel2102)

---

## 📦 Versions

| Version | Date | Highlights | Source | Download |
|---|---|---|---|---|
| **v1.2.0** | 2026-07 | Graphical app, Advanced Hardening (Defender / config / shares / software), full system profile | [`/v1.2.0`](./v1.2.0) | [Releases ⬇](../../releases/tag/v1.2.0) |
| v1.0.0 | 2026-05 | Initial release: system audit + process hunt + interactive kill manager | [`/v1.0.0`](./v1.0.0) | [Releases ⬇](../../releases/tag/v1.0.0) |

Full history in [CHANGELOG.md](./CHANGELOG.md).

---

## ▶️ How to run

**Easiest — download the app (no Python needed):**
1. Open [Releases](../../releases) and download the `.exe` for your version.
   - `Sentry-GUI.exe` — graphical window app (v1.2.0)
   - `Sentry.exe` — terminal version
2. Right-click → **Run as Administrator** (needed for full results).

> ⚠️ The executables are unsigned, so Windows SmartScreen may warn on first run —
> click **More info → Run anyway**. This is normal for self-built `.exe` files.

**From source:**
```bash
cd v1.2.0
pip install -r requirements.txt      # rich, psutil, pywin32
python Sentry_GUI.py                  # graphical version
python Sentry.py                      # terminal version
```

---

## 🧪 What it checks

- **System audit** — network connections, open ports, event logs, startup items,
  password policy, firewall, patch status, and **Advanced Hardening** (Defender health,
  SMBv1 / RDP / UAC / BitLocker, network shares, installed-software inventory).
- **Process hunt** — hidden/suspended, fileless, injected, unsigned, and
  suspicious-path processes, with an interactive kill manager.
- Scored **A–F**, with severity-ranked findings and timestamped text reports.

---

## ⚖️ License

[MIT](./LICENSE) — © 2026 hetpatel2102. Provided as-is for auditing systems you own
or are authorized to assess.
