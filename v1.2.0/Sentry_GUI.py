"""
Sentry - Windows Security Suite (Graphical front-end)
A windowed GUI over the Sentry scan engine (Sentry.py). Runs the same
system_Audit, process_Scan and Advanced Hardening checks, but presents them
as buttons + sortable tables instead of a terminal menu.

Author: Het Patel | github.com/hetpatel2102
"""

import os
import sys
import ctypes
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# Make the scan engine importable whether run from source or frozen.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import Sentry as core   # reuses every wa_*/ph_* data function

APP_TITLE = "Sentry - Windows Security Suite  v1.2.0 by Het Patel"

# --- palette -----------------------------------------------------------------
BG      = "#1b1b1d"
PANEL   = "#242426"
CARD    = "#2b2b2e"
FG      = "#e6e6e6"
MUTED   = "#9a9a9a"
ACCENT  = "#c0392b"      # Sentry red
ACCENT2 = "#8a5a2b"      # amber/brown

SEV_COLOR = {"HIGH": "#ff5555", "MEDIUM": "#f1c40f", "LOW": "#3ddc84", "INFO": "#4aa3df"}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Re-launch the app elevated (UAC prompt), then close this instance."""
    try:
        if getattr(sys, "frozen", False):
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "", None, 1)
        else:
            script = os.path.abspath(__file__)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
        sys.exit(0)
    except Exception as exc:
        messagebox.showerror("Sentry", f"Could not elevate: {exc}")


def normalize_audit(findings: dict):
    """Flatten the system-audit findings into (severity, category, item, detail)."""
    rows = []
    for f in findings.get("network", []):
        rows.append((f.get("level", "INFO"), "Network",
                     f"{f.get('remote_ip', '?')}:{f.get('remote_port', '')}",
                     f"{f.get('process', '?')} (PID {f.get('pid', '?')}), local :{f.get('local_port', '')}"))
    for f in findings.get("ports", []):
        rows.append((f.get("level", "INFO"), "Open Port", f"Port {f.get('port')}", f.get("service", "")))
    for f in findings.get("events", []):
        rows.append((f.get("level", "INFO"), "Event Log", f.get("event", ""), f.get("detail", "")))
    for f in findings.get("startup", []):
        detail = f"{f.get('hive', '')}  {f.get('path', '')}"
        if f.get("flag"):
            detail += f"  [{f['flag']}]"
        rows.append((f.get("level", "INFO"), "Startup", f.get("name", ""), detail))
    for f in findings.get("password", []):
        rows.append((f.get("level", "INFO"), "Password", f.get("check", ""),
                     f"{f.get('value', '')}  ({f.get('note', '')})"))
    for f in findings.get("firewall", []):
        rows.append((f.get("level", "INFO"), "Firewall", f.get("check", ""),
                     f"{f.get('state', '')}  ({f.get('note', '')})"))
    for f in findings.get("patches", []):
        if f.get("check") == "Recent Patches (last 5)":
            for u in (f.get("value") if isinstance(f.get("value"), list) else []):
                rows.append(("INFO", "Patch", f"KB {u.get('id', '')}", f"installed {u.get('date', '')}"))
            continue
        rows.append((f.get("level", "INFO"), "Patch", f.get("check", ""),
                     f"{f.get('value', '')}  ({f.get('note', '')})"))
    for f in findings.get("advanced", []):
        rows.append((f.get("level", "INFO"), f.get("category", "Advanced"), f.get("check", ""),
                     f"{f.get('value', '')}  ({f.get('note', '')})"))
    return rows


class SentryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1060x700")
        self.minsize(940, 620)
        self.configure(bg=BG)
        self._busy = False
        self._last_audit = None
        self._last_proc = None
        self._setup_style()
        self._build_header()
        self._build_body()
        self._set_status("Ready.  Choose a scan on the left.")

    # -- styling --------------------------------------------------------------
    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=CARD)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Head.TLabel", background=BG, foreground=FG, font=("Segoe UI Semibold", 15))
        style.configure("Score.TLabel", background=BG, foreground=FG, font=("Consolas", 16, "bold"))
        style.configure("Side.TButton", font=("Segoe UI", 10, "bold"), padding=(10, 10),
                        background=CARD, foreground=FG, borderwidth=0)
        style.map("Side.TButton", background=[("active", ACCENT2), ("disabled", "#333")])
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(10, 10),
                        background=ACCENT, foreground="white", borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#e04a38"), ("disabled", "#333")])
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=FG,
                        rowheight=24, font=("Consolas", 9), borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL, foreground=ACCENT2,
                        font=("Segoe UI Semibold", 9), borderwidth=0)
        style.map("Treeview", background=[("selected", "#3a3a3d")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                        padding=(14, 6), font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", FG)])
        style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL, borderwidth=0)

    # -- header ---------------------------------------------------------------
    def _build_header(self):
        head = ttk.Frame(self, style="TFrame")
        head.pack(fill="x", padx=16, pady=(12, 4))
        ttk.Label(head, text="\U0001F6E1  SENTRY", style="Head.TLabel").pack(side="left")
        ttk.Label(head, text="Windows Security Suite  v1.2.0 \u2014 Het Patel", style="Muted.TLabel").pack(side="left", padx=(10, 0), pady=(6, 0))

        badge = ttk.Frame(head, style="TFrame")
        badge.pack(side="right")
        admin = is_admin()
        who = os.environ.get("USERNAME", "user")
        host = os.environ.get("COMPUTERNAME", "host")
        ttk.Label(badge, text=f"{host}\\{who}", style="Muted.TLabel").pack(side="right", padx=(10, 0))
        tag = "ADMIN" if admin else "STANDARD USER"
        lbl = tk.Label(badge, text=tag, bg=("#2e7d32" if admin else "#7a5b00"),
                       fg="white", font=("Segoe UI", 8, "bold"), padx=8, pady=2)
        lbl.pack(side="right")
        if not admin:
            ttk.Button(badge, text="Run as Admin", style="Side.TButton",
                       command=relaunch_as_admin).pack(side="right", padx=(0, 10))

    # -- body -----------------------------------------------------------------
    def _build_body(self):
        body = ttk.Frame(self, style="TFrame")
        body.pack(fill="both", expand=True, padx=16, pady=8)

        # sidebar
        side = ttk.Frame(body, style="Panel.TFrame", width=190)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        self.btn_audit = ttk.Button(side, text="System Audit", style="Accent.TButton",
                                    command=self.run_audit)
        self.btn_proc = ttk.Button(side, text="Process Scan", style="Accent.TButton",
                                   command=self.run_proc)
        self.btn_sweep = ttk.Button(side, text="Full Sweep", style="Accent.TButton",
                                    command=self.run_sweep)
        for b in (self.btn_audit, self.btn_proc, self.btn_sweep):
            b.pack(fill="x", padx=12, pady=(12, 0))
        ttk.Separator(side).pack(fill="x", padx=12, pady=14)
        self.btn_save = ttk.Button(side, text="Save Report", style="Side.TButton",
                                   command=self.save_report)
        self.btn_clear = ttk.Button(side, text="Clear", style="Side.TButton", command=self.clear_all)
        self.btn_exit = ttk.Button(side, text="Exit", style="Side.TButton", command=self.destroy)
        for b in (self.btn_save, self.btn_clear, self.btn_exit):
            b.pack(fill="x", padx=12, pady=(0, 8))
        self._action_btns = [self.btn_audit, self.btn_proc, self.btn_sweep,
                             self.btn_save, self.btn_clear]

        # main
        main = ttk.Frame(body, style="TFrame")
        main.pack(side="left", fill="both", expand=True, padx=(12, 0))

        topbar = ttk.Frame(main, style="TFrame")
        topbar.pack(fill="x")
        self.score_lbl = ttk.Label(topbar, text="Score: --", style="Score.TLabel")
        self.score_lbl.pack(side="left")
        self.progress = ttk.Progressbar(topbar, mode="indeterminate", length=180)
        self.progress.pack(side="right", pady=6)
        self.status_lbl = ttk.Label(main, text="", style="Muted.TLabel")
        self.status_lbl.pack(fill="x", pady=(2, 8))

        self.nb = ttk.Notebook(main)
        self.nb.pack(fill="both", expand=True)

        # System Information tab
        self.sys_tree = self._make_tree(self.nb, [("Field", 200), ("Value", 640)])
        self.nb.add(self.sys_tree.master, text="System Information")

        # Findings tab
        self.find_tree = self._make_tree(self.nb, [("Sev", 80), ("Category", 130),
                                                   ("Item", 260), ("Detail", 380)])
        for sev, col in SEV_COLOR.items():
            self.find_tree.tag_configure(sev, foreground=col)
        self.nb.add(self.find_tree.master, text="Security Findings")

        # Processes tab
        proc_frame = ttk.Frame(self.nb, style="TFrame")
        self.proc_tree = self._make_tree(proc_frame, [("Sev", 80), ("PID", 70),
                                                      ("Process", 200), ("Category", 150),
                                                      ("Finding", 360)], pack=False)
        for sev, col in SEV_COLOR.items():
            self.proc_tree.tag_configure(sev, foreground=col)
        self.proc_tree.pack(fill="both", expand=True, side="top")
        killbar = ttk.Frame(proc_frame, style="TFrame")
        killbar.pack(fill="x", pady=6)
        ttk.Button(killbar, text="Kill Selected", style="Side.TButton",
                   command=self.kill_selected).pack(side="left", padx=(0, 8))
        ttk.Button(killbar, text="Kill All HIGH", style="Accent.TButton",
                   command=self.kill_all_high).pack(side="left", padx=(0, 8))
        ttk.Button(killbar, text="Rescan", style="Side.TButton",
                   command=self.run_proc).pack(side="left")
        self.nb.add(proc_frame, text="Processes")

    def _make_tree(self, parent, columns, pack=True):
        wrap = ttk.Frame(parent, style="TFrame")
        cols = [c[0] for c in columns]
        tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
        for name, width in columns:
            tree.heading(name, text=name)
            tree.column(name, width=width, anchor="w", stretch=(name in ("Detail", "Value", "Finding")))
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        tree._wrap = wrap
        if pack:
            pass
        return tree

    # -- busy / status --------------------------------------------------------
    def _set_status(self, text):
        self.status_lbl.config(text=text)

    def _set_busy(self, busy, msg=""):
        self._busy = busy
        for b in self._action_btns:
            b.config(state="disabled" if busy else "normal")
        if busy:
            self.progress.start(12)
            self._set_status(msg or "Working...")
        else:
            self.progress.stop()

    def _run_async(self, worker, on_done, msg):
        if self._busy:
            return
        self._set_busy(True, msg)

        def task():
            try:
                result = worker()
            except Exception as exc:  # surface engine errors to the UI
                result = {"error": f"{type(exc).__name__}: {exc}"}
            self.after(0, lambda: self._done(result, on_done))
        threading.Thread(target=task, daemon=True).start()

    def _done(self, result, on_done):
        self._set_busy(False)
        if isinstance(result, dict) and result.get("error"):
            self._set_status("Scan failed.")
            messagebox.showerror("Sentry", result["error"])
            return
        on_done(result)

    # -- score ----------------------------------------------------------------
    def _show_score(self, score, grade, high, medium, label="Security"):
        color = "#3ddc84" if score >= 80 else "#f1c40f" if score >= 50 else "#ff5555"
        self.score_lbl.config(text=f"{label} Score: {score}/100  [{grade}]   "
                                   f"HIGH {high}  MEDIUM {medium}", foreground=color)

    # -- workers --------------------------------------------------------------
    def run_audit(self):
        self._run_async(self._audit_worker, self._render_audit, "Running system audit...")

    def _audit_worker(self):
        sysinfo = core.wa_get_system_info()
        findings = {
            "network":  core.wa_scan_network_connections(),
            "ports":    core.wa_scan_open_ports(),
            "events":   core.wa_check_event_logs(),
            "startup":  core.wa_check_startup_programs(),
            "password": core.wa_check_password_policy(),
            "firewall": core.wa_check_firewall(),
            "patches":  core.wa_check_patch_status(),
            "advanced": core.wa_check_advanced(),
        }
        score, grade, high, medium = core.wa_compute_score(findings)
        return {"sysinfo": sysinfo, "findings": findings,
                "score": score, "grade": grade, "high": high, "medium": medium}

    def _render_audit(self, data):
        self._last_audit = data
        self._fill_sysinfo(data["sysinfo"])
        self._fill_findings(normalize_audit(data["findings"]))
        self._show_score(data["score"], data["grade"], data["high"], data["medium"])
        self.nb.select(1)
        self._set_status(f"System audit complete - {len(self.find_tree.get_children())} findings. "
                         f"Report ready to save.")

    def run_proc(self):
        if not core.HAS_PSUTIL:
            messagebox.showerror("Sentry", "psutil is required for the process scan.")
            return
        self._run_async(self._proc_worker, self._render_proc, "Hunting processes...")

    def _proc_worker(self):
        core._refresh_self_pids()
        total = len(core.psutil.pids())
        all_f = []
        for fn in (core.ph_hunt_hidden_suspended, core.ph_hunt_fileless,
                   core.ph_hunt_injection, core.ph_hunt_unsigned, core.ph_hunt_suspicious_paths):
            try:
                all_f.extend(fn())
            except Exception:
                continue
        score, grade, high, medium = core.ph_compute_score(all_f)
        return {"findings": all_f, "score": score, "grade": grade,
                "high": high, "medium": medium, "total": total}

    def _render_proc(self, data):
        self._last_proc = data
        self.proc_tree.delete(*self.proc_tree.get_children())
        for f in data["findings"]:
            sev = f.get("level", "INFO")
            self.proc_tree.insert("", "end",
                                  values=(sev, f.get("pid", ""), f.get("name", ""),
                                          f.get("category", ""), f.get("finding", "")),
                                  tags=(sev,))
        self._show_score(data["score"], data["grade"], data["high"], data["medium"], label="Threat")
        self.nb.select(2)
        self._set_status(f"Process scan complete - {data['total']} processes scanned, "
                         f"{len(data['findings'])} flagged.")

    def run_sweep(self):
        self._run_async(self._sweep_worker, self._render_sweep, "Running full sweep...")

    def _sweep_worker(self):
        audit = self._audit_worker()
        proc = self._proc_worker() if core.HAS_PSUTIL else {"findings": [], "score": 100,
                                                            "grade": "A", "high": 0, "medium": 0, "total": 0}
        return {"audit": audit, "proc": proc}

    def _render_sweep(self, data):
        self._render_audit(data["audit"])
        self._render_proc(data["proc"])
        a, p = data["audit"], data["proc"]
        th = a["high"] + p["high"]
        tm = a["medium"] + p["medium"]
        combined = max(0, 100 - th * 12 - tm * 4)
        grade = "A" if combined >= 80 else "B" if combined >= 65 else "C" if combined >= 50 else "F"
        self._show_score(combined, grade, th, tm, label="Combined")
        self.nb.select(1)
        self._set_status("Full sweep complete.  Review Security Findings and Processes tabs.")

    # -- fillers --------------------------------------------------------------
    def _fill_sysinfo(self, info):
        self.sys_tree.delete(*self.sys_tree.get_children())
        rows = [
            ("Hostname", info.get("hostname")),
            ("FQDN", info.get("fqdn")),
            ("Logged-on User", info.get("logged_on")),
            ("Domain / Workgroup", f"{info.get('domain','')}  "
             f"({'Domain-joined' if info.get('domain_joined') else 'Workgroup'})"),
            ("OS Edition", info.get("edition")),
            ("OS Version / Build", f"{info.get('os_version','')}  (build {info.get('build','')})"
             + (f"  {info.get('display_version')}" if info.get('display_version') else "")),
            ("Architecture", info.get("architecture")),
            ("Install Date", info.get("install_date")),
            ("Last Boot / Uptime", f"{info.get('last_boot','')}  (up {info.get('uptime','')})"),
            ("Manufacturer", info.get("manufacturer")),
            ("Model", info.get("model")),
            ("Serial Number", info.get("serial")),
            ("BIOS Version", info.get("bios")),
            ("Processor", f"{info.get('cpu', info.get('processor',''))}"
             + (f"  ({info.get('cores')}C / {info.get('threads')}T)" if info.get("cores") else "")),
            ("RAM", f"{info.get('ram_total_gb','?')} GB"
             + (f"  ({info.get('ram_used_pct')}% used)" if info.get('ram_used_pct') is not None else "")),
            ("Primary IPv4", info.get("ip")),
            ("MAC Address", info.get("mac")),
            ("Secure Boot", info.get("secure_boot")),
            ("TPM", info.get("tpm")),
            ("Admin Rights", "YES" if info.get("admin") else "NO"),
            ("Scan Time", info.get("scan_time")),
        ]
        for k, v in rows:
            if v not in (None, "", "Unknown"):
                self.sys_tree.insert("", "end", values=(k, v))
        for i, d in enumerate(info.get("drives") or []):
            self.sys_tree.insert("", "end", values=("Storage" if i == 0 else "", d))

    def _fill_findings(self, rows):
        self.find_tree.delete(*self.find_tree.get_children())
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "PASS": 4}
        for sev, cat, item, detail in sorted(rows, key=lambda r: order.get(r[0], 5)):
            self.find_tree.insert("", "end", values=(sev, cat, item, detail), tags=(sev,))

    # -- process actions ------------------------------------------------------
    def _kill_rows(self, items):
        killed = 0
        for iid in items:
            vals = self.proc_tree.item(iid, "values")
            if len(vals) < 3:
                continue
            try:
                pid = int(vals[1])
            except (ValueError, TypeError):
                continue
            ok, msg = core.ph_kill_process(pid, vals[2])
            if ok:
                self.proc_tree.delete(iid)
                killed += 1
            else:
                messagebox.showwarning("Sentry", msg)
        if killed:
            self._set_status(f"Terminated {killed} process(es).")

    def kill_selected(self):
        sel = self.proc_tree.selection()
        if not sel:
            messagebox.showinfo("Sentry", "Select one or more processes first.")
            return
        names = ", ".join(self.proc_tree.item(i, "values")[2] for i in sel)
        if messagebox.askyesno("Confirm", f"Terminate {len(sel)} process(es)?\n\n{names}"):
            self._kill_rows(sel)

    def kill_all_high(self):
        high = [i for i in self.proc_tree.get_children()
                if self.proc_tree.item(i, "values")[0] == "HIGH"]
        if not high:
            messagebox.showinfo("Sentry", "No HIGH-risk processes listed.")
            return
        if messagebox.askyesno("Confirm", f"Terminate ALL {len(high)} HIGH-risk process(es)? "
                                          "This cannot be undone."):
            self._kill_rows(high)

    # -- report / misc --------------------------------------------------------
    def save_report(self):
        saved = []
        try:
            if self._last_audit:
                a = self._last_audit
                saved.append(core.wa_write_report(a["sysinfo"], a["findings"], a["score"],
                                                  a["grade"], a["high"], a["medium"]))
            if self._last_proc:
                p = self._last_proc
                saved.append(core.ph_write_report(p["findings"], p["score"], p["grade"],
                                                  p["high"], p["medium"], p["total"]))
        except Exception as exc:
            messagebox.showerror("Sentry", f"Could not write report: {exc}")
            return
        if not saved:
            messagebox.showinfo("Sentry", "Run a scan first, then save.")
            return
        paths = "\n".join(os.path.abspath(s) for s in saved)
        self._set_status("Report saved.")
        messagebox.showinfo("Sentry", f"Report(s) saved:\n\n{paths}")

    def clear_all(self):
        for t in (self.sys_tree, self.find_tree, self.proc_tree):
            t.delete(*t.get_children())
        self._last_audit = self._last_proc = None
        self.score_lbl.config(text="Score: --", foreground=FG)
        self._set_status("Cleared.")


def main():
    app = SentryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
