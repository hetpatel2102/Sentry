"""
Sentry - Windows Security Suite
Combined System_Audit + Process_Scan in one tool.
Author: Het Patel | github.com/hetpatel2102
"""

import os
import sys
import socket
import subprocess
import datetime
import platform
import winreg
import ctypes
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.rule import Rule
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.layout import Layout
    from rich.live import Live
    from rich.padding import Padding
except ImportError:
    print("[ERROR] Missing dependency: run   pip install rich   then retry.")
    sys.exit(1)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import win32api, win32con, win32security, win32process, pywintypes
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


# PIDs belonging to Sentry itself. Populated at scan time so the process
# hunters never flag the tool (important when running as the PyInstaller-built
# Sentry.exe, which is unsigned and loads its bundled DLLs from a temp folder).
SELF_PIDS = set()


def _refresh_self_pids():
    pids = {os.getpid()}
    if HAS_PSUTIL:
        try:
            me = psutil.Process(os.getpid())
            try:
                pids.add(me.ppid())
            except Exception:
                pass
            for child in me.children(recursive=True):
                pids.add(child.pid)
            # When frozen into Sentry.exe, exclude every process using our exe
            # (the one-file bootloader + the app both run as Sentry.exe).
            if getattr(sys, "frozen", False):
                exe = (sys.executable or "").lower()
                for p in psutil.process_iter(["pid", "exe"]):
                    try:
                        if (p.info.get("exe") or "").lower() == exe:
                            pids.add(p.info["pid"])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            pass
    SELF_PIDS.clear()
    SELF_PIDS.update(pids)
    return SELF_PIDS

class DimTimeElapsedColumn(TimeElapsedColumn):
    """TimeElapsedColumn rendered in dim white."""
    def render(self, task):
        elapsed = super().render(task)
        elapsed.stylize("dim white")
        return elapsed


console = Console()

BANNER = r"""
╔═══════════════════════════════════════════════════════════════════╗
║  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ║
║  ░                                                             ░  ║
║  ░    ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗     ░  ║
║  ░    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝     ░  ║
║  ░    ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝      ░  ║
║  ░    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝       ░  ║
║  ░    ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║        ░  ║
║  ░    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝        ░  ║
║  ░          W i n d o w s   S e c u r i t y   S u i t e        ░  ║
║  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ║
╚═══════════════════════════════════════════════════════════════════╝
"""

def print_banner():
    console.print()
    console.print(Text(BANNER, style="bold dark_red"))
    console.print(Text("  Windows Security Suite  v1.2.0  —  by Het Patel", style="dim white"))
    console.print(Text("  github.com/hetpatel2102\n", style="dim dark_red"))


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_cmd(cmd: str) -> str:
    try:
        # CREATE_NO_WINDOW stops child console windows from flashing when
        # Sentry runs as a windowed GUI app (harmless for the console build).
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.stdout.strip()
    except Exception:
        return ""


def severity_color(level: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dark_green", "INFO": "#1e90ff"}.get(level.upper(), "white")


def print_admin_notice():
    if not is_admin():
        console.print("[dim red]  TIP: Run as Administrator for full results.[/]")
        console.print("[dim red]  Some checks need elevated privileges.[/]\n")
    else:
        console.print("[bold red]  * Running as Administrator — all features unlocked.[/]\n")


def print_menu():
    console.print(Rule("[bold dark_green]  CHOOSE YOUR SCOUT", style="dim white"))
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 3))
    table.add_column("Option", style="bold #5a3a1a", width=6, header_style="bold #5a3a1a")
    table.add_column("Tool",   style="bold white", width=22, header_style="bold #5a3a1a")
    table.add_column("Description", style="dim white", width=48, header_style="bold #5a3a1a")

    table.add_row("[bold #5a3a1a][ 1 ][/]", "system_Audit", "full system security audit — network, ports, firewall, patches & more")
    table.add_row("[bold #5a3a1a][ 2 ][/]", "process_Scan", "hunt for hidden, fileless, injected & unsigned malicious processes")
    table.add_row("[bold #5a3a1a][ 3 ][/]", "both",         "unleash full functionality")
    table.add_row("[bold red][ q ][/]",  "Quit",         "Exit Sentry")

    console.print(table)
    console.print()


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
}
RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900}
SUSPICIOUS_KEYWORDS = ["temp", "appdata\\local\\temp", "tmp", "cmd.exe", "powershell", "wscript", "cscript", "mshta", "regsvr32", "rundll32"]


def _sysinfo_report_block(sysinfo):
    """Consistent multi-line system/asset profile for the report headers."""
    g = sysinfo.get
    dv = g("display_version", "")
    return [
        f"  Hostname     : {g('hostname', '?')}" + (f"   ({g('fqdn')})" if g('fqdn') else ""),
        f"  OS           : {g('edition', g('os', ''))}" + (f"  ({dv})" if dv else "") + f"  build {g('build', '')}",
        f"  Architecture : {g('architecture', '')}",
        f"  Manufacturer : {g('manufacturer', 'Unknown')}  {g('model', '')}",
        f"  Serial / BIOS: {g('serial', 'Unknown')}  /  {g('bios', 'Unknown')}",
        f"  Processor    : {g('cpu', g('processor', ''))}  ({g('cores', '?')}C / {g('threads', '?')}T)",
        f"  RAM          : {g('ram_total_gb', '?')} GB",
        f"  User         : {g('logged_on', g('username', ''))}",
        f"  Domain       : {g('domain', '')}  ({'Domain-joined' if g('domain_joined') else 'Workgroup'})",
        f"  Network      : {g('ip', 'Unknown')}   MAC {g('mac', 'Unknown')}",
        f"  Install Date : {g('install_date', 'Unknown')}",
        f"  Last Boot    : {g('last_boot', 'Unknown')}   (up {g('uptime', '?')})",
        f"  Secure Boot  : {g('secure_boot', 'Unknown')}   |   TPM: {g('tpm', 'Unknown')}",
        f"  Scan Time    : {g('scan_time', '')}",
        f"  Admin Run    : {'YES' if g('admin') else 'NO'}",
    ]


def _primary_ipv4():
    """Local IPv4 of the interface used for outbound traffic (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"


def _primary_mac(ip):
    if not HAS_PSUTIL or not ip or ip == "Unknown":
        return "Unknown"
    try:
        for _name, addrs in psutil.net_if_addrs().items():
            if any(a.family == socket.AF_INET and a.address == ip for a in addrs):
                for a in addrs:
                    if getattr(a, "family", None) == psutil.AF_LINK and a.address:
                        return a.address.upper()
    except Exception:
        pass
    return "Unknown"


def wa_get_system_info() -> dict:
    now = datetime.datetime.now()
    info = {
        "hostname": platform.node(), "os": platform.platform(),
        "architecture": platform.machine(), "processor": platform.processor() or "Unknown",
        "username": os.environ.get("USERNAME", "Unknown"),
        "domain": os.environ.get("USERDOMAIN", "Unknown"),
        "scan_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "admin": is_admin(),
    }
    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        info["fqdn"] = ""
    info["logged_on"] = run_cmd("whoami").strip() or f"{info['domain']}\\{info['username']}"

    # --- Rich hardware / OS profile via one CIM query (no admin required) ---
    cim = _ps_json("powershell -NoProfile -Command \""
                   "$os=Get-CimInstance Win32_OperatingSystem;"
                   "$cs=Get-CimInstance Win32_ComputerSystem;"
                   "$b=Get-CimInstance Win32_BIOS;"
                   "$c=Get-CimInstance Win32_Processor|Select-Object -First 1;"
                   "[pscustomobject]@{Edition=$os.Caption;Version=$os.Version;Build=$os.BuildNumber;"
                   "Mfr=$cs.Manufacturer;Model=$cs.Model;Joined=$cs.PartOfDomain;Dom=$cs.Domain;"
                   "Serial=$b.SerialNumber;Bios=$b.SMBIOSBIOSVersion;"
                   "CPU=$c.Name;Cores=$c.NumberOfCores;Threads=$c.NumberOfLogicalProcessors}"
                   "|ConvertTo-Json\"")
    c = cim[0] if cim else {}
    info["edition"]       = c.get("Edition") or info["os"]
    info["os_version"]    = c.get("Version") or platform.version()
    info["build"]         = str(c.get("Build") or "")
    info["manufacturer"]  = c.get("Mfr") or "Unknown"
    info["model"]         = c.get("Model") or "Unknown"
    info["serial"]        = c.get("Serial") or "Unknown"
    info["bios"]          = c.get("Bios") or "Unknown"
    info["cpu"]           = c.get("CPU") or info["processor"]
    info["cores"]         = c.get("Cores")
    info["threads"]       = c.get("Threads")
    info["domain_joined"] = bool(c.get("Joined"))
    if c.get("Dom"):
        info["domain"] = c.get("Dom")

    # Feature-update version (e.g. 23H2) + install date from the registry
    ver_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    info["display_version"] = _reg_get(winreg.HKEY_LOCAL_MACHINE, ver_key, "DisplayVersion") or ""
    inst = _reg_get(winreg.HKEY_LOCAL_MACHINE, ver_key, "InstallDate")
    try:
        info["install_date"] = datetime.datetime.fromtimestamp(int(inst)).strftime("%Y-%m-%d")
    except Exception:
        info["install_date"] = "Unknown"

    if HAS_PSUTIL:
        try:
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            secs = int((now - boot).total_seconds())
            d_, r_ = divmod(secs, 86400); h_, r_ = divmod(r_, 3600)
            info["last_boot"] = boot.strftime("%Y-%m-%d %H:%M")
            info["uptime"] = f"{d_}d {h_}h {r_ // 60}m"
        except Exception:
            pass
        try:
            mem = psutil.virtual_memory()
            info["ram_total_gb"] = round(mem.total / (1024 ** 3))
            info["ram_used_pct"] = mem.percent
        except Exception:
            pass
        drives = []
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    u = psutil.disk_usage(part.mountpoint)
                    drives.append(f"{part.device.rstrip(chr(92))} "
                                  f"{round(u.total / (1024 ** 3))} GB "
                                  f"({round(u.free / (1024 ** 3))} GB free, {u.percent}% used)")
                except Exception:
                    continue
        except Exception:
            pass
        info["drives"] = drives
        try:
            cu = psutil.disk_usage("C:\\")
            info["storage_total_gb"] = round(cu.total / (1024 ** 3))
            info["storage_free_gb"]  = round(cu.free / (1024 ** 3))
        except Exception:
            pass

    info["ip"] = _primary_ipv4()
    info["mac"] = _primary_mac(info["ip"])

    sb = run_cmd("powershell -NoProfile -Command \"try { Confirm-SecureBootUEFI } "
                 "catch { 'Unknown' }\"").strip().lower()
    info["secure_boot"] = {"true": "Enabled", "false": "Disabled"}.get(sb, "Unknown / legacy BIOS")
    tpm = run_cmd("powershell -NoProfile -Command \"(Get-CimInstance -Namespace "
                  "root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm "
                  "-ErrorAction SilentlyContinue).IsEnabled_InitialValue\"").strip().lower()
    info["tpm"] = "Present & enabled" if tpm == "true" else ("Present" if tpm == "false" else "Not detected / needs admin")

    return info


def wa_scan_network_connections() -> list:
    findings = []
    if HAS_PSUTIL:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.status == "ESTABLISHED":
                try:
                    remote_ip = c.raddr.ip if c.raddr else "N/A"
                    remote_port = c.raddr.port if c.raddr else 0
                    local_port = c.laddr.port if c.laddr else 0
                    pid = c.pid or 0
                    try:
                        proc_name = psutil.Process(pid).name() if pid else "Unknown"
                    except Exception:
                        proc_name = "Unknown"
                    suspicious_ports = {4444, 1337, 31337, 6666, 9999, 12345}
                    level = "HIGH" if remote_port in suspicious_ports else "INFO"
                    findings.append({"local_port": local_port, "remote_ip": remote_ip, "remote_port": remote_port, "process": proc_name, "pid": pid, "level": level})
                except Exception:
                    continue
    else:
        raw = run_cmd("netstat -ano")
        for line in raw.splitlines()[4:]:
            parts = line.split()
            if len(parts) >= 4 and "ESTABLISHED" in parts:
                findings.append({"local_port": parts[1], "remote_ip": parts[2], "remote_port": "", "process": "N/A (install psutil)", "pid": parts[-1], "level": "INFO"})
    return findings


def wa_scan_port(port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                level = "HIGH" if port in RISKY_PORTS else "MEDIUM" if port not in {80, 443} else "LOW"
                return {"port": port, "service": service, "level": level}
    except Exception:
        pass
    return None


def wa_scan_open_ports() -> list:
    open_ports = []
    ports_to_scan = list(COMMON_PORTS.keys()) + list(range(1024, 1100))
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(wa_scan_port, p): p for p in ports_to_scan}
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


def wa_check_event_logs() -> list:
    findings = []
    raw = run_cmd('wevtutil qe Security /q:"*[System[EventID=4625]]" /c:10 /rd:true /f:text')
    failed_count = raw.count("4625")
    if failed_count > 5:
        findings.append({"event": "Failed Logon Attempts", "detail": f"{failed_count} failed logon events (ID 4625) in recent logs", "level": "HIGH"})
    elif failed_count > 0:
        findings.append({"event": "Failed Logon Attempts", "detail": f"{failed_count} failed logon event(s) found", "level": "MEDIUM"})
    else:
        findings.append({"event": "Failed Logon Attempts", "detail": "No recent failed logon events — looks clean", "level": "LOW"})
    lockout_raw = run_cmd('wevtutil qe Security /q:"*[System[EventID=4740]]" /c:5 /rd:true /f:text')
    lockout_count = lockout_raw.count("4740")
    findings.append({"event": "Account Lockouts", "detail": f"{lockout_count} account lockout(s) detected (ID 4740)" if lockout_count > 0 else "No account lockouts detected", "level": "HIGH" if lockout_count > 0 else "LOW"})
    audit_raw = run_cmd('wevtutil qe Security /q:"*[System[EventID=4719]]" /c:5 /rd:true /f:text')
    audit_count = audit_raw.count("4719")
    findings.append({"event": "Audit Policy Changes", "detail": f"Audit policy was changed {audit_count} time(s) — review carefully" if audit_count > 0 else "No audit policy tampering detected", "level": "HIGH" if audit_count > 0 else "LOW"})
    return findings


def wa_check_startup_programs() -> list:
    findings = []
    reg_paths = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, path in reg_paths:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    suspicious = any(kw in value.lower() for kw in SUSPICIOUS_KEYWORDS)
                    findings.append({"name": name, "path": value[:80] + ("..." if len(value) > 80 else ""), "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM", "level": "HIGH" if suspicious else "INFO", "flag": "SUSPICIOUS PATH" if suspicious else ""})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            continue
    return findings


def wa_check_password_policy() -> list:
    findings = []
    raw = run_cmd("net accounts")
    def extract(label):
        for line in raw.splitlines():
            if label.lower() in line.lower():
                parts = line.split(":")
                return parts[-1].strip() if len(parts) > 1 else "Unknown"
        return "Unknown"
    min_len = extract("Minimum password length")
    max_age = extract("Maximum password age")
    lockout = extract("Lockout threshold")
    history = extract("Password history")
    try:
        ml = int(min_len)
        findings.append({"check": "Minimum Password Length", "value": str(ml), "level": "HIGH" if ml < 8 else "MEDIUM" if ml < 12 else "LOW", "note": "Should be ≥ 12" if ml < 12 else "Good"})
    except Exception:
        findings.append({"check": "Minimum Password Length", "value": min_len, "level": "INFO", "note": "Could not parse"})
    findings.append({"check": "Maximum Password Age (days)", "value": max_age, "level": "MEDIUM" if max_age in ("Never", "Unlimited") else "LOW", "note": "Passwords never expire!" if max_age in ("Never", "Unlimited") else "OK"})
    try:
        lt = int(lockout)
        findings.append({"check": "Lockout Threshold (attempts)", "value": str(lt), "level": "HIGH" if lt == 0 else "MEDIUM" if lt > 10 else "LOW", "note": "No lockout — brute force possible!" if lt == 0 else ("Too lenient" if lt > 10 else "Good")})
    except Exception:
        findings.append({"check": "Lockout Threshold", "value": lockout, "level": "INFO", "note": "Could not parse"})
    try:
        ph = int(history)
        findings.append({"check": "Password History (remember N)", "value": str(ph), "level": "MEDIUM" if ph < 5 else "LOW", "note": "Should remember ≥ 5 passwords" if ph < 5 else "Good"})
    except Exception:
        findings.append({"check": "Password History", "value": history, "level": "INFO", "note": "Could not parse"})
    return findings


def wa_check_firewall() -> list:
    findings = []
    for profile in ["Domain", "Private", "Public"]:
        raw = run_cmd(f'netsh advfirewall show {profile.lower()}profile state')
        state = "ON" if "ON" in raw.upper() else "OFF"
        findings.append({"check": f"Firewall — {profile} Profile", "state": state, "level": "HIGH" if state == "OFF" else "LOW", "note": f"{profile} firewall is {'ENABLED' if state == 'ON' else 'DISABLED — fix this!'}"})
    raw_rules = run_cmd('netsh advfirewall firewall show rule name=all dir=in action=allow')
    rule_count = raw_rules.count("Rule Name:")
    findings.append({"check": "Inbound Allow Rules (total)", "state": str(rule_count), "level": "MEDIUM" if rule_count > 50 else "LOW", "note": f"{rule_count} inbound allow rules{'— review for unnecessary rules' if rule_count > 50 else ''}"})
    return findings


def wa_check_patch_status() -> list:
    findings = []
    raw = run_cmd('powershell -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | Format-Table HotFixID, InstalledOn -AutoSize"')
    lines = [l for l in raw.splitlines() if l.strip() and "HotFixID" not in l and "---" not in l]
    recent_updates = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            recent_updates.append({"id": parts[0], "date": " ".join(parts[1:])})
    if recent_updates:
        latest_date_str = recent_updates[0].get("date", "")
        try:
            latest_date = datetime.datetime.strptime(latest_date_str.split()[0], "%m/%d/%Y")
            days_since = (datetime.datetime.now() - latest_date).days
            level = "HIGH" if days_since > 90 else "MEDIUM" if days_since > 30 else "LOW"
            findings.append({"check": "Last Windows Update", "value": latest_date_str, "days_since": days_since, "level": level, "note": f"{days_since} days ago — {'OUTDATED!' if days_since > 90 else 'Update soon' if days_since > 30 else 'Up to date'}"})
        except Exception:
            findings.append({"check": "Last Windows Update", "value": latest_date_str or "Unknown", "days_since": -1, "level": "INFO", "note": "Could not parse date"})
    else:
        findings.append({"check": "Last Windows Update", "value": "No data", "days_since": -1, "level": "HIGH", "note": "Could not retrieve update history — run as admin"})
    findings.append({"check": "Recent Patches (last 5)", "value": recent_updates, "level": "INFO", "note": ""})
    return findings


def wa_display_system_info(info):
    console.print(Rule("[bold #5a3a1a]  SYSTEM INFORMATION", style="#5a3a1a"))
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2), show_edge=False)
    table.add_column("Key",   style="dim #5a3a1a", width=22, no_wrap=True)
    table.add_column("Value", style="white",       width=72)

    def add(key, value):
        if value not in (None, "", "Unknown"):
            table.add_row(key, str(value))

    def section(label):
        table.add_row("", "")
        table.add_row(f"[bold #5a3a1a]{label}[/]", "")

    # --- Identity ---
    add("Hostname",        info.get("hostname"))
    add("FQDN",            info.get("fqdn"))
    add("Logged-on User",  info.get("logged_on"))
    add("Domain / Workgroup",
        f"{info.get('domain', '')}  ({'Domain-joined' if info.get('domain_joined') else 'Workgroup'})")

    # --- Operating System ---
    section("Operating System")
    dv = info.get("display_version")
    add("Edition", f"{info.get('edition', info.get('os'))}" + (f"  ({dv})" if dv else ""))
    add("Version / Build", f"{info.get('os_version', '')}  (build {info.get('build', '')})")
    add("Architecture",   info.get("architecture"))
    add("Install Date",   info.get("install_date"))
    if info.get("last_boot"):
        add("Last Boot / Uptime", f"{info.get('last_boot')}   (up {info.get('uptime', '?')})")

    # --- Hardware ---
    section("Hardware")
    add("Manufacturer",   info.get("manufacturer"))
    add("Model",          info.get("model"))
    add("Serial Number",  info.get("serial"))
    add("BIOS Version",   info.get("bios"))
    cores, threads = info.get("cores"), info.get("threads")
    ct = f"  ({cores}C / {threads}T)" if cores and threads else ""
    add("Processor", f"{info.get('cpu', info.get('processor'))}{ct}")
    if info.get("ram_total_gb"):
        rp = info.get("ram_used_pct")
        add("RAM", f"{info['ram_total_gb']} GB" + (f"  ({rp}% in use)" if rp is not None else ""))
    drives = info.get("drives") or []
    for i, dstr in enumerate(drives):
        add("Storage" if i == 0 else "", dstr)
    if not drives and info.get("storage_total_gb"):
        add("Storage", f"C: {info['storage_total_gb']} GB ({info.get('storage_free_gb', '?')} GB free)")

    # --- Network ---
    section("Network")
    add("Primary IPv4",   info.get("ip"))
    add("MAC Address",    info.get("mac"))

    # --- Security posture & session ---
    section("Security & Session")
    add("Secure Boot",    info.get("secure_boot"))
    add("TPM",            info.get("tpm"))
    table.add_row("Admin Rights",
                  "[bold dark_green]YES[/]" if info.get("admin") else "[bold red]NO — some checks may fail[/]")
    add("Scan Time",      info.get("scan_time"))

    console.print(table)
    console.print()


def wa_display_network_connections(conns):
    console.print(Rule("[bold #5a3a1a]  NETWORK CONNECTIONS", style="#5a3a1a"))
    if not conns:
        console.print("  [dark_green]No active connections found.[/]\n")
        return
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Local Port",  width=12, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Remote IP",   width=20, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Remote Port", width=13, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Process",     width=25, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("PID",         width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",        width=8, header_style="bold #5a3a1a", no_wrap=True)
    for c in conns[:20]:
        lvl = c["level"]
        table.add_row(str(c["local_port"]), str(c["remote_ip"]), str(c["remote_port"]), str(c["process"]), str(c["pid"]), f"[{severity_color(lvl)}]{lvl}[/]")
    console.print(table)
    if len(conns) > 20:
        console.print(f"  [dim]...and {len(conns)-20} more connections (see report)[/]")
    console.print()


def wa_display_open_ports(ports):
    console.print(Rule("[bold #5a3a1a]  OPEN PORTS", style="#5a3a1a"))
    if not ports:
        console.print("  [dark_green]No open ports detected on common port list.[/]\n")
        return
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Port",       width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Service",    width=18, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk Level", width=12, header_style="bold #5a3a1a", no_wrap=True)
    for p in ports:
        table.add_row(str(p["port"]), p["service"], f"[{severity_color(p['level'])}]{p['level']}[/]")
    console.print(table)
    console.print()


def wa_display_event_logs(events):
    console.print(Rule("[bold #5a3a1a]  WINDOWS EVENT LOG ANALYSIS", style="#5a3a1a"))
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Event Check", width=28, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Finding",     width=58, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",        width=8, header_style="bold #5a3a1a", no_wrap=True)
    for e in events:
        table.add_row(e["event"], e["detail"], f"[{severity_color(e['level'])}]{e['level']}[/]")
    console.print(table)
    console.print()


def wa_display_startup_programs(programs):
    console.print(Rule("[bold #5a3a1a]  STARTUP PROGRAMS AUDIT", style="#5a3a1a"))
    if not programs:
        console.print("  [dark_green]No startup programs found in registry.[/]\n")
        return
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Name", width=26, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Path", width=55, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Hive", width=6, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk", width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Flag", width=16, header_style="bold #5a3a1a", no_wrap=True)
    for p in programs:
        path_display = p["path"][:54] + ("…" if len(p["path"]) > 54 else "")
        table.add_row(p["name"][:25], path_display, p["hive"], f"[{severity_color(p['level'])}]{p['level']}[/]", f"[red]{p['flag']}[/]" if p["flag"] else "")
    console.print(table)
    console.print()


def wa_display_password_policy(policy):
    console.print(Rule("[bold #5a3a1a]  PASSWORD POLICY", style="#5a3a1a"))
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Check",          width=35, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Current Value",  width=18, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",           width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Recommendation", width=35, header_style="bold #5a3a1a", no_wrap=True)
    for p in policy:
        table.add_row(p["check"], str(p["value"]), f"[{severity_color(p['level'])}]{p['level']}[/]", p["note"])
    console.print(table)
    console.print()


def wa_display_firewall(fw):
    console.print(Rule("[bold #5a3a1a]  FIREWALL STATUS", style="#5a3a1a"))
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Check",  width=32, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Status", width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",   width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Note",   width=45, header_style="bold #5a3a1a", no_wrap=True)
    for f in fw:
        table.add_row(f["check"], f["state"], f"[{severity_color(f['level'])}]{f['level']}[/]", f["note"])
    console.print(table)
    console.print()


def wa_display_patch_status(patches):
    console.print(Rule("[bold #5a3a1a]  PATCH STATUS", style="#5a3a1a"))
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Check",  width=30, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Value",  width=28, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",   width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Note",   width=38, header_style="bold #5a3a1a", no_wrap=True)
    for p in patches:
        if p["check"] == "Recent Patches (last 5)":
            updates = p["value"]
            if isinstance(updates, list) and updates:
                table.add_row("", "", "", "")
                for u in updates:
                    table.add_row(f"  [dim]Patch {u['id']}[/]", f"[dim]{u['date']}[/]", "", "")
            continue
        table.add_row(p["check"], str(p.get("value", "")), f"[{severity_color(p['level'])}]{p['level']}[/]", p["note"])
    console.print(table)
    console.print()


# ---------------------------------------------------------------------
#  v1.2.0 - Advanced hardening & posture checks
#  Adds Defender/AV health, config hardening, network shares, and an
#  installed-software inventory. Each helper returns finding dicts shaped
#  like the other modules: {category, check, value, level, note}.
# ---------------------------------------------------------------------

RISKY_SOFTWARE = [
    (re.compile(r"adobe\s+flash", re.I),                    "HIGH",   "End-of-life & permanently vulnerable - uninstall"),
    (re.compile(r"java(\s|\(tm\)).*\b[678]\b", re.I),       "MEDIUM", "Old Java runtime - update or remove"),
    (re.compile(r"python\s*2(\.\d+)?\b", re.I),             "LOW",    "Python 2 is end-of-life"),
    (re.compile(r"winrar", re.I),                           "MEDIUM", "Ensure version >= 6.23 (CVE-2023-38831)"),
    (re.compile(r"quicktime", re.I),                        "HIGH",   "End-of-life & unpatched"),
    (re.compile(r"(teamviewer|anydesk|vnc|logmein)", re.I), "INFO",   "Remote-access tool - confirm it's intended"),
]


def _reg_get(hive, path, name):
    """Read a single registry value, or None if absent."""
    try:
        key = winreg.OpenKey(hive, path)
        value, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return value
    except Exception:
        return None


def _reg_qv(key, name):
    try:
        v, _ = winreg.QueryValueEx(key, name)
        return v
    except Exception:
        return None


def _ps_json(command):
    """Run a PowerShell command and json.loads its output (always a list)."""
    raw = run_cmd(command)
    try:
        data = json.loads(raw) if raw.strip() else None
    except Exception:
        return []
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def _adv_defender():
    data = _ps_json('powershell -NoProfile -Command "Get-MpComputerStatus | '
                    'Select-Object RealTimeProtectionEnabled,AntivirusEnabled,'
                    'AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json"')
    if not data:
        return [{"category": "Defender", "check": "Microsoft Defender", "value": "n/a",
                 "level": "INFO", "note": "Status unavailable (3rd-party AV, or run as admin)"}]
    d = data[0]
    out = []
    rtp = bool(d.get("RealTimeProtectionEnabled"))
    out.append({"category": "Defender", "check": "Real-Time Protection",
                "value": "ON" if rtp else "OFF", "level": "LOW" if rtp else "HIGH",
                "note": "Active" if rtp else "Real-time scanning is DISABLED"})
    try:
        age = int(d.get("AntivirusSignatureAge"))
        lvl = "HIGH" if age > 14 else "MEDIUM" if age > 7 else "LOW"
        out.append({"category": "Defender", "check": "Signature Age (days)", "value": str(age),
                    "level": lvl, "note": "Update definitions" if age > 7 else "Current"})
    except (TypeError, ValueError):
        pass
    tp = bool(d.get("IsTamperProtected"))
    out.append({"category": "Defender", "check": "Tamper Protection",
                "value": "ON" if tp else "OFF", "level": "LOW",
                "note": "Enabled" if tp else "Consider enabling"})
    return out


def _adv_hardening():
    out = []
    HKLM = winreg.HKEY_LOCAL_MACHINE

    smb1 = run_cmd('powershell -NoProfile -Command "(Get-SmbServerConfiguration).EnableSMB1Protocol"').strip().lower()
    if smb1 in ("true", "false"):
        on = smb1 == "true"
        out.append({"category": "Hardening", "check": "SMBv1 protocol",
                    "value": "ENABLED" if on else "disabled", "level": "HIGH" if on else "LOW",
                    "note": "Legacy/wormable (EternalBlue) - disable" if on else "Good"})

    lua = _reg_get(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    if lua is not None:
        out.append({"category": "Hardening", "check": "UAC (EnableLUA)", "value": str(lua),
                    "level": "HIGH" if lua == 0 else "LOW",
                    "note": "UAC is DISABLED" if lua == 0 else "Enabled"})

    deny = _reg_get(HKLM, r"System\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if deny == 0:
        nla = _reg_get(HKLM, r"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
        if nla == 0:
            out.append({"category": "Hardening", "check": "Remote Desktop (RDP)", "value": "ON, no NLA",
                        "level": "HIGH", "note": "RDP enabled without Network Level Auth"})
        else:
            out.append({"category": "Hardening", "check": "Remote Desktop (RDP)", "value": "ENABLED",
                        "level": "MEDIUM", "note": "On (NLA required) - restrict/disable if unused"})
    elif deny is not None:
        out.append({"category": "Hardening", "check": "Remote Desktop (RDP)", "value": "disabled",
                    "level": "LOW", "note": "Off"})

    aal = _reg_get(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    if str(aal) == "1":
        pwd = _reg_get(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")
        out.append({"category": "Hardening", "check": "Automatic Logon", "value": "ENABLED",
                    "level": "HIGH", "note": "Password stored in registry!" if pwd else "Auto-logon is on"})

    rr = run_cmd('powershell -NoProfile -Command "(Get-Service RemoteRegistry).Status"').strip()
    if rr:
        running = rr.lower() == "running"
        out.append({"category": "Hardening", "check": "Remote Registry svc", "value": rr,
                    "level": "MEDIUM" if running else "LOW",
                    "note": "Running - disable if unused" if running else "Not running"})

    bl = run_cmd('powershell -NoProfile -Command "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"').strip()
    if bl in ("0", "1"):
        on = bl == "1"
        out.append({"category": "Hardening", "check": "BitLocker (OS drive)",
                    "value": "On" if on else "Off", "level": "LOW" if on else "MEDIUM",
                    "note": "Encrypted" if on else "OS drive NOT encrypted"})
    return out


def _adv_shares():
    out = []
    shares = _ps_json('powershell -NoProfile -Command "Get-SmbShare | Select-Object Name,Path | ConvertTo-Json"')
    custom = [s for s in shares if not str(s.get("Name", "")).endswith("$")]
    for s in custom:
        name = s.get("Name")
        access = run_cmd(f"powershell -NoProfile -Command \"Get-SmbShareAccess -Name '{name}' | Out-String\"").lower()
        loose = "everyone" in access and "allow" in access
        out.append({"category": "Shares", "check": f"Share '{name}'", "value": str(s.get("Path", "")),
                    "level": "HIGH" if loose else "MEDIUM",
                    "note": "Open to EVERYONE" if loose else "Custom share - review access"})
    out.append({"category": "Shares", "check": "SMB shares",
                "value": f"{len(shares)} total / {len(custom)} custom", "level": "INFO",
                "note": "Default admin shares (C$, ADMIN$, IPC$) are normal"})
    return out


def _enum_installed_software():
    apps = {}
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, base in roots:
        try:
            bkey = winreg.OpenKey(hive, base)
        except Exception:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(bkey, i); i += 1
            except OSError:
                break
            try:
                sk = winreg.OpenKey(bkey, sub)
                name = _reg_qv(sk, "DisplayName")
                if name:
                    apps[name] = _reg_qv(sk, "DisplayVersion") or "?"
                winreg.CloseKey(sk)
            except Exception:
                continue
        winreg.CloseKey(bkey)
    return apps


def _adv_software():
    out = []
    apps = _enum_installed_software()
    for name, ver in apps.items():
        for pattern, lvl, note in RISKY_SOFTWARE:
            if pattern.search(name):
                out.append({"category": "Software", "check": name[:38], "value": str(ver),
                            "level": lvl, "note": note})
                break
    out.append({"category": "Software", "check": "Installed programs",
                "value": f"{len(apps)} found", "level": "INFO",
                "note": "Verify internet-facing apps vs vendor advisories"})
    out.append({"category": "Software", "check": "View / uninstall apps",
                "value": "Windows", "level": "INFO",
                "note": "Settings > Apps > Installed apps"})
    return out


def wa_check_advanced():
    """v1.2.0 - Defender, config hardening, shares, and software inventory."""
    findings = []
    for probe in (_adv_defender, _adv_hardening, _adv_shares, _adv_software):
        try:
            findings.extend(probe())
        except Exception:
            continue
    return findings


def wa_display_advanced(findings):
    console.print(Rule("[bold #5a3a1a]  ADVANCED HARDENING  (v1.2.0)", style="#5a3a1a"))
    if not findings:
        console.print("  [dark_green]No advanced findings.[/]\n"); return
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("Category", width=11, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Check",    width=30, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Value",    width=16, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",     width=8,  header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Note",     width=36, header_style="bold #5a3a1a", no_wrap=True)
    for f in findings:
        table.add_row(str(f.get("category", ""))[:10], str(f.get("check", ""))[:29],
                      str(f.get("value", ""))[:15], f"[{severity_color(f['level'])}]{f['level']}[/]",
                      str(f.get("note", ""))[:35])
    console.print(table)
    console.print("  [dim]Full installed-apps list ->  Windows Settings > Apps > Installed apps"
                  "   (or run  appwiz.cpl  /  ms-settings:appsfeatures)[/]")
    console.print()


def wa_compute_score(all_findings):
    high = medium = 0
    for key in ["network", "ports", "events", "startup", "password", "firewall", "patches", "advanced"]:
        for item in all_findings.get(key, []):
            lv = item.get("level", "").upper()
            if lv == "HIGH":     high += 1
            elif lv == "MEDIUM": medium += 1
    score = max(0, 100 - (high * 15) - (medium * 5))
    grade = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "F"
    return score, grade, high, medium


def wa_display_summary(score, grade, high, medium):
    color = "dark_green" if score >= 80 else "yellow" if score >= 50 else "red"
    console.print(Rule("[bold white]  AUDIT SUMMARY", style="white"))
    console.print()
    console.print(f"  [{color}]Security Score: {score}/100  [{grade}][/{color}]")
    console.print(f"  [red]HIGH risk findings  : {high}[/]")
    console.print(f"  [yellow]MEDIUM risk findings: {medium}[/]")
    console.print()


def wa_write_report(sysinfo, all_findings, score, grade, high, medium):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sentry_system_audit_{timestamp}.txt"
    lines = []
    lines.append("=" * 70)
    lines.append("          SENTRY — SYSTEM_AUDIT SECURITY REPORT")
    lines.append("=" * 70)
    lines.extend(_sysinfo_report_block(sysinfo))
    lines.append("=" * 70)
    lines.append(f"  SECURITY SCORE : {score}/100  [Grade: {grade}]")
    lines.append(f"  HIGH risk      : {high}")
    lines.append(f"  MEDIUM risk    : {medium}")
    lines.append("=" * 70)
    lines.append("")
    sections = [
        ("NETWORK CONNECTIONS", "network",  lambda c: f"  [{c['level']:6}] {c['remote_ip']}:{c['remote_port']}  (PID {c['pid']} - {c['process']})"),
        ("OPEN PORTS",          "ports",    lambda p: f"  [{p['level']:6}] Port {p['port']:5}  {p['service']}"),
        ("EVENT LOG ANALYSIS",  "events",   lambda e: f"  [{e['level']:6}] {e['event']}: {e['detail']}"),
        ("STARTUP PROGRAMS",    "startup",  lambda p: f"  [{p['level']:6}] {p['name']} ({p['hive']}) -> {p['path']}" + (f"  *** {p['flag']} ***" if p.get("flag") else "")),
        ("PASSWORD POLICY",     "password", lambda p: f"  [{p['level']:6}] {p['check']}: {p['value']}  ({p['note']})"),
        ("FIREWALL STATUS",     "firewall", lambda f: f"  [{f['level']:6}] {f['check']}: {f['state']}  - {f['note']}"),
    ]
    for title, key, fmt in sections:
        lines.append("-" * 70)
        lines.append(f"  {title}")
        lines.append("-" * 70)
        for item in all_findings.get(key, []):
            lines.append(fmt(item))
        lines.append("")
    lines.append("-" * 70)
    lines.append("  PATCH STATUS")
    lines.append("-" * 70)
    for p in all_findings.get("patches", []):
        if p["check"] == "Recent Patches (last 5)":
            for u in (p["value"] if isinstance(p["value"], list) else []):
                lines.append(f"  [INFO  ] Patch {u['id']} installed on {u['date']}")
        else:
            lines.append(f"  [{p['level']:6}] {p['check']}: {p.get('value', '')}  ({p['note']})")
    lines.append("")
    lines.append("-" * 70)
    lines.append("  ADVANCED HARDENING  (Defender / Config / Shares / Software)")
    lines.append("-" * 70)
    for item in all_findings.get("advanced", []):
        lines.append(f"  [{item['level']:6}] [{item.get('category', '')}] {item['check']}: {item['value']}  ({item['note']})")
    lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT  —  Generated by Sentry v1.2.0")
    lines.append("  github.com/hetpatel2102")
    lines.append("=" * 70)
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filename


def run_system_audit():
    console.print(Rule("[bold #5a3a1a]  SYSTEM_AUDIT — SYSTEM SECURITY AUDIT", style="#5a3a1a"))
    console.print()
    tasks = [
        ("System Info",         wa_get_system_info),
        ("Network Connections", wa_scan_network_connections),
        ("Open Ports",          wa_scan_open_ports),
        ("Event Logs",          wa_check_event_logs),
        ("Startup Programs",    wa_check_startup_programs),
        ("Password Policy",     wa_check_password_policy),
        ("Firewall Status",     wa_check_firewall),
        ("Patch Status",        wa_check_patch_status),
        ("Advanced Checks",     wa_check_advanced),
    ]
    results = {}
    with Progress(SpinnerColumn(spinner_name="dots", style="dim white"), TextColumn("[dim white]{task.description}"), BarColumn(bar_width=30, style="dim white", complete_style="dim white"), TextColumn("[dim white]{task.percentage:>3.0f}%"), DimTimeElapsedColumn(), console=console, transient=True) as progress:
        overall = progress.add_task("Running audit...", total=len(tasks))
        for name, fn in tasks:
            task = progress.add_task(f"  {name}", total=1)
            try:
                results[name] = fn()
            except Exception:
                results[name] = []
            progress.update(task, completed=1)
            progress.update(overall, advance=1)
    console.print()
    all_findings = {}
    sysinfo = results.get("System Info", {})
    wa_display_system_info(sysinfo)
    net = results.get("Network Connections", []);  all_findings["network"] = net;  wa_display_network_connections(net)
    ports = results.get("Open Ports", []);         all_findings["ports"] = ports;  wa_display_open_ports(ports)
    events = results.get("Event Logs", []);        all_findings["events"] = events; wa_display_event_logs(events)
    startup = results.get("Startup Programs", []); all_findings["startup"] = startup; wa_display_startup_programs(startup)
    password = results.get("Password Policy", []); all_findings["password"] = password; wa_display_password_policy(password)
    fw = results.get("Firewall Status", []);       all_findings["firewall"] = fw;  wa_display_firewall(fw)
    patches = results.get("Patch Status", []);     all_findings["patches"] = patches; wa_display_patch_status(patches)
    advanced = results.get("Advanced Checks", []); all_findings["advanced"] = advanced; wa_display_advanced(advanced)
    score, grade, high, medium = wa_compute_score(all_findings)
    wa_display_summary(score, grade, high, medium)
    report_file = wa_write_report(sysinfo, all_findings, score, grade, high, medium)
    console.print(f"  [bold dark_green]Report saved to:[/] [#5a3a1a]{report_file}[/]")
    console.print()
    return report_file


SUSPICIOUS_PATH_KEYWORDS = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\", "\\public\\", "\\recycle", "\\windows\\temp\\", "%temp%"]
SAFE_SUSPENDED_PROCESSES = {"backgroundtaskhost.exe", "runtimebroker.exe", "shellexperiencehost.exe", "lockapp.exe", "searchapp.exe", "searchhost.exe", "applicationframehost.exe", "systemsettings.exe", "memcompression", "registry", "rtkuwp.exe", "adobenotificationclient.exe", "unknown"}


def ph_hunt_hidden_suspended() -> list:
    findings = []
    raw_tasklist = run_cmd("tasklist /FO CSV /NH")
    tasklist_pids = set()
    for line in raw_tasklist.splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            try:
                tasklist_pids.add(int(parts[1]))
            except ValueError:
                continue
    for proc in psutil.process_iter(["pid", "name", "status", "exe"]):
        try:
            pid = proc.info["pid"]; name = proc.info["name"] or "Unknown"
            status = proc.info["status"] or ""; exe = proc.info["exe"] or ""
            if pid in SELF_PIDS:
                continue
            if pid not in tasklist_pids and pid != 0:
                findings.append({"pid": pid, "name": name, "exe": exe or "N/A", "finding": "NOT in tasklist — possibly hidden", "level": "HIGH", "category": "Hidden"})
            if status == psutil.STATUS_STOPPED:
                is_safe = name.lower() in SAFE_SUSPENDED_PROCESSES
                findings.append({"pid": pid, "name": name, "exe": exe or "N/A", "finding": "Suspended by Windows (normal)" if is_safe else "Process is SUSPENDED", "level": "LOW" if is_safe else "MEDIUM", "category": "Suspended"})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def ph_hunt_fileless() -> list:
    findings = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid = proc.info["pid"]; name = proc.info["name"] or "Unknown"; exe = proc.info["exe"]
            if pid in (0, 4) or pid in SELF_PIDS or name.lower() in SAFE_SUSPENDED_PROCESSES:
                continue
            if not exe:
                findings.append({"pid": pid, "name": name, "exe": "NO PATH", "finding": "No executable path — possible fileless process", "level": "HIGH", "category": "Fileless"})
            elif not os.path.exists(exe):
                findings.append({"pid": pid, "name": name, "exe": exe, "finding": "Executable NOT found on disk", "level": "HIGH", "category": "Fileless"})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def ph_hunt_injection() -> list:
    findings = []
    suspicious_parents = {
        "svchost.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "explorer.exe": ["powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe"],
        "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    }
    pid_name = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid_name[proc.info["pid"]] = (proc.info["name"] or "").lower()
        except Exception:
            continue
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        try:
            pid = proc.info["pid"]; name = (proc.info["name"] or "Unknown").lower()
            exe = proc.info["exe"] or ""; ppid = proc.info["ppid"] or 0
            if pid in SELF_PIDS:
                continue
            parent_name = pid_name.get(ppid, "").lower()
            for parent, bad_children in suspicious_parents.items():
                if parent_name == parent and name in [c.lower() for c in bad_children]:
                    findings.append({"pid": pid, "name": proc.info["name"], "exe": exe or "N/A", "finding": f"Spawned by {parent} — classic injection pivot", "level": "HIGH", "category": "Injection"})
                    break
            try:
                maps = proc.memory_maps()
                for m in maps:
                    path_lower = m.path.lower()
                    if any(kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS) and path_lower.endswith(".dll"):
                        findings.append({"pid": pid, "name": proc.info["name"], "exe": exe or "N/A", "finding": f"DLL loaded from suspicious path: {m.path[:60]}", "level": "HIGH", "category": "DLL Injection"})
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def ph_hunt_unsigned() -> list:
    findings = []
    exe_map = {}
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid = proc.info["pid"]; name = proc.info["name"] or "Unknown"; exe = proc.info["exe"]
            if exe and pid not in (0, 4) and pid not in SELF_PIDS and os.path.exists(exe):
                exe_map[exe] = (pid, name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not exe_map:
        return findings
    paths = list(exe_map.keys())[:60]
    paths_ps = ", ".join(f'"{p}"' for p in paths)
    ps_cmd = (f'powershell -Command "$paths = @({paths_ps}); foreach ($p in $paths) {{ $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction SilentlyContinue; if ($sig) {{ Write-Output ($p + \\"|\\" + $sig.Status) }} }}"')
    raw = run_cmd(ps_cmd)
    for line in raw.splitlines():
        if "|" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) != 2:
            continue
        exe_path, status = parts[0].strip(), parts[1].strip()
        if status in ("NotSigned", "UnknownError", "HashMismatch", "NotTrusted"):
            pid, name = exe_map.get(exe_path, (0, "Unknown"))
            level = "HIGH" if status in ("HashMismatch", "NotTrusted") else "MEDIUM"
            findings.append({"pid": pid, "name": name, "exe": exe_path[:70], "finding": f"Signature status: {status}", "level": level, "category": "Unsigned"})
    return findings


def ph_hunt_suspicious_paths() -> list:
    findings = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            pid = proc.info["pid"]; name = proc.info["name"] or "Unknown"
            exe = (proc.info["exe"] or "").lower(); user = proc.info["username"] or "N/A"
            if not exe or pid in (0, 4) or pid in SELF_PIDS:
                continue
            for kw in SUSPICIOUS_PATH_KEYWORDS:
                if kw in exe:
                    findings.append({"pid": pid, "name": name, "exe": proc.info["exe"][:70], "finding": f"Running from suspicious path ({kw.strip(chr(92))})", "level": "HIGH", "category": "Suspicious Path", "user": user})
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def ph_make_findings_table(title, findings):
    table = Table(title=f"[bold #5a3a1a]{title}[/]", box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", title_justify="left", padding=(0, 2), show_edge=False)
    table.add_column("PID",      width=7, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Name",     width=25, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Category", width=18, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Finding",  width=52, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",     width=8, header_style="bold #5a3a1a", no_wrap=True)
    if not findings:
        table.add_row("—", "[dark_green]None detected[/]", "—", "Clean", "[dark_green]LOW[/]")
    else:
        for f in findings:
            color = severity_color(f["level"])
            finding_text = f["finding"][:51] + ("…" if len(f["finding"]) > 51 else "")
            table.add_row(str(f["pid"]), f["name"][:24], f.get("category", "—"), finding_text, f"[{color}]{f['level']}[/]")
    return table


def ph_compute_score(all_findings):
    high   = sum(1 for f in all_findings if f.get("level") == "HIGH")
    medium = sum(1 for f in all_findings if f.get("level") == "MEDIUM")
    score  = max(0, 100 - (high * 12) - (medium * 4))
    grade  = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "F"
    return score, grade, high, medium


def ph_display_summary(score, grade, high, medium, total_scanned):
    color = "dark_green" if score >= 80 else "yellow" if score >= 50 else "red"
    console.print(Rule("[bold white]  HUNT SUMMARY", style="white"))
    console.print()
    console.print(f"  [{color}]Threat Score : {score}/100  [{grade}][/{color}]")
    console.print(f"  [white]Processes scanned : {total_scanned}[/]")
    console.print(f"  [red]HIGH  threats     : {high}[/]")
    console.print(f"  [yellow]MEDIUM threats    : {medium}[/]")
    console.print()


def ph_write_report(all_findings, score, grade, high, medium, total_scanned):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sentry_process_scan_{timestamp}.txt"
    lines = []
    lines.append("=" * 70)
    lines.append("          SENTRY — PROCESS_SCAN THREAT REPORT")
    lines.append("=" * 70)
    lines.append(f"  Hostname         : {platform.node()}")
    lines.append(f"  OS               : {platform.platform()}")
    lines.append(f"  Scan Time        : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Admin Run        : {'YES' if is_admin() else 'NO'}")
    lines.append(f"  Processes Scanned: {total_scanned}")
    lines.append("=" * 70)
    lines.append(f"  THREAT SCORE     : {score}/100  [Grade: {grade}]")
    lines.append(f"  HIGH  threats    : {high}")
    lines.append(f"  MEDIUM threats   : {medium}")
    lines.append("=" * 70)
    lines.append("")
    categories = {}
    for f in all_findings:
        categories.setdefault(f.get("category", "Other"), []).append(f)
    for cat, items in categories.items():
        lines.append("-" * 70)
        lines.append(f"  {cat.upper()}")
        lines.append("-" * 70)
        for f in items:
            lines.append(f"  [{f['level']:6}] PID {f['pid']:6}  {f['name'][:22]:22}  {f['finding']}")
            lines.append(f"           Path: {f.get('exe', 'N/A')}")
        lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT  —  Generated by Sentry v1.2.0")
    lines.append("  github.com/hetpatel2102")
    lines.append("=" * 70)
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return filename


def ph_kill_process(pid, name):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
        return True, f"Process {name} (PID {pid}) terminated successfully."
    except psutil.NoSuchProcess:
        return False, f"PID {pid} no longer exists — already dead."
    except psutil.AccessDenied:
        return False, f"Access denied. Run as Administrator to kill {name} (PID {pid})."
    except Exception as e:
        return False, f"Failed to kill {name} (PID {pid}): {e}"


def ph_build_kill_table(killable):
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold #5a3a1a", padding=(0, 2), show_edge=False)
    table.add_column("#",        width=4,  style="bold #5a3a1a", no_wrap=True, header_style="bold #5a3a1a")
    table.add_column("PID",      width=7, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Name",     width=25, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Category", width=18, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Risk",     width=8, header_style="bold #5a3a1a", no_wrap=True)
    table.add_column("Finding",  width=48, header_style="bold #5a3a1a", no_wrap=True)
    for i, f in enumerate(killable, start=1):
        color = severity_color(f["level"])
        finding_text = f["finding"][:47] + ("…" if len(f["finding"]) > 47 else "")
        table.add_row(str(i), str(f["pid"]), f["name"][:24], f.get("category", "—"), f"[{color}]{f['level']}[/]", finding_text)
    return table


def ph_interactive_kill_ui(all_findings, report_file):
    admin = is_admin()
    seen_pids = set()
    killable = []
    for f in all_findings:
        pid = f.get("pid")
        if pid and pid not in seen_pids and f.get("level") in ("HIGH", "MEDIUM"):
            seen_pids.add(pid)
            killable.append(f)
    killable.sort(key=lambda x: 0 if x["level"] == "HIGH" else 1)
    action_log = []

    while True:
        console.print(Rule("[bold white]  PROCESS MANAGER", style="white"))
        console.print()
        if not killable:
            console.print("[dark_green]  No flagged processes remaining. System looks clean![/]")
            console.print()
            break

        console.print(f"  [dim]Flagged processes ({len(killable)} remaining):[/]\n")
        console.print(ph_build_kill_table(killable))
        console.print()

        hints = ["[#5a3a1a]#[/] — kill by number", "[#5a3a1a]a[/] — kill ALL listed", "[#5a3a1a]r[/] — rescan", "[#5a3a1a]q[/] — quit"]
        if admin:
            hints.insert(1, "[red bold]!h[/] — kill ALL HIGH instantly")
        console.print("  Commands: " + "   ".join(hints))
        console.print()

        if admin:
            console.print("[red bold]  ⚡ ADMIN MODE — You have the power to terminate any process.[/]")
            console.print("[red bold]  Use !h to instantly kill all HIGH risk processes.[/]\n")

        try:
            raw = console.input("  [bold #5a3a1a]>[/] ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [dim]Interrupted. Exiting...[/]\n")
            break

        if not raw:
            continue

        if raw == "q":
            console.print()
            console.print(f"[bold #5a3a1a]  Session ended.  Report saved at: [white]{report_file}[/][/]")
            console.print()
            if action_log:
                console.print("  [dim]Actions taken this session:[/]")
                for entry in action_log:
                    console.print(f"    {'[dark_green]✔[/]' if entry['success'] else '[red]✘[/]'}  {entry['msg']}")
                console.print()
            break

        if raw == "r":
            console.print("\n  [#5a3a1a]Rescanning...[/]\n")
            still_alive = []
            for f in killable:
                try:
                    psutil.Process(f["pid"]); still_alive.append(f)
                except psutil.NoSuchProcess:
                    console.print(f"  [dim]PID {f['pid']} ({f['name']}) is gone.[/]")
            killable = still_alive
            console.print()
            continue

        if raw == "!h":
            if not admin:
                console.print("  [red]This command requires Administrator mode.[/]\n"); continue
            high_procs = [f for f in killable if f["level"] == "HIGH"]
            if not high_procs:
                console.print("  [yellow]No HIGH risk processes in the list.[/]\n"); continue
            console.print()
            console.print(f"[red bold]  ⚠  You are about to terminate {len(high_procs)} HIGH risk process(es):[/]")
            for f in high_procs:
                console.print(f"  [white]• {f['name']} (PID {f['pid']})[/]")
            console.print("[white]  This cannot be undone. Proceed?[/]\n")
            confirm = console.input("  [red bold]Type YES to confirm, anything else to cancel:[/] ").strip()
            console.print()
            if confirm == "YES":
                for f in high_procs:
                    ok, msg = ph_kill_process(f["pid"], f["name"])
                    console.print(f"    {'[dark_green]✔[/]' if ok else '[red]✘[/]'}  {msg}")
                    action_log.append({"success": ok, "msg": msg})
                    if ok:
                        killable = [x for x in killable if x["pid"] != f["pid"]]
                console.print()
            else:
                console.print("  [dim]Mass kill cancelled.[/]\n")
            continue

        if raw == "a":
            console.print()
            console.print(f"[yellow]  ⚠  You are about to terminate ALL {len(killable)} flagged process(es). This cannot be undone.[/]")
            confirm = console.input("  [yellow]Type YES to confirm:[/] ").strip()
            console.print()
            if confirm == "YES":
                for f in list(killable):
                    ok, msg = ph_kill_process(f["pid"], f["name"])
                    console.print(f"    {'[dark_green]✔[/]' if ok else '[red]✘[/]'}  {msg}")
                    action_log.append({"success": ok, "msg": msg})
                    if ok:
                        killable.remove(f)
                console.print()
            else:
                console.print("  [dim]Cancelled.[/]\n")
            continue

        try:
            idx = int(raw) - 1
            if idx < 0 or idx >= len(killable):
                raise ValueError
        except ValueError:
            console.print(f"  [red]Unknown command:[/] '{raw}' — try a number, a, r, q" + (", or !h" if admin else "") + "\n")
            continue

        target = killable[idx]
        console.print()
        detail = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        detail.add_column("Key", style="dim #5a3a1a", width=14)
        detail.add_column("Value", style="white")
        detail.add_row("Name",     target["name"])
        detail.add_row("PID",      str(target["pid"]))
        detail.add_row("Risk",     f"[{severity_color(target['level'])}]{target['level']}[/]")
        detail.add_row("Category", target.get("category", "—"))
        detail.add_row("Finding",  target["finding"])
        detail.add_row("Path",     target.get("exe", "N/A"))
        console.print(detail)
        console.print()

        if admin:
            console.print(f"  [red bold]⚡ ADMIN MODE — Terminating [white]{target['name']}[/white] (PID {target['pid']}) will immediately stop this process.[/]")
            confirm = console.input("  [red bold]Type KILL to terminate, anything else to cancel:[/] ").strip()
        else:
            confirm = console.input(f"  [yellow]Terminate [white]{target['name']}[/white] (PID {target['pid']})? [bold](y/n):[/] ").strip().lower()

        console.print()
        should_kill = (confirm == "KILL") if admin else (confirm == "y")
        if should_kill:
            ok, msg = ph_kill_process(target["pid"], target["name"])
            console.print(f"    {'[dark_green]✔[/]' if ok else '[red]✘[/]'}  {msg}\n")
            action_log.append({"success": ok, "msg": msg})
            if ok:
                killable.pop(idx)
        else:
            console.print("  [dim]Skipped.[/]\n")


def run_process_scan():
    console.print(Rule("[bold #5a3a1a]  PROCESS_SCAN — MALICIOUS PROCESS DETECTION", style="#5a3a1a"))
    console.print()
    if not HAS_PSUTIL:
        console.print("[red]  psutil is required for Process_Scan. Run: pip install psutil[/]")
        return None
    _refresh_self_pids()
    total_scanned = len(list(psutil.process_iter()))
    modules = [
        ("Hunting hidden & suspended processes",  ph_hunt_hidden_suspended),
        ("Hunting fileless processes",            ph_hunt_fileless),
        ("Hunting process injection indicators",  ph_hunt_injection),
        ("Hunting unsigned executables",          ph_hunt_unsigned),
        ("Hunting suspicious path processes",     ph_hunt_suspicious_paths),
    ]
    section_results = {}
    with Progress(SpinnerColumn(spinner_name="dots", style="dim white"), TextColumn("[dim white]{task.description}"), BarColumn(bar_width=30, style="dim white", complete_style="dim white"), TextColumn("[dim white]{task.percentage:>3.0f}%"), DimTimeElapsedColumn(), console=console, transient=True) as progress:
        overall = progress.add_task("Running hunt...", total=len(modules))
        for label, fn in modules:
            task = progress.add_task(f"  {label}", total=1)
            try:
                section_results[label] = fn()
            except Exception:
                section_results[label] = []
            progress.update(task, completed=1)
            progress.update(overall, advance=1)
    console.print()
    section_labels = [
        ("Hidden & Suspended",       "Hunting hidden & suspended processes",  ""),
        ("Fileless Processes",        "Hunting fileless processes",            ""),
        ("Process Injection",         "Hunting process injection indicators",  ""),
        ("Unsigned Executables",      "Hunting unsigned executables",          ""),
        ("Suspicious Path Processes", "Hunting suspicious path processes",     ""),
    ]
    all_findings = []
    for display_title, label, icon in section_labels:
        findings = section_results.get(label, [])
        all_findings.extend(findings)
        console.print(ph_make_findings_table(display_title, findings))
        console.print()
    score, grade, high, medium = ph_compute_score(all_findings)
    ph_display_summary(score, grade, high, medium, total_scanned)
    report_file = ph_write_report(all_findings, score, grade, high, medium, total_scanned)
    console.print(f"  [bold dark_green]Report saved to:[/] [#5a3a1a]{report_file}[/]")
    console.print()
    high_count = sum(1 for f in all_findings if f.get("level") == "HIGH")
    med_count  = sum(1 for f in all_findings if f.get("level") == "MEDIUM")
    if high_count + med_count == 0:
        console.print("[dark_green bold]  ✔ No threats to manage. System looks clean![/]")
        console.print("[white]  Press Enter to continue.[/]")
        console.input("")
    else:
        console.print(f"  [bold white]Scan complete.[/]  Found [red bold]{high_count} HIGH[/] and [yellow]{med_count} MEDIUM[/] risk processes.")
        console.print("  Entering process manager — you can review and terminate threats below.\n")
        ph_interactive_kill_ui(all_findings, report_file)
    return report_file


def run_full_sweep():
    console.print("  [bold white]SENTRY — FULL SECURITY SWEEP[/]")
    console.print("  [#5a3a1a]Phase 1:[/] System_Audit  — 9 system checks")
    console.print("  [#5a3a1a]Phase 2:[/] Process_Scan  — 5 threat hunts")
    console.print("  [dim]One report. One score. One session.[/]\n")

    _refresh_self_pids()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    wa_tasks = [
        ("System Info",         wa_get_system_info),
        ("Network Connections", wa_scan_network_connections),
        ("Open Ports",          wa_scan_open_ports),
        ("Event Logs",          wa_check_event_logs),
        ("Startup Programs",    wa_check_startup_programs),
        ("Password Policy",     wa_check_password_policy),
        ("Firewall Status",     wa_check_firewall),
        ("Patch Status",        wa_check_patch_status),
        ("Advanced Checks",     wa_check_advanced),
    ]
    ph_tasks = [
        ("Hunting hidden & suspended processes",  ph_hunt_hidden_suspended),
        ("Hunting fileless processes",            ph_hunt_fileless),
        ("Hunting process injection indicators",  ph_hunt_injection),
        ("Hunting unsigned executables",          ph_hunt_unsigned),
        ("Hunting suspicious path processes",     ph_hunt_suspicious_paths),
    ]
    all_tasks  = wa_tasks + ph_tasks
    wa_results = {}
    ph_results = {}
    total_procs = len(list(psutil.process_iter())) if HAS_PSUTIL else 0

    with Progress(SpinnerColumn(spinner_name="dots", style="dim white"), TextColumn("[dim white]{task.description}"), BarColumn(bar_width=30, style="dim white", complete_style="dim white"), TextColumn("[dim white]{task.percentage:>3.0f}%"), DimTimeElapsedColumn(), console=console, transient=True) as progress:
        overall = progress.add_task("Full sweep in progress...", total=len(all_tasks))
        progress.add_task("── Phase 1: System_Audit", total=0)
        for name, fn in wa_tasks:
            t = progress.add_task(f"  {name}", total=1)
            try:
                wa_results[name] = fn()
            except Exception:
                wa_results[name] = []
            progress.update(t, completed=1)
            progress.update(overall, advance=1)
        progress.add_task("── Phase 2: Process_Scan", total=0)
        for name, fn in ph_tasks:
            t = progress.add_task(f"  {name}", total=1)
            try:
                ph_results[name] = fn()
            except Exception:
                ph_results[name] = []
            progress.update(t, completed=1)
            progress.update(overall, advance=1)

    console.print()
    console.print(Rule("[bold white]  PHASE 1 — SYSTEM AUDIT", style="white"))
    console.print()
    wa_all = {}
    sysinfo = wa_results.get("System Info", {})
    wa_display_system_info(sysinfo)
    net = wa_results.get("Network Connections", []);  wa_all["network"] = net;  wa_display_network_connections(net)
    ports = wa_results.get("Open Ports", []);         wa_all["ports"] = ports;  wa_display_open_ports(ports)
    events = wa_results.get("Event Logs", []);        wa_all["events"] = events; wa_display_event_logs(events)
    startup = wa_results.get("Startup Programs", []); wa_all["startup"] = startup; wa_display_startup_programs(startup)
    password = wa_results.get("Password Policy", []); wa_all["password"] = password; wa_display_password_policy(password)
    fw = wa_results.get("Firewall Status", []);       wa_all["firewall"] = fw;  wa_display_firewall(fw)
    patches = wa_results.get("Patch Status", []);     wa_all["patches"] = patches; wa_display_patch_status(patches)
    adv = wa_results.get("Advanced Checks", []);      wa_all["advanced"] = adv; wa_display_advanced(adv)

    console.print(Rule("[bold white]  PHASE 2 — PROCESS HUNT", style="white"))
    console.print()
    ph_section_labels = [
        ("Hidden & Suspended",       "Hunting hidden & suspended processes",  ""),
        ("Fileless Processes",        "Hunting fileless processes",            ""),
        ("Process Injection",         "Hunting process injection indicators",  ""),
        ("Unsigned Executables",      "Hunting unsigned executables",          ""),
        ("Suspicious Path Processes", "Hunting suspicious path processes",     ""),
    ]
    ph_all_findings = []
    for display_title, label, icon in ph_section_labels:
        findings = ph_results.get(label, [])
        ph_all_findings.extend(findings)
        console.print(ph_make_findings_table(display_title, findings))
        console.print()

    console.print(Rule("[bold white]  FULL SWEEP — COMBINED SUMMARY", style="white"))
    console.print()
    wa_high = wa_medium = 0
    for key in ["network", "ports", "events", "startup", "password", "firewall", "patches", "advanced"]:
        for item in wa_all.get(key, []):
            lv = item.get("level", "").upper()
            if lv == "HIGH":     wa_high += 1
            elif lv == "MEDIUM": wa_medium += 1
    ph_high   = sum(1 for f in ph_all_findings if f.get("level") == "HIGH")
    ph_medium = sum(1 for f in ph_all_findings if f.get("level") == "MEDIUM")
    total_high   = wa_high + ph_high
    total_medium = wa_medium + ph_medium
    combined_score = max(0, 100 - (total_high * 12) - (total_medium * 4))
    combined_grade = "A" if combined_score >= 80 else "B" if combined_score >= 65 else "C" if combined_score >= 50 else "F"
    color = "dark_green" if combined_score >= 80 else "yellow" if combined_score >= 50 else "red"

    console.print(f"  [{color}]Combined Security Score : {combined_score}/100  [{combined_grade}][/{color}]")
    console.print(f"  [dim white]── System_Audit ──[/]")
    console.print(f"  [red]HIGH findings   : {wa_high}[/]")
    console.print(f"  [yellow]MEDIUM findings : {wa_medium}[/]")
    console.print(f"  [dim white]── Process_Scan ──[/]")
    console.print(f"  [red]HIGH threats    : {ph_high}[/]")
    console.print(f"  [yellow]MEDIUM threats  : {ph_medium}[/]")
    console.print(f"  [white]Total processes scanned : {total_procs}[/]")
    console.print()

    report_file = f"sentry_fullsweep_{timestamp}.txt"
    lines = []
    lines.append("=" * 70)
    lines.append("          SENTRY — FULL SWEEP SECURITY REPORT")
    lines.append("=" * 70)
    lines.extend(_sysinfo_report_block(sysinfo))
    lines.append(f"  Processes Sc.: {total_procs}")
    lines.append("=" * 70)
    lines.append(f"  COMBINED SCORE    : {combined_score}/100  [Grade: {combined_grade}]")
    lines.append(f"  Total HIGH        : {total_high}  (Audit: {wa_high}  |  Hunter: {ph_high})")
    lines.append(f"  Total MEDIUM      : {total_medium}  (Audit: {wa_medium}  |  Hunter: {ph_medium})")
    lines.append("=" * 70)
    lines.append("")
    lines.append("=" * 70)
    lines.append("  PHASE 1 — SYSTEM AUDIT (System_Audit)")
    lines.append("=" * 70)
    lines.append("")
    wa_sections = [
        ("NETWORK CONNECTIONS", "network",  lambda c: f"  [{c['level']:6}] {c['remote_ip']}:{c['remote_port']}  (PID {c['pid']} - {c['process']})"),
        ("OPEN PORTS",          "ports",    lambda p: f"  [{p['level']:6}] Port {p['port']:5}  {p['service']}"),
        ("EVENT LOG ANALYSIS",  "events",   lambda e: f"  [{e['level']:6}] {e['event']}: {e['detail']}"),
        ("STARTUP PROGRAMS",    "startup",  lambda p: f"  [{p['level']:6}] {p['name']} ({p['hive']}) -> {p['path']}" + (f"  *** {p.get('flag','')} ***" if p.get("flag") else "")),
        ("PASSWORD POLICY",     "password", lambda p: f"  [{p['level']:6}] {p['check']}: {p['value']}  ({p['note']})"),
        ("FIREWALL STATUS",     "firewall", lambda f: f"  [{f['level']:6}] {f['check']}: {f['state']}  - {f['note']}"),
    ]
    for title, key, fmt in wa_sections:
        lines.append("-" * 70)
        lines.append(f"  {title}")
        lines.append("-" * 70)
        for item in wa_all.get(key, []):
            lines.append(fmt(item))
        lines.append("")
    lines.append("-" * 70)
    lines.append("  PATCH STATUS")
    lines.append("-" * 70)
    for p in wa_all.get("patches", []):
        if p["check"] == "Recent Patches (last 5)":
            for u in (p["value"] if isinstance(p["value"], list) else []):
                lines.append(f"  [INFO  ] Patch {u['id']} installed on {u['date']}")
        else:
            lines.append(f"  [{p['level']:6}] {p['check']}: {p.get('value', '')}  ({p['note']})")
    lines.append("")
    lines.append("-" * 70)
    lines.append("  ADVANCED HARDENING  (Defender / Config / Shares / Software)")
    lines.append("-" * 70)
    for item in wa_all.get("advanced", []):
        lines.append(f"  [{item['level']:6}] [{item.get('category', '')}] {item['check']}: {item['value']}  ({item['note']})")
    lines.append("")
    lines.append("=" * 70)
    lines.append("  PHASE 2 — PROCESS HUNT (Process_Scan)")
    lines.append("=" * 70)
    lines.append("")
    ph_categories = {}
    for f in ph_all_findings:
        ph_categories.setdefault(f.get("category", "Other"), []).append(f)
    for cat, items in ph_categories.items():
        lines.append("-" * 70)
        lines.append(f"  {cat.upper()}")
        lines.append("-" * 70)
        for f in items:
            lines.append(f"  [{f['level']:6}] PID {f['pid']:6}  {f['name'][:22]:22}  {f['finding']}")
            lines.append(f"           Path: {f.get('exe', 'N/A')}")
        lines.append("")
    lines.append("=" * 70)
    lines.append(f"  COMBINED SCORE : {combined_score}/100  [Grade: {combined_grade}]")
    lines.append(f"  HIGH  : {total_high}   MEDIUM : {total_medium}")
    lines.append("=" * 70)
    lines.append("  END OF REPORT  —  Generated by Sentry v1.2.0  (Full Sweep)")
    lines.append("  github.com/hetpatel2102")
    lines.append("=" * 70)
    with open(report_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    console.print(f"  [bold dark_green]Full sweep report saved to:[/] [#5a3a1a]{report_file}[/]")
    console.print()

    ph_high_count = ph_high
    ph_med_count  = ph_medium
    if ph_high_count + ph_med_count == 0:
        console.print("[dark_green bold]  ✔ No process threats to manage. Looks clean![/]")
        console.print("[white]  Press Enter to continue.[/]")
        console.input("")
    else:
        console.print(f"  [bold white]Process manager — review threats from the hunt.[/]")
        console.print(f"  Found [red bold]{ph_high_count} HIGH[/] and [yellow]{ph_med_count} MEDIUM[/] risk processes.")
        console.print("  Terminate anything suspicious before returning to the menu.\n")
        ph_interactive_kill_ui(ph_all_findings, report_file)


def main():
    # Force UTF-8 output so the Unicode banner/tables render even when the
    # output is redirected to a file or run in a legacy code-page console.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    print_banner()
    print_admin_notice()

    while True:
        print_menu()
        try:
            choice = console.input("  [bold #5a3a1a]Select an option (1 / 2 / 3 / q):[/] ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [dim]Exiting Sentry...[/]\n")
            break

        console.print()

        if choice == "q":
            console.print("[bold #5a3a1a]  Thanks for using Sentry.  Stay secure. — Het Patel  |  github.com/hetpatel2102[/]\n")
            break
        elif choice == "1":
            run_system_audit()
            console.input("  [dim]Press Enter to return to the menu...[/] ")
            console.print()
        elif choice == "2":
            run_process_scan()
            console.input("  [dim]Press Enter to return to the menu...[/] ")
            console.print()
        elif choice == "3":
            run_full_sweep()
            console.input("  [dim]Press Enter to return to the menu...[/] ")
            console.print()
        else:
            console.print("  [red]Invalid option.[/] Please type 1, 2, 3, or q.\n")


if __name__ == "__main__":
    main()