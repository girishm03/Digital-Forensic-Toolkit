import os
import sys
import psutil
import datetime
import socket
import re
from typing import Dict, Any, List, Optional

SUSPICIOUS_PATHS = [
    r"appdata\local\temp",
    r"windows\temp",
    r"users\public",
    r"perflogs",
    r"c:\programdata",
    r"/tmp",
    r"/var/tmp",
    r"/dev/shm"
]

SUSPICIOUS_PORTS = [4444, 1337, 6667, 8888, 9001, 31337, 5555, 7777]

def get_system_summary() -> Dict[str, Any]:
    """Get core live system hardware and OS environment summary."""
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time(), tz=datetime.timezone.utc).isoformat()
    net_if = psutil.net_if_addrs()
    ips = []
    for iface, addrs in net_if.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.append({"interface": iface, "ip": addr.address, "netmask": addr.netmask})

    mem = psutil.virtual_memory()

    return {
        "hostname": socket.gethostname(),
        "platform": sys.platform,
        "boot_time": boot_time,
        "cpu_count": psutil.cpu_count(logical=True),
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "memory_used_percent": mem.percent,
        "network_interfaces": ips
    }

def triage_processes() -> List[Dict[str, Any]]:
    """
    Triage running processes with forensic heuristics (masquerading, anomalous paths, suspicious parents).
    """
    processes = []
    for p in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'memory_percent', 'cpu_percent']):
        try:
            info = p.info
            pid = info['pid']
            name = info['name'] or ""
            exe = info['exe'] or ""
            cmdline = " ".join(info['cmdline']) if info['cmdline'] else ""
            username = info['username'] or ""
            created = datetime.datetime.fromtimestamp(info['create_time'], tz=datetime.timezone.utc).isoformat() if info['create_time'] else ""
            
            # Anomaly heuristics
            is_suspicious = False
            reasons = []

            exe_lower = exe.lower()
            for sp in SUSPICIOUS_PATHS:
                if sp in exe_lower:
                    is_suspicious = True
                    reasons.append(f"Running from high-risk temp/staging directory ({sp})")

            # Check masquerading system binaries
            system_binaries = ["svchost.exe", "lsass.exe", "services.exe", "smss.exe", "csrss.exe", "wininit.exe", "explorer.exe"]
            name_lower = name.lower()
            if name_lower in system_binaries:
                if "windows\\system32" not in exe_lower and "windows\\syswow64" not in exe_lower and exe_lower:
                    if name_lower == "explorer.exe" and "windows\\explorer.exe" in exe_lower:
                        pass
                    else:
                        is_suspicious = True
                        reasons.append(f"System binary spoofing / masquerade: {name} not in System32 ({exe})")

            # Command line anomalies
            if any(term in cmdline.lower() for term in ["-enc ", "-encodedcommand", "downloadstring", "iex", "bypass", "wscript.shell", "bitsadmin", "certutil -urlcache"]):
                is_suspicious = True
                reasons.append("Command line contains obfuscated or evasion parameters")

            processes.append({
                "pid": pid,
                "ppid": info['ppid'],
                "name": name,
                "exe": exe,
                "cmdline": cmdline[:250],
                "username": username,
                "created_time": created,
                "memory_percent": round(info['memory_percent'] or 0, 2),
                "cpu_percent": round(info['cpu_percent'] or 0, 2),
                "is_suspicious": is_suspicious,
                "reasons": reasons
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return sorted(processes, key=lambda x: (not x["is_suspicious"], x["name"].lower()))

def triage_network_connections() -> List[Dict[str, Any]]:
    """
    Forensic capture of live network sockets, remote endpoints, and associated PIDs.
    """
    connections = []
    pid_map = {}
    for p in psutil.process_iter(['pid', 'name']):
        try:
            pid_map[p.info['pid']] = p.info['name']
        except Exception:
            pass

    try:
        raw_conns = psutil.net_connections(kind='inet')
    except Exception:
        raw_conns = []

    for conn in raw_conns:
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else None
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            status = conn.status
            proc_name = pid_map.get(conn.pid, "Unknown")

            is_suspicious = False
            reasons = []
            if rport in SUSPICIOUS_PORTS:
                is_suspicious = True
                reasons.append(f"Connection to known threat/malware port ({rport})")

            connections.append({
                "proto": proto,
                "local_address": laddr,
                "remote_address": raddr,
                "remote_port": rport,
                "status": status,
                "pid": conn.pid,
                "process_name": proc_name,
                "is_suspicious": is_suspicious,
                "reasons": reasons
            })
        except Exception:
            continue

    return sorted(connections, key=lambda x: (not x["is_suspicious"], x["proto"]))

def triage_persistence_hooks() -> Dict[str, Any]:
    """
    Inspect common persistence mechanisms: Windows Registry Run keys, Services.
    """
    results = {
        "registry_run_keys": [],
        "active_services": []
    }

    # Registry Run keys on Windows
    if sys.platform == "win32":
        try:
            import winreg
            hives = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run")
            ]
            for hive, subkey, label in hives:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                        idx = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(key, idx)
                                results["registry_run_keys"].append({
                                    "location": label,
                                    "name": name,
                                    "command": str(val)
                                })
                                idx += 1
                            except OSError:
                                break
                except Exception:
                    pass
        except Exception:
            pass

    # Windows Services (psutil)
    if hasattr(psutil, "win_service_iter"):
        for svc in psutil.win_service_iter():
            try:
                s_info = svc.as_dict()
                if s_info.get("status") == "running" or s_info.get("start_type") == "automatic":
                    bin_path = s_info.get("binpath") or ""
                    results["active_services"].append({
                        "name": s_info.get("name"),
                        "display_name": s_info.get("display_name"),
                        "status": s_info.get("status"),
                        "start_type": s_info.get("start_type"),
                        "bin_path": bin_path
                    })
            except Exception:
                continue

    return results

def scan_process_memory(pid: int, pattern: str, max_matches: int = 50) -> Dict[str, Any]:
    """
    Perform volatile memory string/regex scanning on a specific live process.
    """
    if sys.platform != "win32":
        return {"error": "Process memory reading currently supported on Windows."}

    # On Windows, read memory regions using ctypes or VirtualQueryEx if permitted
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        kernel32 = ctypes.windll.kernel32
        h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            return {"error": f"Unable to open process PID {pid} (Access Denied or Process Terminated). Run with Administrator privileges."}

        regex = re.compile(pattern.encode("utf-8", errors="ignore"), re.IGNORECASE)
        matches = []

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        MEM_COMMIT = 0x1000
        PAGE_NOACCESS = 0x01
        PAGE_GUARD = 0x100

        address = 0
        while kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS or mbi.Protect & PAGE_GUARD):
                size = min(mbi.RegionSize, 2 * 1024 * 1024)
                buf = ctypes.create_string_buffer(size)
                bytes_read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(h_proc, mbi.BaseAddress, buf, size, ctypes.byref(bytes_read)):
                    raw_data = buf.raw[:bytes_read.value]
                    for m in regex.finditer(raw_data):
                        offset = address + m.start()
                        matched_str = m.group(0).decode("ascii", errors="replace")
                        matches.append({
                            "address": f"0x{offset:016X}",
                            "match": matched_str
                        })
                        if len(matches) >= max_matches:
                            break
            if len(matches) >= max_matches:
                break
            address += mbi.RegionSize

        kernel32.CloseHandle(h_proc)

        return {
            "pid": pid,
            "pattern": pattern,
            "total_matches": len(matches),
            "matches": matches
        }

    except Exception as e:
        return {"error": f"Error scanning process memory: {str(e)}"}
