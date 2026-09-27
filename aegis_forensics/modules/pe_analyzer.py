import datetime
import math
from typing import Dict, Any, List, Optional
import pefile

SUSPICIOUS_APIS = {
    "Process Injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext", "RtlCreateUserThread"],
    "Memory Manipulation": ["VirtualProtect", "VirtualProtectEx", "VirtualAlloc", "MapViewOfFile"],
    "Anti-Debugging / Evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"],
    "Persistence & Service": ["CreateServiceA", "CreateServiceW", "StartServiceCtrlDispatcher", "RegSetValueExA", "RegSetValueExW"],
    "Network & Exfiltration": ["InternetOpenA", "InternetOpenW", "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW", "WSAStartup", "connect", "send"],
    "Keylogging & Spyware": ["GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW", "GetForegroundWindow", "BitBlt"],
    "Process Execution": ["WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"]
}

def analyze_pe(file_path: str) -> Dict[str, Any]:
    """
    Forensic PE header analyzer for Windows executables, DLLs, and drivers.
    """
    try:
        pe = pefile.PE(file_path, fast_load=False)
    except pefile.PEFormatError:
        return {"is_pe": False, "error": "Not a valid Windows Portable Executable (PE) binary."}
    except Exception as e:
        return {"is_pe": False, "error": str(e)}

    # Headers
    is_64bit = pe.FILE_HEADER.Machine == 0x8664
    machine_type = "x64 (AMD64)" if is_64bit else "x86 (i386)" if pe.FILE_HEADER.Machine == 0x14C else f"0x{pe.FILE_HEADER.Machine:X}"
    
    timestamp = pe.FILE_HEADER.TimeDateStamp
    try:
        compile_date = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        compile_date = f"Invalid/Spoofed ({timestamp})"

    subsystem_code = pe.OPTIONAL_HEADER.Subsystem
    subsystems = {1: "Native / Driver", 2: "Windows GUI", 3: "Windows CUI (Console)", 7: "POSIX CUI"}
    subsystem = subsystems.get(subsystem_code, f"Other ({subsystem_code})")

    # Sections
    sections = []
    has_packed_sections = False
    for section in pe.sections:
        sec_name = section.Name.decode("ascii", errors="ignore").strip("\x00")
        entropy = section.get_entropy()
        raw_size = section.SizeOfRawData
        virt_size = section.Misc_VirtualSize
        
        # Check suspicious characteristics
        is_high_entropy = entropy > 7.1
        # Virtual size significantly larger than raw size indicates unpacking into memory
        is_size_anomalous = virt_size > (raw_size * 4) and raw_size > 0
        if is_high_entropy or is_size_anomalous or sec_name in ["UPX0", "UPX1", ".aspack", ".themida"]:
            has_packed_sections = True

        sections.append({
            "name": sec_name,
            "virtual_address": f"0x{section.VirtualAddress:08X}",
            "virtual_size": virt_size,
            "raw_size": raw_size,
            "entropy": round(entropy, 3),
            "is_packed": is_high_entropy or is_size_anomalous,
            "characteristics": f"0x{section.Characteristics:08X}"
        })

    # Imports & Suspicious API scan
    imported_dlls = []
    suspicious_findings = []
    
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("ascii", errors="ignore")
                    funcs.append(func_name)
                    # Check suspicious APIs
                    for category, target_apis in SUSPICIOUS_APIS.items():
                        if func_name in target_apis:
                            suspicious_findings.append({
                                "category": category,
                                "api": func_name,
                                "dll": dll_name
                            })
                elif imp.ordinal:
                    funcs.append(f"Ordinal#{imp.ordinal}")
            imported_dlls.append({
                "dll": dll_name,
                "function_count": len(funcs),
                "functions": funcs[:30]
            })

    # Exports
    exported_funcs = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exported_funcs.append(exp.name.decode("ascii", errors="ignore"))

    # Security Directory (Authenticode)
    has_signature = False
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        has_signature = (sec_dir.VirtualAddress > 0 and sec_dir.Size > 0)

    # Compute Threat Score (0 - 100)
    threat_score = 0
    if has_packed_sections:
        threat_score += 35
    if len(suspicious_findings) > 0:
        threat_score += min(45, len(suspicious_findings) * 8)
    if not has_signature:
        threat_score += 10
    if timestamp == 0 or timestamp > 2000000000:
        threat_score += 10

    pe.close()

    return {
        "is_pe": True,
        "architecture": machine_type,
        "compile_timestamp": compile_date,
        "entry_point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}",
        "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}",
        "subsystem": subsystem,
        "has_signature": has_signature,
        "has_packed_sections": has_packed_sections,
        "sections": sections,
        "imported_dlls_count": len(imported_dlls),
        "imported_dlls": imported_dlls,
        "suspicious_apis": suspicious_findings,
        "exported_functions": exported_funcs[:50],
        "threat_score": min(100, threat_score),
        "assessment": "High Risk / Likely Malicious" if threat_score >= 60 else "Suspicious / Requires Review" if threat_score >= 30 else "Normal / Low Risk"
    }
