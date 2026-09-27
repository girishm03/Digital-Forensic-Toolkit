import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import os
import re

CRITICAL_EVENT_IDS = {
    4624: ("Successful Logon", "Security", "Low"),
    4625: ("Failed Logon", "Security", "Medium"),
    4672: ("Special Privileges Assigned", "Security", "Low"),
    4688: ("Process Creation", "Security", "Low"),
    7045: ("New Service Installed", "System", "High"),
    1102: ("Security Log Cleared (Tampering Detected!)", "Security", "Critical"),
    104: ("Log Cleared", "System", "Critical"),
    4104: ("PowerShell Script Block Execution", "PowerShell", "Medium"),
    4720: ("User Account Created", "Security", "High"),
    4728: ("Member Added to Global Admin Group", "Security", "High"),
    4738: ("User Account Modified", "Security", "Medium"),
    7036: ("Service State Changed", "System", "Info")
}

def analyze_evtx(file_path: str, max_records: int = 1000) -> Dict[str, Any]:
    """
    Forensic Windows Event Log (.evtx) parser and security threat triage.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"EVTX file not found: {file_path}")

    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        return {"error": "python-evtx library is required to parse .evtx files."}

    parsed_records = []
    event_distribution = {}
    suspicious_events = []
    failed_logons = []
    powershell_scripts = []
    log_cleared_events = []
    process_creations = []

    count = 0
    try:
        with Evtx(file_path) as evtx:
            for record in evtx.records():
                count += 1
                if count > max_records:
                    break

                xml_str = record.xml()
                try:
                    # Strip namespace for simplified parsing
                    xml_clean = re.sub(r'xmlns="[^"]+"', '', xml_str)
                    root = ET.fromstring(xml_clean)

                    sys_elem = root.find("System")
                    if sys_elem is None:
                        continue

                    event_id_elem = sys_elem.find("EventID")
                    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

                    channel_elem = sys_elem.find("Channel")
                    channel = channel_elem.text if channel_elem is not None else "Unknown"

                    time_elem = sys_elem.find("TimeCreated")
                    timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""

                    computer_elem = sys_elem.find("Computer")
                    computer = computer_elem.text if computer_elem is not None else ""

                    # Extract EventData
                    data_dict = {}
                    data_elem = root.find("EventData")
                    if data_elem is not None:
                        for d in data_elem.findall("Data"):
                            name = d.get("Name")
                            if name:
                                data_dict[name] = d.text or ""
                            elif d.text:
                                data_dict[f"field_{len(data_dict)}"] = d.text

                    event_name, category, severity = CRITICAL_EVENT_IDS.get(
                        event_id, (f"Event ID {event_id}", channel, "Info")
                    )

                    event_distribution[event_id] = event_distribution.get(event_id, 0) + 1

                    record_summary = {
                        "record_id": record.record_num(),
                        "event_id": event_id,
                        "event_name": event_name,
                        "timestamp": timestamp,
                        "channel": channel,
                        "computer": computer,
                        "severity": severity,
                        "details": data_dict
                    }

                    parsed_records.append(record_summary)

                    # Categorize critical security patterns
                    if event_id in [1102, 104]:
                        log_cleared_events.append(record_summary)
                        suspicious_events.append(record_summary)
                    elif event_id == 4625:
                        failed_logons.append({
                            "timestamp": timestamp,
                            "user": data_dict.get("TargetUserName", "Unknown"),
                            "domain": data_dict.get("TargetDomainName", ""),
                            "source_ip": data_dict.get("IpAddress", "Unknown"),
                            "status": data_dict.get("Status", ""),
                            "sub_status": data_dict.get("SubStatus", "")
                        })
                        suspicious_events.append(record_summary)
                    elif event_id == 4104:
                        powershell_scripts.append({
                            "timestamp": timestamp,
                            "script_block": data_dict.get("ScriptBlockText", "")[:300]
                        })
                        suspicious_events.append(record_summary)
                    elif event_id == 4688:
                        process_creations.append({
                            "timestamp": timestamp,
                            "process_name": data_dict.get("NewProcessName", ""),
                            "command_line": data_dict.get("CommandLine", ""),
                            "parent_process": data_dict.get("ParentProcessName", ""),
                            "user": data_dict.get("TargetUserName", "")
                        })
                    elif event_id in [7045, 4720, 4728]:
                        suspicious_events.append(record_summary)

                except Exception:
                    continue

    except Exception as e:
        return {"error": f"Error parsing EVTX log: {str(e)}"}

    return {
        "file_name": os.path.basename(file_path),
        "total_records_analyzed": len(parsed_records),
        "event_distribution": event_distribution,
        "suspicious_events_count": len(suspicious_events),
        "suspicious_events": suspicious_events[:50],
        "failed_logons_count": len(failed_logons),
        "failed_logons": failed_logons[:50],
        "log_cleared_tamper_alerts": log_cleared_events,
        "powershell_executions": powershell_scripts[:30],
        "process_creations": process_creations[:50],
        "records_sample": parsed_records[:100]
    }
