import json
from typing import Dict, Any, List, Optional

MITRE_TECHNIQUES = {
    "T1070.001": {
        "id": "T1070.001",
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide evidence of intrusion and cover tracks.",
        "url": "https://attack.mitre.org/techniques/T1070/001/"
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt authentication against accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade defenses and elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1055/"
    },
    "T1036": {
        "id": "T1036",
        "name": "Masquerading (Process Spoofing)",
        "tactic": "Defense Evasion",
        "description": "Adversaries may match or spoof legitimate system files or directories to evade detection.",
        "url": "https://attack.mitre.org/techniques/T1036/"
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Extension Spoofing & Right-to-Left Override",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disguise executables with deceptive file extensions like .png or .pdf.",
        "url": "https://attack.mitre.org/techniques/T1036/005/"
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding registry keys to Run/RunOnce hives.",
        "url": "https://attack.mitre.org/techniques/T1547/001/"
    },
    "T1543.003": {
        "id": "T1543.003",
        "name": "Windows Service Execution",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may install new Windows services to execute commands automatically.",
        "url": "https://attack.mitre.org/techniques/T1543/003/"
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell Script Execution",
        "tactic": "Execution",
        "description": "Adversaries may use PowerShell commands and scripts to execute malicious payloads.",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1568.002": {
        "id": "T1568.002",
        "name": "Domain Generation Algorithms (DGA)",
        "tactic": "Command and Control",
        "description": "Adversaries may use DGA to dynamically generate rendezvous domains for C2 communications.",
        "url": "https://attack.mitre.org/techniques/T1568/002/"
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated / Packed Binary Payloads",
        "tactic": "Defense Evasion",
        "description": "Adversaries may compress, pack, or encrypt payloads to evade signature detection.",
        "url": "https://attack.mitre.org/techniques/T1027/"
    }
}

DEFAULT_SAMPLE_EVIDENCE = [
    {"description": "Audit log was cleared (Event 1102 anti-forensics alert)", "event_type": "Log Cleared", "threat_type": "ANTI-FORENSICS"},
    {"description": "Brute force authentication sequence: multiple 4625 failed logons on admin", "event_type": "Failed Logon", "threat_type": "POTENTIAL BRUTE FORCE"},
    {"description": "Extension spoof detected: suspicious_invoice.png contains PE executable header", "event_type": "EXTENSION_SPOOFED", "threat_type": "EXTENSION SPOOF"},
    {"description": "Process injection APIs: VirtualAllocEx and WriteProcessMemory discovered in PE imports", "event_type": "PE_COMPILED", "threat_type": "PROCESS INJECTION"},
    {"description": "High entropy DGA domain query: x8f9a2b7k9q3z1p8.malwaredomain.cc", "event_type": "DNS_QUERY", "threat_type": "C2 DGA BEACON"}
]

def map_forensic_evidence_to_mitre(findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Correlates forensic findings to MITRE ATT&CK tactics, techniques, and matrix categories.
    Handles nested dicts and stringifies fields safely to prevent AttributeErrors.
    """
    mapped_techniques = {}
    tactics_summary = {
        "Initial Access": 0,
        "Execution": 0,
        "Persistence": 0,
        "Privilege Escalation": 0,
        "Defense Evasion": 0,
        "Credential Access": 0,
        "Discovery": 0,
        "Command and Control": 0,
        "Exfiltration": 0
    }

    # If no findings in active timeline, use default forensic demonstration baseline
    input_findings = findings if findings and len(findings) > 0 else DEFAULT_SAMPLE_EVIDENCE

    for f in input_findings:
        if not isinstance(f, dict):
            continue

        desc = str(f.get("description") or "")
        threat_type = str(f.get("threat_type") or "")
        ev_type = str(f.get("event_type") or f.get("type") or "")
        details_val = f.get("details", "")
        details_str = json.dumps(details_val) if isinstance(details_val, (dict, list)) else str(details_val)

        combined_text = f"{desc} {threat_type} {ev_type} {details_str}".lower()

        matched_ids = []

        if "cleared" in combined_text or "1102" in combined_text or "104" in combined_text:
            matched_ids.append("T1070.001")
        if "brute" in combined_text or "failed logon" in combined_text or "4625" in combined_text:
            matched_ids.append("T1110")
        if "injection" in combined_text or "virtualalloc" in combined_text or "writeprocessmemory" in combined_text:
            matched_ids.append("T1055")
        if "masquerad" in combined_text:
            matched_ids.append("T1036")
        if "extension" in combined_text or "spoof" in combined_text:
            matched_ids.append("T1036.005")
        if "run key" in combined_text or "hklm\\run" in combined_text or "hkcu\\run" in combined_text:
            matched_ids.append("T1547.001")
        if "service" in combined_text and ("installed" in combined_text or "7045" in combined_text):
            matched_ids.append("T1543.003")
        if "powershell" in combined_text or "4104" in combined_text:
            matched_ids.append("T1059.001")
        if "dga" in combined_text or "entropy" in combined_text and "domain" in combined_text:
            matched_ids.append("T1568.002")
        if "packed" in combined_text or "high entropy" in combined_text:
            matched_ids.append("T1027")

        for tid in matched_ids:
            if tid in MITRE_TECHNIQUES:
                tech = MITRE_TECHNIQUES[tid]
                if tid not in mapped_techniques:
                    mapped_techniques[tid] = {
                        **tech,
                        "detection_count": 0,
                        "evidence_samples": []
                    }
                mapped_techniques[tid]["detection_count"] += 1
                sample_text = desc if desc else (threat_type if threat_type else ev_type)
                if sample_text and sample_text not in mapped_techniques[tid]["evidence_samples"]:
                    mapped_techniques[tid]["evidence_samples"].append(sample_text)

                for tac in tactics_summary.keys():
                    if tac.lower() in tech["tactic"].lower():
                        tactics_summary[tac] += 1

    return {
        "total_techniques_mapped": len(mapped_techniques),
        "techniques": list(mapped_techniques.values()),
        "tactics_summary": tactics_summary,
        "threat_posture": "CRITICAL" if len(mapped_techniques) >= 4 else "ELEVATED" if len(mapped_techniques) >= 2 else "MONITORED",
        "is_baseline_demo": (findings is None or len(findings) == 0)
    }
