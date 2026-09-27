from typing import Dict, Any, List, Optional

MITRE_TECHNIQUES = {
    "T1070.001": {
        "id": "T1070.001",
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide evidence of intrusion.",
        "url": "https://attack.mitre.org/techniques/T1070/001/"
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt authentication.",
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
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may match or spoof legitimate system files or directories to evade detection.",
        "url": "https://attack.mitre.org/techniques/T1036/"
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding registry keys to Run/RunOnce.",
        "url": "https://attack.mitre.org/techniques/T1547/001/"
    },
    "T1543.003": {
        "id": "T1543.003",
        "name": "Windows Service",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may install new Windows services to execute commands automatically.",
        "url": "https://attack.mitre.org/techniques/T1543/003/"
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell Script Execution",
        "tactic": "Execution",
        "description": "Adversaries may use PowerShell commands and scripts to execute code.",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1568.002": {
        "id": "T1568.002",
        "name": "Domain Generation Algorithms (DGA)",
        "tactic": "Command and Control",
        "description": "Adversaries may use DGA to dynamically generate rendezvous domains for C2.",
        "url": "https://attack.mitre.org/techniques/T1568/002/"
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated / Packed Binary Payloads",
        "tactic": "Defense Evasion",
        "description": "Adversaries may compress, pack, or encrypt payloads to evade signature detection.",
        "url": "https://attack.mitre.org/techniques/T1027/"
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Extension Spoofing & Right-to-Left Override",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disguise executables with deceptive file extensions like .png or .pdf.",
        "url": "https://attack.mitre.org/techniques/T1036/005/"
    }
}

def map_forensic_evidence_to_mitre(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlates forensic findings to MITRE ATT&CK tactics, techniques, and matrix categories.
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

    for f in findings:
        desc = (f.get("description") or f.get("details") or f.get("threat_type") or "").lower()
        ev_type = (f.get("event_type") or f.get("type") or "").lower()

        matched_ids = []

        if "cleared" in desc or "cleared" in ev_type or "1102" in desc:
            matched_ids.append("T1070.001")
        if "brute" in desc or "failed logon" in desc or "4625" in desc:
            matched_ids.append("T1110")
        if "injection" in desc or "virtualalloc" in desc or "writeprocessmemory" in desc:
            matched_ids.append("T1055")
        if "masquerad" in desc or "spoofing" in desc:
            matched_ids.append("T1036")
        if "run key" in desc or "hklm\\run" in desc or "hkcu\\run" in desc:
            matched_ids.append("T1547.001")
        if "service" in desc and ("installed" in desc or "7045" in desc):
            matched_ids.append("T1543.003")
        if "powershell" in desc or "script" in desc or "4104" in desc:
            matched_ids.append("T1059.001")
        if "dga" in desc or "entropy" in desc and "domain" in desc:
            matched_ids.append("T1568.002")
        if "packed" in desc or "high entropy" in desc:
            matched_ids.append("T1027")
        if "disguised" in desc or "extension" in desc and "spoof" in desc:
            matched_ids.append("T1036.005")

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
                mapped_techniques[tid]["evidence_samples"].append(f.get("description") or f.get("details") or str(f))

                for tac in tactics_summary.keys():
                    if tac.lower() in tech["tactic"].lower():
                        tactics_summary[tac] += 1

    return {
        "total_techniques_mapped": len(mapped_techniques),
        "techniques": list(mapped_techniques.values()),
        "tactics_summary": tactics_summary,
        "threat_posture": "CRITICAL" if len(mapped_techniques) >= 4 else "ELEVATED" if len(mapped_techniques) >= 2 else "MONITORED"
    }
