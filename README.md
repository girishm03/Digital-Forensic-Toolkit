<div align="center">

# 🛡️ Aegis Forensics Suite (AFT)

### *Defensive Digital Forensics & Incident Response (DFIR) Command Platform*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-8%20Passed%20(100%25)-10B981?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/License-MIT-00FFC8?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0EA5E9?style=for-the-badge)](https://github.com/)

<p align="center">
  <b>A full-stack, enterprise-grade digital forensics examination platform featuring an animated Cyber Command Center Web HUD, interactive radar telemetry, deep artifact triage engines, and a unified CLI.</b>
</p>

[Key Features](#-key-features) •
[Quickstart](#-quickstart) •
[Web Command Center](#-web-command-center-walkthrough) •
[CLI Reference](#-command-line-interface-cli) •
[MITRE ATT&CK Matrix](#-mitre-attck-correlation) •
[Testing](#-automated-tests) •
[LinkedIn Showcase Guide](#-linkedin-post--showcase-guide)

---

</div>

## 📌 Executive Summary

**Aegis Forensics Toolkit** bridges the gap between low-level forensic reverse engineering and intuitive incident response workflows. Built with an asynchronous Python backend and a futuristic glassmorphic UI, Aegis empowers SOC analysts, forensic examiners, and security engineers to acquire, dissect, and correlate volatile and non-volatile digital evidence rapidly.

Whether investigating ransomware intrusions, disguised trojans, or volatile host state, Aegis guarantees evidentiary integrity aligned with **ISO/IEC 27037** standards.

---

## ⚡ Key Features

| Forensic Domain | Capabilities |
| :--- | :--- |
| **🔒 Evidence Vault & CoC** | Cryptographic multi-hashing (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`), Shannon entropy calculation, automated vault intake with baseline locking, and 1-click tamper audits with immutable Chain of Custody logging. |
| **✂️ Raw File Carver** | Deep binary file carving from raw memory dumps, crash images, and unallocated disk sectors. Recovers embedded `JPEG`, `PNG`, `PDF`, and `ZIP` files with byte offset tracking, integrity hashes, and instant visual thumbnails. |
| **🕵️ File & Magic Byte Analysis** | Raw header byte inspection against canonical signatures. Automatically flags **Extension Spoofing** (e.g. executable PE payload disguised as `.png` or `.pdf`), extracts EXIF metadata with GPS coordinates (linked to Google Maps), and regex scans for IOCs (IPv4, URLs, emails, Base64). |
| **⚙️ Windows PE Executable Triage** | Dissects PE32/PE32+ binaries (`.exe`, `.dll`, `.sys`). Analyzes compile timestamps, section packing anomalies (UPX/Themida indicators), import tables, and flags high-risk API injection patterns (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`). Calculates an automated Threat Score ($0-100$). |
| **📋 Windows Event Logs (.evtx)** | Fast EVTX parsing with automated security triage for Logon (`4624`), Failed Logon (`4625`), Process Creation (`4688`), Service Installed (`7045`), and Security Audit Log Cleared (`1102`/`104` anti-forensic tampering alerts). |
| **🌐 Browser Artifact Forensics** | Offline and live artifact parsing for Chromium (Chrome, Edge, Brave, Opera) and Mozilla Firefox SQLite databases—retrieving URL navigation history, file downloads, timestamps, and search queries. |
| **💻 Live Volatile Host Triage** | Inspects active running processes with masquerading heuristics (system binaries outside System32, temp directory executions, evasion command lines), maps active TCP/UDP sockets to PIDs, and enumerates registry `Run`/`RunOnce` persistence keys. |
| **📡 Network PCAP Forensics** | Packet capture parsing via `dpkt`, flow conversation tracking, protocol breakdown, DNS query profiling with DGA (Domain Generation Algorithm) entropy alerts, plaintext HTTP inspection, and TLS Client Hello SNI extraction. |
| **⏱️ Supertimeline & Alerts** | Multi-source chronological correlation (File MACB timestamps, Event Logs, Browser History, Network Flows) with heuristic anomaly detectors (brute-force sequences, log clearing, off-hours execution). |
| **🏛️ MITRE ATT&CK Matrix** | Correlates forensic findings to official MITRE enterprise tactics (Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Command & Control). |
| **🔎 Threat Intelligence Lookup** | Rapid reputation and attribution check for hashes, IP addresses (C2 detection), and domains with confidence scoring. |
| **📄 Court-Ready Reporting** | Generates official, court-admissible PDF reports with investigator signatures, evidence inventories, and tamper audit logs, alongside standalone interactive HTML reports. |

---

## 🚀 Quickstart

### 1. Prerequisites
- **Python 3.10 or higher** installed.
- Git installed.

### 2. Clone the Repository
```bash
git clone https://github.com/girishm03/Digital-Forensic-Toolkit-.git
cd Digital-Forensic-Toolkit-
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch the Web Command Center
```bash
python main.py
```
Open **[http://127.0.0.1:8080](http://127.0.0.1:8080)** in your browser.

*(Alternatively, run via the CLI runner: `python cli.py server --port 8080`)*

---

## 🖥️ Web Command Center Walkthrough

The Aegis Web GUI is crafted with a cyber-tactical aesthetic:
- **Aegis Shield HUD**: Animated dual-ring gyro-shield emblem indicating defensive readiness.
- **Sentry Radar**: Live HTML5 Canvas sweeping radar with threat blip simulation.
- **DEFCON Status Ticker**: Real-time threat banner (`DEFCON 5: NORMAL` $\rightarrow$ `DEFCON 1: CRITICAL BREACH`) dynamically updating upon threat detection.
- **CRT Scanline Overlay**: Toggleable retro-tactical scanline filter.
- **Tactical Audio Synthesizer**: Web Audio API sound generator delivering crisp sci-fi clicks and red-alert acoustic alarms on threat discovery (toggleable).
- **1-Click Synthetic Sample Testing**: Instant testing with pre-packaged evidence files (`suspicious_invoice.png`, `incident_capture.pcap`, `corrupted_ram_dump.raw`).

---

## 💻 Command Line Interface (CLI)

Aegis includes a standalone CLI engine:

```bash
# Display help and available commands
python cli.py --help

# 1. Cryptographic Hashing & Entropy Calculation
python cli.py hash aegis_forensics/samples/suspicious_invoice.png

# 2. Evidence Baseline Integrity Verification
python cli.py verify <file> --hash <expected_sha256> --algo sha256

# 3. Magic Byte & Extension Spoofing Analysis
python cli.py analyze aegis_forensics/samples/suspicious_invoice.png

# 4. Forensic File Carving from Raw Dumps
python cli.py carve aegis_forensics/samples/corrupted_ram_dump.raw

# 5. Windows PE Executable Analysis
python cli.py pe C:\Windows\System32\cmd.exe

# 6. Windows Event Log (.evtx) Triage
python cli.py evtx Security.evtx --limit 1000

# 7. PCAP Network Packet Capture Inspection
python cli.py pcap aegis_forensics/samples/incident_capture.pcap

# 8. Threat Intelligence Indicator Lookup
python cli.py intel 104.28.19.44
python cli.py intel 6a6082630da7dd5ea17926d83f9f2de5

# 9. Live Host Volatile Triage
python cli.py triage

# 10. Case Vault & Evidence Management
python cli.py case create --id CASE-2026-001 --title "Workstation Intrusion" --investigator "Analyst"
python cli.py case list
python cli.py case add-evidence --case-id CASE-2026-001 --file evidence.bin --label "Disk Segment" --investigator "Analyst"
```

---

## 🏛️ MITRE ATT&CK Correlation

Aegis correlates multi-source artifacts to the **MITRE ATT&CK Matrix**:

| Technique ID | Technique Name | Tactic | Forensic Signal |
| :--- | :--- | :--- | :--- |
| **T1070.001** | Clear Windows Event Logs | Defense Evasion | EVTX Event ID `1102` / `104` |
| **T1110** | Brute Force | Credential Access | EVTX Event ID `4625` clustering |
| **T1055** | Process Injection | Defense Evasion / PrivEsc | `VirtualAllocEx`, `WriteProcessMemory` in PE imports |
| **T1036.005** | Extension Spoofing | Defense Evasion | Header magic bytes mismatching file extension |
| **T1027** | Obfuscated/Packed Payloads | Defense Evasion | PE section entropy $> 7.1$ or high virtual/raw size delta |
| **T1547.001** | Registry Run Keys | Persistence | Windows `HKLM`/`HKCU` `Run` keys enumerated |
| **T1543.003** | Windows Service | Persistence | EVTX Event ID `7045` (Service Installed) |
| **T1568.002** | Domain Generation Algorithm | Command and Control | DNS query Shannon entropy $> 4.2$ |

---

## 📂 Project Structure

```
Digital Forensics Toolkit/
├── aegis_forensics/
│   ├── core/
│   │   ├── hashing.py           # Multi-hash generation & cryptographic baseline audits
│   │   ├── case_manager.py      # ISO/IEC 27037 Case Vault & immutable custody logs
│   │   └── reporter.py          # Court-admissible PDF & standalone HTML reports
│   ├── modules/
│   │   ├── file_analyzer.py     # Magic bytes, EXIF/GPS, entropy profile, hex dump, IOCs
│   │   ├── carver.py            # Raw binary file carver (JPEG, PNG, PDF, ZIP)
│   │   ├── pe_analyzer.py       # PE32/PE32+ executable header & injection API triage
│   │   ├── evtx_analyzer.py     # Windows Event Log (.evtx) parser & threat triage
│   │   ├── browser_analyzer.py  # Chromium & Firefox SQLite history/downloads parser
│   │   ├── live_triage.py       # Volatile memory triage: process tree, sockets, registry
│   │   ├── pcap_analyzer.py     # PCAP packet capture parser (dpkt), DNS DGA, TLS SNI
│   │   ├── timeline.py          # Unified supertimeline & attack sequence correlator
│   │   ├── mitre_mapper.py      # Enterprise MITRE ATT&CK TTP mapping engine
│   │   └── threat_intel.py      # IOC reputation scoring & threat actor attribution
│   ├── api/
│   │   └── routes.py            # FastAPI REST & WebSocket endpoints
│   ├── web/
│   │   ├── static/
│   │   │   ├── css/style.css    # Cyberpunk/Glassmorphic tactical design system
│   │   │   └── js/app.js        # Dynamic charts, radar, audio synthesizer, async triage
│   │   └── templates/
│   │       └── index.html       # Single-Page Command Center Web GUI
│   ├── samples/                 # Synthetic evidence files for 1-click test driving
│   └── cli.py                   # Rich CLI engine
├── tests/
│   └── test_toolkit.py          # Automated pytest suite (8/8 test suites passing)
├── cases/                       # Local evidence storage vault & chain-of-custody audits
├── main.py                      # FastAPI web server entrypoint
├── cli.py                       # Root CLI runner shortcut
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation
```

---

## 🧪 Automated Tests

Run the full automated pytest suite:

```bash
python -m pytest tests/test_toolkit.py -v
```

**Test Coverage:**
- Cryptographic Hashing & Tamper Detection
- Case Vault & Chain of Custody Lifecycle
- Magic Byte Verification & Extension Spoofing
- PCAP Packet Parsing & Flow Reconstruction
- Supertimeline & Anomaly Sequence Detection
- Raw Binary File Carving
- MITRE ATT&CK Mapping
- Threat Intelligence Lookup

---

## 📸 LinkedIn Post & Showcase Guide

To maximize engagement on LinkedIn and attract cybersecurity enthusiasts, recruiters, and SOC managers, follow this blueprint:

### 1. Which Screenshots to Take (5 High-Impact Visuals)

1. **Screenshot 1: The Command Center (The Hero Image)**
   - *Tab*: **Command Center**
   - *What to capture*: Full screen showing the animated Aegis Shield emblem, the live sweeping radar canvas, DEFCON status ticker, physical RAM/CPU gauges, and the registered cases table.
   - *Why*: Instantly stops the scroll with its dark, sleek, cyberpunk aesthetic.

2. **Screenshot 2: Extension Spoofing & Interactive Hex Viewer**
   - *Tab*: **File & Magic Bytes** (Load `suspicious_invoice.png`)
   - *What to capture*: The red warning banner (`CRITICAL SPOOFING WARNING: File has extension .png, but magic bytes identify it as Windows PE Executable`), the chunked entropy chart, and the raw hex viewer.
   - *Why*: Demonstrates real-world defense against disguised phishing and malware payloads.

3. **Screenshot 3: Raw Memory File Carving in Action**
   - *Tab*: **File Carver** (Load `corrupted_ram_dump.raw`)
   - *What to capture*: The grid showing carved JPEG and PNG images extracted from unallocated memory with visual thumbnails, byte offsets, and SHA-256 hashes.
   - *Why*: Shows deep technical capability (carving files from raw binary).

4. **Screenshot 4: MITRE ATT&CK Matrix & TTP Navigator**
   - *Tab*: **MITRE ATT&CK Matrix**
   - *What to capture*: The tactics breakdown bar (`Defense Evasion: 4`, `Credential Access: 2`) and technique cards (`T1070.001 Clear Event Logs`, `T1055 Process Injection`, `T1036 Masquerading`).
   - *Why*: Enterprise security teams and recruiters look for grounding in the MITRE ATT&CK framework.

5. **Screenshot 5: Official Court-Admissible PDF Report**
   - *Action*: Click **Export PDF** on any case
   - *What to capture*: The generated PDF report opened in a viewer showing the formal case header, cryptographic evidence inventory table with SHA-256 baseline hashes, and the investigator declaration sign-off.
   - *Why*: Proves professionalism and ISO/IEC 27037 compliance.

---

### 2. Sample LinkedIn Post Caption Template

```markdown
🛡️ Super excited to share my latest cybersecurity project: Aegis Forensics Toolkit (AFT)!

As modern cyber threats become more stealthy—from disguised payloads to unallocated memory injection—I wanted to build an all-in-one Defensive Digital Forensics & Incident Response (DFIR) platform that bridges low-level binary analysis with an intuitive, cyber-tactical Command Center.

Key capabilities engineered into Aegis:
🔹 Evidence Vault & Chain of Custody (ISO/IEC 27037 compliant hashing & tamper auditing)
🔹 Raw Binary File Carver (Extracts embedded JPEGs, PNGs, PDFs, and ZIPs from memory dumps)
🔹 PE Binary Deep Dive (Section packing entropy, compile timestamps, and injection API triage)
🔹 Windows Event Log (.evtx) Triage (Detects 4625 brute-force & 1102 audit log clears)
🔹 Network PCAP Forensics (DNS DGA detection, TLS SNI extraction, and flow mapping)
🔹 MITRE ATT&CK Matrix Navigator (Automated enterprise TTP correlation)
🔹 Court-Admissible PDF & HTML Reporting (Complete with cryptographic baselines & sign-off)
🔹 Interactive Web HUD with live radar telemetry, DEFCON status ticker, and Web Audio synthesis!

Built with: Python, FastAPI, dpkt, pefile, python-evtx, ReportLab, and modern CSS/JS.

Check out the GitHub repository and let me know your thoughts:
🔗 https://github.com/girishm03/Digital-Forensic-Toolkit-

#Cybersecurity #DigitalForensics #DFIR #IncidentResponse #Python #InfoSec #ThreatHunting #MITREATTACK #SOCAnalyst #MalwareAnalysis #BlueTeam
```

---

## ⚖️ Legal & Ethical Disclaimer

**Aegis Forensics Toolkit** is developed solely for **defensive digital forensics, authorized incident response, cybersecurity research, and educational purposes**. Always ensure appropriate legal authorization before acquiring, analyzing, or handling forensic artifacts from any system or network.

---

<div align="center">
  <b>Built with 🛡️ by Cybersecurity Engineers for Blue Teams Worldwide.</b>
</div>
