import sys
import os
import argparse
import json
from aegis_forensics.core.hashing import calculate_hashes, verify_file_integrity
from aegis_forensics.core.case_manager import CaseManager
from aegis_forensics.modules.file_analyzer import analyze_file_header, extract_strings_and_iocs, calculate_chunked_entropy
from aegis_forensics.modules.pe_analyzer import analyze_pe
from aegis_forensics.modules.evtx_analyzer import analyze_evtx
from aegis_forensics.modules.browser_analyzer import parse_browser_database, discover_installed_browsers
from aegis_forensics.modules.live_triage import get_system_summary, triage_processes, triage_network_connections, triage_persistence_hooks
from aegis_forensics.modules.pcap_analyzer import analyze_pcap
from aegis_forensics.modules.carver import carve_embedded_files
from aegis_forensics.modules.threat_intel import lookup_indicator

def print_banner():
    banner = r"""
    ========================================================================
     ___  ____ ____ _ ____    ____ ____ ____ ____ _  _ ____ _ ____ ____ 
     |__] |___ | __ | [__     |___ |  | |__/ |___ |\ | [__  | |    [__  
     |  ] |___ |__] | ___]    |    |__| |  \ |___ | \| ___] | |___ ___] 
    ========================================================================
       AEGIS DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) COMMAND SUITE     
    ========================================================================
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis Forensics Toolkit - Defensive Digital Forensics & Incident Response Suite"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available forensic commands")

    # Command: server
    p_server = subparsers.add_parser("server", help="Start the Web Command Center GUI")
    p_server.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    p_server.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")

    # Command: hash
    p_hash = subparsers.add_parser("hash", help="Calculate cryptographic hashes & entropy")
    p_hash.add_argument("file", help="Target evidence file path")

    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Verify evidence integrity against expected hash")
    p_verify.add_argument("file", help="Evidence file path")
    p_verify.add_argument("--hash", required=True, help="Expected baseline hash value")
    p_verify.add_argument("--algo", default="sha256", choices=["md5", "sha1", "sha256", "sha512"], help="Hash algorithm")

    # Command: analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze file magic bytes, headers, and IOCs")
    p_analyze.add_argument("file", help="File to examine")

    # Command: pe
    p_pe = subparsers.add_parser("pe", help="Analyze Windows PE binary headers, sections, and suspicious APIs")
    p_pe.add_argument("file", help="PE executable (.exe, .dll, .sys)")

    # Command: evtx
    p_evtx = subparsers.add_parser("evtx", help="Parse Windows Event Log (.evtx) for security threats")
    p_evtx.add_argument("file", help="Path to .evtx log file")
    p_evtx.add_argument("--limit", type=int, default=500, help="Maximum records to parse")

    # Command: pcap
    p_pcap = subparsers.add_parser("pcap", help="Parse PCAP network capture (DNS, HTTP, TLS SNI, flows)")
    p_pcap.add_argument("file", help="Path to .pcap or .pcapng file")

    # Command: browser
    p_browser = subparsers.add_parser("browser", help="Triage browser history and downloads")
    p_browser.add_argument("--file", help="Path to SQLite history database file")
    p_browser.add_argument("--discover", action="store_true", help="Auto-discover live browser profiles on host")

    # Command: carve
    p_carve = subparsers.add_parser("carve", help="Carve embedded JPEGs, PNGs, PDFs, and ZIPs from binary/disk images")
    p_carve.add_argument("file", help="Path to binary file or disk image to carve")

    # Command: intel
    p_intel = subparsers.add_parser("intel", help="Lookup Threat Intelligence reputation for an IOC")
    p_intel.add_argument("ioc", help="Hash (MD5/SHA256), IPv4 address, or domain name")

    # Command: triage
    p_triage = subparsers.add_parser("triage", help="Perform live volatile system triage")
    p_triage.add_argument("--all", action="store_true", help="Include processes, sockets, persistence")
    p_triage.add_argument("--suspicious-only", action="store_true", help="Filter for suspicious items only")

    # Command: case
    p_case = subparsers.add_parser("case", help="Forensic case and evidence management")
    case_subs = p_case.add_subparsers(dest="case_action")
    
    p_case_create = case_subs.add_parser("create", help="Create new case")
    p_case_create.add_argument("--id", required=True, help="Case identifier (e.g. CASE-2026-001)")
    p_case_create.add_argument("--title", required=True, help="Case title")
    p_case_create.add_argument("--investigator", required=True, help="Lead investigator name")

    p_case_list = case_subs.add_parser("list", help="List all active cases")

    p_case_add = case_subs.add_parser("add-evidence", help="Ingest evidence into case vault")
    p_case_add.add_argument("--case-id", required=True, help="Target case ID")
    p_case_add.add_argument("--file", required=True, help="Evidence file to ingest")
    p_case_add.add_argument("--label", required=True, help="Evidence descriptive label")
    p_case_add.add_argument("--investigator", required=True, help="Investigator name")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "server":
        print_banner()
        print(f"[*] Initializing Aegis Forensics Command Center...")
        print(f"[*] Web Interface: http://{args.host}:{args.port}")
        import uvicorn
        uvicorn.run("main:app", host=args.host, port=args.port, reload=False)

    elif args.command == "hash":
        hashes = calculate_hashes(args.file)
        print(f"\n[+] Forensic Hash Calculation: {hashes['file_name']}")
        print(f"    File Size: {hashes['size_human']} ({hashes['size_bytes']} bytes)")
        print(f"    MD5:     {hashes['md5']}")
        print(f"    SHA-1:   {hashes['sha1']}")
        print(f"    SHA-256: {hashes['sha256']}")
        print(f"    SHA-512: {hashes['sha512']}")
        print(f"    Shannon Entropy: {hashes['entropy']} / 8.0000 -> {hashes['entropy_assessment']}\n")

    elif args.command == "verify":
        res = verify_file_integrity(args.file, args.hash, algorithm=args.algo)
        print(f"\n[+] Integrity Verification for: {res['file_name']}")
        print(f"    Algorithm: {res['algorithm']}")
        print(f"    Expected:  {res['expected_hash']}")
        print(f"    Computed:  {res['computed_hash']}")
        print(f"    Status:    {res['status']}\n")

    elif args.command == "analyze":
        print(f"\n[+] Analyzing file: {args.file}")
        header = analyze_file_header(args.file)
        print(f"    Magic Hex:      {header['magic_hex']}")
        print(f"    Detected Type:  {header['detected_type']}")
        print(f"    Description:    {header['description']}")
        if header.get("is_spoofed"):
            print(f"    [!] {header['anomaly_warning']}")
        
        iocs = extract_strings_and_iocs(args.file)
        print(f"    Strings Found:  {iocs['total_strings_found']}")
        if iocs['iocs']['ips']:
            print(f"    [!] Found IPs:    {', '.join(iocs['iocs']['ips'][:10])}")
        if iocs['iocs']['urls']:
            print(f"    [!] Found URLs:   {', '.join(iocs['iocs']['urls'][:5])}")

    elif args.command == "pe":
        res = analyze_pe(args.file)
        if not res.get("is_pe"):
            print(f"[-] {res.get('error')}")
            return
        print(f"\n[+] PE Analysis: {args.file}")
        print(f"    Architecture:     {res['architecture']}")
        print(f"    Subsystem:        {res['subsystem']}")
        print(f"    Compile Time:     {res['compile_timestamp']}")
        print(f"    Threat Score:     {res['threat_score']}/100 -> {res['assessment']}")
        print(f"    Sections ({len(res['sections'])}):")
        for s in res['sections']:
            packed = " [PACKED/HIGH ENTROPY]" if s['is_packed'] else ""
            print(f"      - {s['name']:<10} Entropy: {s['entropy']:<5} RawSize: {s['raw_size']}{packed}")
        if res['suspicious_apis']:
            print(f"\n    [!] Suspicious APIs Detected ({len(res['suspicious_apis'])}):")
            for sa in res['suspicious_apis'][:15]:
                print(f"      * [{sa['category']}] {sa['api']} (from {sa['dll']})")

    elif args.command == "evtx":
        res = analyze_evtx(args.file, max_records=args.limit)
        if "error" in res:
            print(f"[-] {res['error']}")
            return
        print(f"\n[+] EVTX Log Triage: {res['file_name']}")
        print(f"    Total Records:    {res['total_records_analyzed']}")
        print(f"    Suspicious Events:{res['suspicious_events_count']}")
        print(f"    Failed Logons:    {res['failed_logons_count']}")
        if res['log_cleared_tamper_alerts']:
            print(f"    [CRITICAL] LOG CLEARED TAMPERING DETECTED: {len(res['log_cleared_tamper_alerts'])} events!")

    elif args.command == "pcap":
        res = analyze_pcap(args.file)
        if "error" in res:
            print(f"[-] {res['error']}")
            return
        print(f"\n[+] PCAP Capture Triage: {res['file_name']}")
        print(f"    Total Packets:   {res['total_packets']} ({res['total_bytes']} bytes)")
        print(f"    Protocols:       {json.dumps(res['protocol_breakdown'])}")
        print(f"    Top Flow:        {res['top_conversations'][0] if res['top_conversations'] else 'None'}")
        print(f"    DNS Queries:     {len(res['dns_queries'])}")
        print(f"    TLS SNI Records: {len(res['tls_sni_records'])}")

    elif args.command == "browser":
        if args.discover:
            browsers = discover_installed_browsers()
            print(f"\n[+] Discovered {len(browsers)} Live Browser Databases:")
            for b in browsers:
                print(f"    - {b['browser']}: {b['history_path']} ({b['size_bytes']} bytes)")
        elif args.file:
            res = parse_browser_database(args.file)
            print(f"\n[+] Browser Database: {res['database_file']} ({res['browser_family']})")
            print(f"    History Items:   {res['total_history_count']}")
            print(f"    Downloads:       {res['total_downloads_count']}")
            if res['history']:
                print(f"    Recent Visit:    {res['history'][0]['title']} ({res['history'][0]['url']})")

    elif args.command == "carve":
        res = carve_embedded_files(args.file)
        print(f"\n[+] File Carving: {res['source_file']}")
        print(f"    Scanned:     {res['total_scanned_bytes']} bytes")
        print(f"    Carved Files: {res['carved_count']}")
        for cf in res['carved_files']:
            print(f"      - [{cf['id']}] {cf['type']} @ {cf['start_offset_hex']} (Size: {cf['size_human']}, SHA256: {cf['sha256'][:16]}...)")

    elif args.command == "intel":
        res = lookup_indicator(args.ioc)
        print(f"\n[+] Threat Intelligence Lookup: {res['ioc']}")
        print(f"    Classification:  {res['classification']}")
        print(f"    Confidence:      {res['confidence_score']}%")
        print(f"    Threat Family:   {res['threat_family']}")
        print(f"    Attribution:     {res['actor_attribution']}")
        print(f"    Verdict:         {res['details']}")

    elif args.command == "triage":
        sys_info = get_system_summary()
        print(f"\n[+] Live Host: {sys_info['hostname']} ({sys_info['platform']})")
        print(f"    CPUs: {sys_info['cpu_count']}, Memory: {sys_info['memory_used_percent']}% used of {sys_info['memory_total_gb']} GB")
        
        procs = triage_processes()
        susp_procs = [p for p in procs if p['is_suspicious']]
        print(f"[+] Total Running Processes: {len(procs)} (Suspicious: {len(susp_procs)})")
        for p in susp_procs:
            print(f"    [!] PID {p['pid']} - {p['name']} ({', '.join(p['reasons'])})")

        conns = triage_network_connections()
        susp_conns = [c for c in conns if c['is_suspicious']]
        print(f"[+] Active Network Sockets: {len(conns)} (Suspicious: {len(susp_conns)})")
        for c in susp_conns:
            print(f"    [!] {c['proto']} {c['local_address']} -> {c['remote_address']} ({c['process_name']})")

    elif args.command == "case":
        mgr = CaseManager()
        if args.case_action == "create":
            c = mgr.create_case(case_id=args.id, title=args.title, investigator=args.investigator)
            print(f"[+] Created Case: {c['case_id']} - '{c['title']}'")
        elif args.case_action == "list":
            cases = mgr.list_cases()
            print(f"[+] Registered Cases ({len(cases)}):")
            for c in cases:
                print(f"    - [{c['case_id']}] {c['title']} | Investigator: {c['investigator']} | Evidence: {c['evidence_count']}")
        elif args.case_action == "add-evidence":
            ev = mgr.add_evidence(
                case_id=args.case_id,
                source_file_path=args.file,
                evidence_label=args.label,
                investigator=args.investigator
            )
            print(f"[+] Evidence Ingested: {ev['evidence_id']} ({ev['label']})")
            print(f"    SHA-256: {ev['sha256']}")

if __name__ == "__main__":
    main()
