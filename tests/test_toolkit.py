import os
import shutil
import tempfile
import pytest
from aegis_forensics.core.hashing import calculate_hashes, verify_file_integrity
from aegis_forensics.core.case_manager import CaseManager
from aegis_forensics.core.reporter import generate_pdf_report, generate_html_report
from aegis_forensics.modules.file_analyzer import (
    analyze_file_header, calculate_chunked_entropy, extract_strings_and_iocs, generate_hex_dump
)
from aegis_forensics.modules.timeline import SuperTimeline
from aegis_forensics.modules.pcap_analyzer import analyze_pcap

def test_hashing_and_verification():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("Aegis Digital Forensics Evidence Baseline Test Content")
        f_path = f.name

    try:
        hashes = calculate_hashes(f_path)
        assert "md5" in hashes
        assert "sha256" in hashes
        assert len(hashes["sha256"]) == 64
        assert hashes["entropy"] > 0

        # Verify intact
        v1 = verify_file_integrity(f_path, hashes["sha256"], "sha256")
        assert v1["is_intact"] is True

        # Verify tampered
        v2 = verify_file_integrity(f_path, "0" * 64, "sha256")
        assert v2["is_intact"] is False
    finally:
        if os.path.exists(f_path):
            os.remove(f_path)

def test_case_manager_and_chain_of_custody():
    test_dir = tempfile.mkdtemp(prefix="aegis_case_test_")
    mgr = CaseManager(base_dir=test_dir)

    try:
        # Create case
        c = mgr.create_case(
            case_id="TEST-CASE-01",
            title="Intrusion Investigation",
            investigator="Examiner Smith",
            description="Testing case vault creation"
        )
        assert c["case_id"] == "TEST-CASE-01"
        assert len(c["chain_of_custody"]) == 1

        # Ingest evidence
        ev_file = os.path.join(test_dir, "evidence_raw.bin")
        with open(ev_file, "wb") as f:
            f.write(b"CONFIDENTIAL FORENSIC EVIDENCE DATA BYTES" * 20)

        ev = mgr.add_evidence(
            case_id="TEST-CASE-01",
            source_file_path=ev_file,
            evidence_label="Drive Dump Segment",
            investigator="Examiner Smith"
        )
        assert ev["evidence_id"].startswith("EV-")
        assert os.path.exists(ev["stored_path"])

        # Audit
        audit = mgr.verify_case_evidence("TEST-CASE-01", investigator="Examiner Smith")
        assert len(audit) == 1
        assert audit[0]["is_intact"] is True

        # Verify report generation
        pdf_out = os.path.join(test_dir, "report.pdf")
        html_out = os.path.join(test_dir, "report.html")
        generate_pdf_report(c, pdf_out)
        generate_html_report(c, html_out)
        assert os.path.exists(pdf_out)
        assert os.path.exists(html_out)
        assert os.path.getsize(pdf_out) > 500
        assert os.path.getsize(html_out) > 500

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

def test_file_analyzer_magic_and_spoofing():
    # Create fake PNG that actually contains PE MZ header
    with tempfile.NamedTemporaryFile("wb", suffix=".png", delete=False) as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00" + b"https://c2-malicious.com/gate 192.168.1.99" + b"\x00" * 64)
        f_path = f.name

    try:
        header = analyze_file_header(f_path)
        assert header["is_spoofed"] is True
        assert "Executable" in header["detected_type"]

        entropy = calculate_chunked_entropy(f_path, num_chunks=4)
        assert len(entropy) > 0

        iocs = extract_strings_and_iocs(f_path)
        assert "192.168.1.99" in iocs["iocs"]["ips"]
        assert any("c2-malicious.com" in u for u in iocs["iocs"]["urls"])

        hex_rows = generate_hex_dump(f_path, offset=0, length=32)
        assert len(hex_rows) == 2
        assert hex_rows[0]["offset"] == "00000000"
    finally:
        if os.path.exists(f_path):
            os.remove(f_path)

def test_pcap_analyzer():
    sample_pcap = r"f:\Cyber Security Projects\Digital Forensics Toolkit\aegis_forensics\samples\incident_capture.pcap"
    if os.path.exists(sample_pcap):
        res = analyze_pcap(sample_pcap)
        assert res["total_packets"] >= 3
        assert "UDP" in res["protocol_breakdown"]
        assert len(res["dns_queries"]) >= 2
        assert len(res["http_requests"]) >= 1

def test_supertimeline_and_anomalies():
    tl = SuperTimeline()
    tl.add_event("2026-09-27T02:15:00Z", "EventLog", "Failed Logon", "Bad password", "Medium", {"TargetUserName": "admin"})
    tl.add_event("2026-09-27T02:15:01Z", "EventLog", "Failed Logon", "Bad password", "Medium", {"TargetUserName": "admin"})
    tl.add_event("2026-09-27T02:15:02Z", "EventLog", "Failed Logon", "Bad password", "Medium", {"TargetUserName": "admin"})
    tl.add_event("2026-09-27T02:15:03Z", "EventLog", "Successful Logon", "Logon success", "Low", {"TargetUserName": "admin"})
    tl.add_event("2026-09-27T02:16:00Z", "EventLog", "Log Cleared", "Security audit log wiped", "Critical")

    data = tl.build_timeline()
    assert data["total_events"] == 5
    assert data["anomalies_count"] >= 2
    types = [a["threat_type"] for a in data["anomalies_detected"]]
    assert any("BRUTE FORCE" in t for t in types)
    assert any("ANTI-FORENSICS" in t for t in types)

def test_file_carver():
    from aegis_forensics.modules.carver import carve_embedded_files
    # Create synthetic binary containing an embedded JPEG inside junk data
    jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00" + b"\x00" * 32 + b"\xFF\xD9"
    raw_blob = b"Random Junk Memory Segment 0x1234" + jpeg_header + b"More Trailing Heap Garbage"

    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(raw_blob)
        temp_name = f.name

    try:
        results = carve_embedded_files(temp_name)
        assert results["carved_count"] >= 1
        carved = results["carved_files"][0]
        assert carved["extension"] == "jpg"
        assert carved["size_bytes"] == len(jpeg_header)
        assert carved["preview_b64"] is not None
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)

def test_mitre_mapping():
    from aegis_forensics.modules.mitre_mapper import map_forensic_evidence_to_mitre
    sample_findings = [
        {"description": "Audit log was cleared (Event 1102)", "severity": "Critical"},
        {"description": "Brute force failed logons detected on admin (Event 4625)", "severity": "High"},
        {"description": "Process injection VirtualAllocEx detected", "severity": "High"}
    ]
    mapping = map_forensic_evidence_to_mitre(sample_findings)
    assert mapping["total_techniques_mapped"] >= 3
    tactics = mapping["tactics_summary"]
    assert tactics["Defense Evasion"] >= 1
    assert tactics["Credential Access"] >= 1

def test_threat_intel():
    from aegis_forensics.modules.threat_intel import lookup_indicator
    # Test known malware hash
    r_hash = lookup_indicator("6a6082630da7dd5ea17926d83f9f2de5")
    assert r_hash["is_known_threat"] is True
    assert r_hash["confidence_score"] > 80

    # Test C2 IP
    r_ip = lookup_indicator("104.28.19.44")
    assert r_ip["is_known_threat"] is True
    assert "Cobalt Strike" in r_ip["threat_family"]

    # Test DGA Domain
    r_domain = lookup_indicator("x8f9a2b7k9q3z1p8.malwaredomain.cc")
    assert r_domain["is_known_threat"] is True
    assert r_domain["confidence_score"] >= 80
