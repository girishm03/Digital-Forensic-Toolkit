import os
import shutil
import tempfile
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from aegis_forensics.core.hashing import calculate_hashes, verify_file_integrity
from aegis_forensics.core.case_manager import CaseManager
from aegis_forensics.core.reporter import generate_pdf_report, generate_html_report
from aegis_forensics.modules.file_analyzer import (
    analyze_file_header, extract_exif_metadata, generate_hex_dump,
    calculate_chunked_entropy, extract_strings_and_iocs
)
from aegis_forensics.modules.pe_analyzer import analyze_pe
from aegis_forensics.modules.evtx_analyzer import analyze_evtx
from aegis_forensics.modules.browser_analyzer import parse_browser_database, discover_installed_browsers
from aegis_forensics.modules.live_triage import (
    get_system_summary, triage_processes, triage_network_connections,
    triage_persistence_hooks, scan_process_memory
)
from aegis_forensics.modules.pcap_analyzer import analyze_pcap
from aegis_forensics.modules.timeline import SuperTimeline
from aegis_forensics.modules.carver import carve_embedded_files
from aegis_forensics.modules.mitre_mapper import map_forensic_evidence_to_mitre
from aegis_forensics.modules.threat_intel import lookup_indicator

router = APIRouter()
case_mgr = CaseManager()

# Global in-memory timeline store for active investigation session
active_timeline = SuperTimeline()

# Helper for temporary uploads
def save_upload_temp(file: UploadFile) -> str:
    temp_dir = tempfile.mkdtemp(prefix="aegis_upload_")
    file_path = os.path.join(temp_dir, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return file_path

# ==================== CASE & EVIDENCE ENDPOINTS ====================

@router.get("/cases")
def list_cases():
    return case_mgr.list_cases()

@router.post("/cases")
def create_case(
    case_id: str = Form(""),
    title: str = Form(...),
    investigator: str = Form(...),
    organization: str = Form("DFIR Unit"),
    description: str = Form(""),
    target_system: str = Form("Unknown Host")
):
    case = case_mgr.create_case(
        case_id=case_id,
        title=title,
        investigator=investigator,
        organization=organization,
        description=description,
        target_system=target_system
    )
    return case

@router.get("/cases/{case_id}")
def get_case_details(case_id: str):
    case = case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case

@router.post("/cases/{case_id}/evidence")
async def ingest_evidence(
    case_id: str,
    label: str = Form(...),
    investigator: str = Form(...),
    notes: str = Form(""),
    file: UploadFile = File(...)
):
    temp_path = save_upload_temp(file)
    try:
        evidence = case_mgr.add_evidence(
            case_id=case_id,
            source_file_path=temp_path,
            evidence_label=label,
            investigator=investigator,
            notes=notes,
            copy_to_vault=True
        )
        # Also ingest into active timeline
        active_timeline.ingest_file_macb(evidence["stored_path"], evidence)
        return evidence
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

@router.post("/cases/{case_id}/verify")
def verify_case(case_id: str, investigator: str = Query("Examiner")):
    return case_mgr.verify_case_evidence(case_id, investigator=investigator)

@router.get("/cases/{case_id}/report/pdf")
def get_pdf_report(case_id: str):
    case = case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    out_dir = os.path.join(case_mgr.base_dir, case_id, "reports")
    os.makedirs(out_dir, exist_ok=True)
    pdf_path = os.path.join(out_dir, f"{case_id}_Forensic_Report.pdf")

    timeline_data = active_timeline.build_timeline()
    generate_pdf_report(case, pdf_path, findings=timeline_data.get("anomalies_detected"))
    
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"{case_id}_Forensic_Report.pdf")

@router.get("/cases/{case_id}/report/html")
def get_html_report(case_id: str):
    case = case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    out_dir = os.path.join(case_mgr.base_dir, case_id, "reports")
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, f"{case_id}_Forensic_Report.html")

    timeline_data = active_timeline.build_timeline()
    generate_html_report(case, html_path, findings=timeline_data.get("anomalies_detected"))
    
    return FileResponse(html_path, media_type="text/html", filename=f"{case_id}_Forensic_Report.html")

# ==================== FILE & MEDIA FORENSICS ====================

@router.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    temp_path = save_upload_temp(file)
    try:
        hashes = calculate_hashes(temp_path)
        header = analyze_file_header(temp_path)
        exif = extract_exif_metadata(temp_path)
        entropy_profile = calculate_chunked_entropy(temp_path, num_chunks=24)
        strings_iocs = extract_strings_and_iocs(temp_path, min_length=5, max_strings=150)
        hex_preview = generate_hex_dump(temp_path, offset=0, length=256)

        # Ingest to timeline
        active_timeline.ingest_file_macb(temp_path, hashes)
        if header.get("is_spoofed"):
            active_timeline.add_event(
                timestamp=hashes["modified_time"],
                source="FileForensics",
                event_type="EXTENSION_SPOOFED",
                description=f"Extension spoof detected: {hashes['file_name']} disguised as {header['extension']}",
                severity="Critical"
            )

        return {
            "hashes": hashes,
            "header": header,
            "exif": exif,
            "entropy_profile": entropy_profile,
            "strings_and_iocs": strings_iocs,
            "hex_preview": hex_preview,
            "temp_file_token": os.path.basename(os.path.dirname(temp_path)) + "/" + file.filename
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/analyze/hex")
def get_hex(path: str = Query(...), offset: int = Query(0), length: int = Query(256)):
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    try:
        rows = generate_hex_dump(path, offset=offset, length=length)
        total_size = os.path.getsize(path)
        return {"rows": rows, "offset": offset, "length": length, "total_size": total_size}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==================== PE EXECUTABLE FORENSICS ====================

@router.post("/analyze/pe")
async def analyze_pe_file(file: UploadFile = File(...)):
    temp_path = save_upload_temp(file)
    try:
        result = analyze_pe(temp_path)
        if result.get("is_pe"):
            active_timeline.add_event(
                timestamp=result.get("compile_timestamp", ""),
                source="PEHeader",
                event_type="PE_COMPILED",
                description=f"Binary compiled: {file.filename} (Subsystem: {result.get('subsystem')})",
                severity="Info",
                details=result
            )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

# ==================== EVTX LOG FORENSICS ====================

@router.post("/analyze/evtx")
async def analyze_evtx_file(file: UploadFile = File(...), max_records: int = Form(1000)):
    temp_path = save_upload_temp(file)
    try:
        res = analyze_evtx(temp_path, max_records=max_records)
        active_timeline.ingest_evtx_records(res)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

# ==================== BROWSER FORENSICS ====================

@router.post("/analyze/browser")
async def analyze_browser_file(file: UploadFile = File(...)):
    temp_path = save_upload_temp(file)
    try:
        res = parse_browser_database(temp_path)
        active_timeline.ingest_browser_history(res)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

@router.get("/analyze/browser/live")
def get_live_browsers():
    return discover_installed_browsers()

@router.post("/analyze/browser/parse_path")
def parse_browser_path(db_path: str = Form(...)):
    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Browser database not found")
    res = parse_browser_database(db_path)
    active_timeline.ingest_browser_history(res)
    return res

# ==================== LIVE SYSTEM TRIAGE ====================

@router.get("/triage/system")
def get_live_system():
    return get_system_summary()

@router.get("/triage/processes")
def get_live_processes():
    return triage_processes()

@router.get("/triage/network")
def get_live_network():
    return triage_network_connections()

@router.get("/triage/persistence")
def get_live_persistence():
    return triage_persistence_hooks()

@router.post("/triage/memory/scan")
def scan_memory(pid: int = Form(...), pattern: str = Form(...)):
    return scan_process_memory(pid=pid, pattern=pattern)

# ==================== NETWORK FORENSICS (PCAP) ====================

@router.post("/analyze/pcap")
async def analyze_pcap_file(file: UploadFile = File(...), max_packets: int = Form(30000)):
    temp_path = save_upload_temp(file)
    try:
        res = analyze_pcap(temp_path, max_packets=max_packets)
        active_timeline.ingest_pcap_events(res)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

# ==================== SUPERTIMELINE ====================

@router.get("/timeline")
def get_timeline():
    return active_timeline.build_timeline()

@router.post("/timeline/clear")
def clear_timeline():
    active_timeline.events.clear()
    return {"status": "cleared"}

# ==================== FILE CARVING ====================

@router.post("/carve")
async def carve_files(file: UploadFile = File(...), max_items: int = Form(50)):
    temp_path = save_upload_temp(file)
    try:
        results = carve_embedded_files(temp_path, max_carved=max_items)
        if results.get("carved_count", 0) > 0:
            active_timeline.add_event(
                timestamp="",
                source="FileCarver",
                event_type="FILES_CARVED",
                description=f"Carved {results['carved_count']} embedded files from {file.filename}",
                severity="Medium"
            )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

# ==================== MITRE ATT&CK MATRIX MAPPING ====================

@router.get("/mitre")
def get_mitre_mapping():
    timeline_data = active_timeline.build_timeline()
    events = timeline_data.get("timeline", [])
    anomalies = timeline_data.get("anomalies_detected", [])
    combined = events + anomalies
    return map_forensic_evidence_to_mitre(combined)

# ==================== THREAT INTEL LOOKUP ====================

@router.post("/intel/lookup")
def lookup_ioc(indicator: str = Form(...), indicator_type: str = Form("auto")):
    return lookup_indicator(ioc=indicator, ioc_type=indicator_type)

# ==================== SAMPLES & TEST SUITE ====================

@router.get("/samples")
def get_samples():
    sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))
    items = []
    if os.path.exists(sample_dir):
        for f in os.listdir(sample_dir):
            p = os.path.join(sample_dir, f)
            if os.path.isfile(p):
                items.append({
                    "name": f,
                    "path": p,
                    "size_bytes": os.path.getsize(p)
                })
    return items
