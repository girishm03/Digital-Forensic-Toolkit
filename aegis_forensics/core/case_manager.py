import os
import json
import uuid
import datetime
from typing import Dict, Any, List, Optional
from aegis_forensics.core.hashing import calculate_hashes, verify_file_integrity

class CaseManager:
    """
    Manages forensic cases, evidence registration, and immutable Chain of Custody records.
    """
    def __init__(self, base_dir: str = "cases"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def create_case(
        self,
        case_id: str,
        title: str,
        investigator: str,
        organization: str = "Digital Forensics & Incident Response",
        description: str = "",
        target_system: str = "Unknown Host"
    ) -> Dict[str, Any]:
        """Create a new forensic investigation case."""
        clean_id = "".join(c for c in case_id if c.isalnum() or c in ("-", "_")).strip()
        if not clean_id:
            clean_id = f"CASE-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

        case_folder = os.path.join(self.base_dir, clean_id)
        os.makedirs(case_folder, exist_ok=True)
        evidence_folder = os.path.join(case_folder, "evidence")
        os.makedirs(evidence_folder, exist_ok=True)

        case_meta = {
            "case_id": clean_id,
            "title": title,
            "investigator": investigator,
            "organization": organization,
            "description": description,
            "target_system": target_system,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "evidence_count": 0,
            "evidence_items": [],
            "chain_of_custody": [
                {
                    "event_id": str(uuid.uuid4())[:8],
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "investigator": investigator,
                    "action": "CASE_INITIALIZED",
                    "details": f"Investigation case '{title}' established by {investigator} ({organization})."
                }
            ]
        }

        meta_path = os.path.join(case_folder, "case_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(case_meta, f, indent=2)

        return case_meta

    def list_cases(self) -> List[Dict[str, Any]]:
        """List all registered cases."""
        cases = []
        if not os.path.exists(self.base_dir):
            return cases

        for item in sorted(os.listdir(self.base_dir)):
            case_path = os.path.join(self.base_dir, item)
            meta_path = os.path.join(case_path, "case_meta.json")
            if os.path.isdir(case_path) and os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        cases.append(json.load(f))
                except Exception:
                    continue
        return cases

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get case metadata by ID."""
        meta_path = os.path.join(self.base_dir, case_id, "case_meta.json")
        if not os.path.exists(meta_path):
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def add_evidence(
        self,
        case_id: str,
        source_file_path: str,
        evidence_label: str,
        investigator: str,
        notes: str = "",
        copy_to_vault: bool = True
    ) -> Dict[str, Any]:
        """
        Register a new evidence item with cryptographic hashing and Chain of Custody logging.
        """
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' does not exist.")

        hashes = calculate_hashes(source_file_path)
        evidence_id = f"EV-{datetime.datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"

        destination_path = source_file_path
        if copy_to_vault:
            vault_dir = os.path.join(self.base_dir, case_id, "evidence")
            dest_filename = f"{evidence_id}_{os.path.basename(source_file_path)}"
            destination_path = os.path.join(vault_dir, dest_filename)
            
            # Copy file in binary chunks
            with open(source_file_path, "rb") as src, open(destination_path, "wb") as dst:
                while chunk := src.read(64 * 1024):
                    dst.write(chunk)
            
            # Re-verify copy integrity
            copied_hashes = calculate_hashes(destination_path)
            if copied_hashes["sha256"] != hashes["sha256"]:
                if os.path.exists(destination_path):
                    os.remove(destination_path)
                raise RuntimeError("Integrity check failed during evidence intake copy!")

        evidence_entry = {
            "evidence_id": evidence_id,
            "label": evidence_label,
            "original_filename": os.path.basename(source_file_path),
            "stored_path": destination_path,
            "size_bytes": hashes["size_bytes"],
            "size_human": hashes["size_human"],
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "sha512": hashes["sha512"],
            "entropy": hashes["entropy"],
            "entropy_assessment": hashes["entropy_assessment"],
            "intake_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "investigator": investigator,
            "notes": notes,
            "status": "SECURED"
        }

        case["evidence_items"].append(evidence_entry)
        case["evidence_count"] = len(case["evidence_items"])

        # Chain of Custody event
        case["chain_of_custody"].append({
            "event_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "investigator": investigator,
            "action": "EVIDENCE_INGESTED",
            "evidence_id": evidence_id,
            "details": f"Acquired '{evidence_label}' ({os.path.basename(source_file_path)}). Baseline SHA-256: {hashes['sha256']}. Notes: {notes}"
        })

        meta_path = os.path.join(self.base_dir, case_id, "case_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(case, f, indent=2)

        return evidence_entry

    def log_custody_action(
        self,
        case_id: str,
        investigator: str,
        action: str,
        details: str,
        evidence_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Append an immutable Chain of Custody event."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' does not exist.")

        entry = {
            "event_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "investigator": investigator,
            "action": action,
            "evidence_id": evidence_id,
            "details": details
        }
        case["chain_of_custody"].append(entry)

        meta_path = os.path.join(self.base_dir, case_id, "case_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(case, f, indent=2)

        return entry

    def verify_case_evidence(self, case_id: str, investigator: str) -> List[Dict[str, Any]]:
        """Verify the integrity of all evidence items associated with a case."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' does not exist.")

        results = []
        all_passed = True
        for ev in case.get("evidence_items", []):
            path = ev["stored_path"]
            if not os.path.exists(path):
                res = {
                    "evidence_id": ev["evidence_id"],
                    "label": ev["label"],
                    "is_intact": False,
                    "status": "FILE_MISSING (Evidence Vault Path Not Found)",
                    "expected_sha256": ev["sha256"],
                    "computed_sha256": None
                }
                all_passed = False
            else:
                ver = verify_file_integrity(path, ev["sha256"], algorithm="sha256")
                res = {
                    "evidence_id": ev["evidence_id"],
                    "label": ev["label"],
                    "is_intact": ver["is_intact"],
                    "status": ver["status"],
                    "expected_sha256": ev["sha256"],
                    "computed_sha256": ver["computed_hash"]
                }
                if not ver["is_intact"]:
                    all_passed = False
            results.append(res)

        self.log_custody_action(
            case_id=case_id,
            investigator=investigator,
            action="INTEGRITY_AUDIT_COMPLETED",
            details=f"Audited {len(results)} items. Result: {'ALL MATCH (Integrity Verified)' if all_passed else 'WARNING: TAMPER OR CORRUPTION DETECTED'}"
        )
        return results
