import os
import hashlib
import base64
from typing import Dict, Any, List

CARVE_SIGNATURES = [
    {
        "type": "JPEG Image",
        "ext": "jpg",
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "max_size": 25 * 1024 * 1024
    },
    {
        "type": "PNG Image",
        "ext": "png",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xae\x42\x60\x82",
        "max_size": 25 * 1024 * 1024
    },
    {
        "type": "PDF Document",
        "ext": "pdf",
        "header": b"%PDF-",
        "footer": b"%%EOF",
        "max_size": 50 * 1024 * 1024
    },
    {
        "type": "ZIP Archive",
        "ext": "zip",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "footer_pad": 18,
        "max_size": 100 * 1024 * 1024
    }
]

def carve_embedded_files(file_path: str, max_carved: int = 50) -> Dict[str, Any]:
    """
    Forensic file carving engine: recovers embedded or hidden files from raw binary/disk images
    based on magic byte headers and trailers.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    # Read binary safely up to 64MB for in-memory carving
    read_limit = min(file_size, 64 * 1024 * 1024)
    with open(file_path, "rb") as f:
        data = f.read(read_limit)

    carved_items = []

    for sig in CARVE_SIGNATURES:
        header = sig["header"]
        footer = sig.get("footer")
        footer_pad = sig.get("footer_pad", 0)
        max_size = sig["max_size"]

        start = 0
        while True:
            if len(carved_items) >= max_carved:
                break

            h_idx = data.find(header, start)
            if h_idx == -1:
                break

            end_idx = -1
            if footer:
                f_idx = data.find(footer, h_idx + len(header))
                if f_idx != -1 and (f_idx + len(footer) + footer_pad - h_idx) <= max_size:
                    end_idx = f_idx + len(footer) + footer_pad

            if end_idx != -1 and end_idx > h_idx:
                carved_blob = data[h_idx:end_idx]
                sha256 = hashlib.sha256(carved_blob).hexdigest()
                md5 = hashlib.md5(carved_blob).hexdigest()

                preview_b64 = None
                if sig["ext"] in ["jpg", "png"] and len(carved_blob) < 5 * 1024 * 1024:
                    preview_b64 = base64.b64encode(carved_blob).decode("ascii")

                carved_items.append({
                    "id": f"CARVE-{len(carved_items)+1:03d}",
                    "type": sig["type"],
                    "extension": sig["ext"],
                    "start_offset": h_idx,
                    "start_offset_hex": f"0x{h_idx:08X}",
                    "end_offset": end_idx,
                    "size_bytes": len(carved_blob),
                    "size_human": f"{len(carved_blob) / 1024:.2f} KB",
                    "sha256": sha256,
                    "md5": md5,
                    "preview_b64": preview_b64
                })
                start = end_idx
            else:
                start = h_idx + len(header)

    return {
        "source_file": os.path.basename(file_path),
        "total_scanned_bytes": len(data),
        "carved_count": len(carved_items),
        "carved_files": carved_items
    }
