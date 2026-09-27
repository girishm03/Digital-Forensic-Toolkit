import os
import re
import math
from typing import Dict, Any, List, Optional
from PIL import Image, ExifTags

# Known magic byte signatures: (offset, bytes_pattern, detected_type, description, canonical_exts)
MAGIC_SIGNATURES = [
    (0, b"\x4D\x5A", "Windows PE Executable / DLL", "Portable Executable (PE32/PE32+)", [".exe", ".dll", ".sys", ".scr"]),
    (0, b"\x7F\x45\x4C\x46", "Linux ELF Executable", "Executable and Linkable Format", [".elf", ".bin", ""]),
    (0, b"\xFE\xED\xFA\xCE", "Mach-O 32-bit", "macOS Mach-O Binary", [""]),
    (0, b"\xFE\xED\xFA\xCF", "Mach-O 64-bit", "macOS Mach-O Binary", [""]),
    (0, b"\xCF\xFA\xED\xFE", "Mach-O 64-bit (reverse)", "macOS Mach-O Binary", [""]),
    (0, b"\x50\x4B\x03\x04", "ZIP / Modern Office Doc", "ZIP Archive or OOXML (DOCX/XLSX/PPTX/JAR/APK)", [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]),
    (0, b"\x50\x4B\x05\x06", "Empty ZIP Archive", "ZIP Archive", [".zip"]),
    (0, b"\x25\x50\x44\x46", "PDF Document", "Adobe Portable Document Format", [".pdf"]),
    (0, b"\xFF\xD8\xFF", "JPEG Image", "JPEG/JFIF raster image", [".jpg", ".jpeg"]),
    (0, b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "PNG Image", "Portable Network Graphics", [".png"]),
    (0, b"\x47\x49\x46\x38\x37\x61", "GIF Image", "GIF 87a Graphics Interchange Format", [".gif"]),
    (0, b"\x47\x49\x46\x38\x39\x61", "GIF Image", "GIF 89a Graphics Interchange Format", [".gif"]),
    (0, b"\x52\x61\x72\x21\x1A\x07", "RAR Archive", "RAR Compressed Archive", [".rar"]),
    (0, b"\x37\x7A\xBC\xAF\x27\x1C", "7-Zip Archive", "7-Zip Compressed File", [".7z"]),
    (0, b"\x1F\x8B\x08", "GZIP Compressed", "GNU Zip Compressed Archive", [".gz", ".tgz"]),
    (0, b"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00", "SQLite Database", "SQLite 3 Database", [".sqlite", ".db", ".sqlite3"]),
    (0, b"\x45\x6C\x66\x46\x69\x6C\x65\x00", "Windows Event Log (EVTX)", "Windows Event Log Binary Format", [".evtx"]),
    (0, b"\xD4\xC3\xB2\xA1", "PCAP Capture (Little Endian)", "Libpcap Packet Capture", [".pcap", ".cap"]),
    (0, b"\xA1\xB2\xC3\xD4", "PCAP Capture (Big Endian)", "Libpcap Packet Capture", [".pcap", ".cap"]),
    (0, b"\x0A\x0D\x0D\x0A", "PCAPNG Capture", "PCAP Next Generation Capture", [".pcapng"]),
    (0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE Compound Document", "Legacy MS Office (DOC, XLS, PPT, MSG)", [".doc", ".xls", ".ppt", ".msg"]),
    (0, b"\x4C\x00\x00\x00\x01\x14\x02\x00", "Windows LNK Shortcut", "Windows Shell Link File", [".lnk"]),
    (0, b"\x77\x4F\x46\x46", "WOFF Font", "Web Open Font Format", [".woff"]),
    (0, b"\x4F\x67\x67\x53", "OGG Audio/Video", "Ogg Vorbis Media Stream", [".ogg", ".ogv", ".oga"]),
    (4, b"\x66\x74\x79\x70", "MP4 / ISO Media", "MPEG-4 Part 14 Video container", [".mp4", ".m4v", ".mov"]),
]

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "url": re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"),
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "windows_path": re.compile(r"[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),
    "base64_blob": re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
}

def analyze_file_header(file_path: str) -> Dict[str, Any]:
    """
    Inspect raw magic bytes at file head, identify signature, and flag extension spoofing.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    _, ext = os.path.splitext(file_path)
    ext_lower = ext.lower()

    # Read first 512 bytes
    with open(file_path, "rb") as f:
        header_sample = f.read(512)

    detected_type = "Unknown Binary or Plain Text"
    description = "No standard forensic signature detected in first 512 bytes"
    canonical_exts = []
    is_spoofed = False
    warning = None

    for offset, pattern, sig_name, sig_desc, exts in MAGIC_SIGNATURES:
        if len(header_sample) >= offset + len(pattern):
            if header_sample[offset:offset + len(pattern)] == pattern:
                detected_type = sig_name
                description = sig_desc
                canonical_exts = exts
                break

    # Extension spoofing heuristic
    if canonical_exts:
        if ext_lower not in canonical_exts:
            # Special case for text / docx inside zip
            if detected_type.startswith("ZIP") and ext_lower in [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]:
                is_spoofed = False
            else:
                is_spoofed = True
                warning = f"CRITICAL ANOMALY: File has extension '{ext_lower}', but binary magic bytes identify it as '{detected_type}'! Possible disguise/trojan."

    # First 16 bytes hex representation
    magic_hex = " ".join(f"{b:02X}" for b in header_sample[:16])

    return {
        "file_name": os.path.basename(file_path),
        "extension": ext_lower,
        "magic_hex": magic_hex,
        "detected_type": detected_type,
        "description": description,
        "canonical_extensions": canonical_exts,
        "is_spoofed": is_spoofed,
        "anomaly_warning": warning
    }

def extract_exif_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract forensic EXIF metadata and GPS coordinates from images.
    """
    result = {
        "has_exif": False,
        "metadata": {},
        "gps": None
    }

    try:
        with Image.open(file_path) as img:
            exif_raw = img.getexif()
            if not exif_raw:
                return result

            result["has_exif"] = True
            extracted = {}
            gps_info = {}

            for tag_id, value in exif_raw.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if tag_name == "GPSInfo":
                    gps_info = value
                else:
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore")
                        except Exception:
                            value = str(value)
                    extracted[tag_name] = str(value)

            result["metadata"] = extracted

            # Process GPS if present
            if gps_info:
                lat = None
                lon = None
                # Basic GPS coordinate parsing
                try:
                    lat_ref = gps_info.get(1)
                    lat_val = gps_info.get(2)
                    lon_ref = gps_info.get(3)
                    lon_val = gps_info.get(4)

                    if lat_val and lon_val:
                        lat_deg = float(lat_val[0]) + float(lat_val[1])/60.0 + float(lat_val[2])/3600.0
                        if lat_ref == "S":
                            lat_deg = -lat_deg
                        lon_deg = float(lon_val[0]) + float(lon_val[1])/60.0 + float(lon_val[2])/3600.0
                        if lon_ref == "W":
                            lon_deg = -lon_deg

                        lat = round(lat_deg, 6)
                        lon = round(lon_deg, 6)
                        result["gps"] = {
                            "latitude": lat,
                            "longitude": lon,
                            "maps_url": f"https://www.google.com/maps?q={lat},{lon}"
                        }
                except Exception:
                    pass

    except Exception:
        pass

    return result

def generate_hex_dump(file_path: str, offset: int = 0, length: int = 256) -> List[Dict[str, Any]]:
    """
    Generate interactive hex view rows (Offset, Hex Bytes, ASCII text).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    rows = []
    with open(file_path, "rb") as f:
        f.seek(offset)
        chunk = f.read(length)

    for i in range(0, len(chunk), 16):
        sub = chunk[i:i+16]
        hex_parts = [f"{b:02X}" for b in sub]
        # Pad if less than 16
        while len(hex_parts) < 16:
            hex_parts.append("  ")

        ascii_chars = "".join((chr(b) if 32 <= b <= 126 else ".") for b in sub)

        rows.append({
            "offset": f"{(offset + i):08X}",
            "hex": hex_parts,
            "hex_str": " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:]),
            "ascii": ascii_chars
        })

    return rows

def calculate_chunked_entropy(file_path: str, num_chunks: int = 32) -> List[Dict[str, Any]]:
    """
    Calculate entropy across discrete chunks of the file to create an entropy profile.
    Highlights packed or encrypted payloads embedded within benign files.
    """
    size = os.path.getsize(file_path)
    if size == 0:
        return []

    chunk_size = max(512, size // num_chunks)
    entropy_profile = []

    with open(file_path, "rb") as f:
        offset = 0
        chunk_idx = 0
        while offset < size:
            data = f.read(chunk_size)
            if not data:
                break
            
            # Calculate Shannon entropy
            byte_counts = [0] * 256
            for b in data:
                byte_counts[b] += 1
            
            ent = 0.0
            total = len(data)
            for count in byte_counts:
                if count > 0:
                    p = count / total
                    ent -= p * math.log2(p)

            entropy_profile.append({
                "chunk_index": chunk_idx,
                "offset": offset,
                "offset_hex": f"0x{offset:X}",
                "entropy": round(ent, 3),
                "is_suspicious": ent > 7.2
            })
            offset += len(data)
            chunk_idx += 1

    return entropy_profile

def extract_strings_and_iocs(file_path: str, min_length: int = 4, max_strings: int = 500) -> Dict[str, Any]:
    """
    Extract readable ASCII & UTF-16 strings and regex match potential Indicators of Compromise (IOCs).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Read binary in chunks up to 8MB limit for string analysis
    max_scan = 8 * 1024 * 1024
    with open(file_path, "rb") as f:
        raw = f.read(max_scan)

    # ASCII regex
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    extracted = [m.group(0).decode("ascii", errors="ignore") for m in ascii_pattern.finditer(raw)]

    # UTF-16 LE regex
    unicode_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}")
    for m in unicode_pattern.finditer(raw):
        try:
            extracted.append(m.group(0).decode("utf-16-le", errors="ignore"))
        except Exception:
            pass

    # Find IOCs
    combined_text = "\n".join(extracted[:5000])

    iocs = {
        "ips": list(set(IOC_PATTERNS["ipv4"].findall(combined_text))),
        "urls": list(set(IOC_PATTERNS["url"].findall(combined_text))),
        "emails": list(set(IOC_PATTERNS["email"].findall(combined_text))),
        "paths": list(set(IOC_PATTERNS["windows_path"].findall(combined_text))),
        "base64_blobs": list(set(IOC_PATTERNS["base64_blob"].findall(combined_text)))[:10]
    }

    # Filter out common benign IPs like 0.0.0.0, 127.0.0.1, 255.255.255.255 if desired
    suspicious_ips = [ip for ip in iocs["ips"] if not ip.startswith(("0.", "127.", "255."))]

    return {
        "total_strings_found": len(extracted),
        "sample_strings": extracted[:max_strings],
        "iocs": {
            "ips": suspicious_ips,
            "urls": iocs["urls"][:50],
            "emails": iocs["emails"][:50],
            "paths": iocs["paths"][:50],
            "base64_count": len(iocs["base64_blobs"])
        }
    }
