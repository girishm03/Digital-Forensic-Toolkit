import hashlib
import os
import math
from typing import Dict, Any, Optional

CHUNK_SIZE = 64 * 1024  # 64 KB chunks for memory-safe streaming

def calculate_hashes(file_path: str) -> Dict[str, Any]:
    """
    Calculate cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512) and file metadata
    using streaming reads for forensic integrity.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    byte_counts = [0] * 256
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            total_bytes += len(chunk)
            for byte in chunk:
                byte_counts[byte] += 1

    # Calculate overall Shannon entropy (0.0 to 8.0)
    entropy = 0.0
    if total_bytes > 0:
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

    stat = os.stat(file_path)

    return {
        "file_name": os.path.basename(file_path),
        "file_path": os.path.abspath(file_path),
        "size_bytes": total_bytes,
        "size_human": format_file_size(total_bytes),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
        "entropy": round(entropy, 4),
        "entropy_assessment": assess_entropy(entropy),
        "created_time": stat.st_ctime,
        "modified_time": stat.st_mtime,
        "accessed_time": stat.st_atime,
    }

def verify_file_integrity(file_path: str, expected_hash: str, algorithm: str = "sha256") -> Dict[str, Any]:
    """
    Verify a file against an expected baseline hash value for Chain of Custody integrity.
    """
    alg = algorithm.lower().replace("-", "")
    if alg not in ["md5", "sha1", "sha256", "sha512"]:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    hasher = getattr(hashlib, alg)()
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)

    computed = hasher.hexdigest()
    matched = (computed.lower() == expected_hash.strip().lower())

    return {
        "file_name": os.path.basename(file_path),
        "algorithm": alg.upper(),
        "expected_hash": expected_hash.strip().lower(),
        "computed_hash": computed,
        "is_intact": matched,
        "status": "VALID (Uncompromised)" if matched else "TAMPERED / MISMATCH (Integrity Violated)"
    }

def assess_entropy(entropy: float) -> str:
    """Assess whether entropy indicates plain text, code, or packed/encrypted data."""
    if entropy < 3.0:
        return "Low (Repetitive data / Sparse binary)"
    elif entropy < 5.0:
        return "Normal (Plain text / Structured source code)"
    elif entropy < 7.2:
        return "Moderate (Compiled binary code / Compressed assets)"
    else:
        return "High (Encrypted data, Packed binary, or Obfuscated payload)"

def format_file_size(size_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {units[i]}"
