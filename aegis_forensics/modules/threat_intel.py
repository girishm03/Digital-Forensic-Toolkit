import hashlib
import re
from typing import Dict, Any, List

KNOWN_THREAT_SIGNATURES = {
    # Sample known malware hashes
    "6a6082630da7dd5ea17926d83f9f2de5": {
        "family": "Trojan.Dropper.Generic",
        "actor": "Unattributed / Commodity Malware",
        "confidence": 92,
        "classification": "MALICIOUS",
        "verdict": "Obfuscated PE header disguised as image container."
    },
    "6b237ee487718490e161eb633f53e918bdb9f6ab6c2f0de358e8c3c9043b9067": {
        "family": "Trojan.Dropper.Generic",
        "actor": "Unattributed / Commodity Malware",
        "confidence": 92,
        "classification": "MALICIOUS",
        "verdict": "PE binary embedded inside suspicious invoice graphic."
    }
}

KNOWN_MALICIOUS_IPS = {
    "104.28.19.44": {"reputation": "MALICIOUS", "score": 88, "country": "US", "asn": "Cloudflare", "threat": "Known Cobalt Strike C2 Listener"},
    "192.168.1.105": {"reputation": "SUSPICIOUS", "score": 65, "country": "Private", "asn": "RFC1918", "threat": "Internal Staging Server (Lateral Movement Target)"},
    "198.51.100.22": {"reputation": "MALICIOUS", "score": 95, "country": "RU", "asn": "Bulletproof Host", "threat": "RedLine Stealer Exfiltration Drop Point"}
}

def lookup_indicator(ioc: str, ioc_type: str = "auto") -> Dict[str, Any]:
    """
    Forensic Threat Intelligence lookup: evaluates reputation, threat actor attribution,
    and confidence scores for hashes, IPs, and domains.
    """
    clean_ioc = ioc.strip()
    
    # Auto-detect type
    if ioc_type == "auto":
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$", clean_ioc):
            ioc_type = "hash"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_ioc):
            ioc_type = "ip"
        elif "." in clean_ioc and not clean_ioc.startswith("http"):
            ioc_type = "domain"
        else:
            ioc_type = "generic"

    if ioc_type == "hash":
        clean_lower = clean_ioc.lower()
        if clean_lower in KNOWN_THREAT_SIGNATURES:
            info = KNOWN_THREAT_SIGNATURES[clean_lower]
            return {
                "ioc": clean_ioc,
                "type": "Cryptographic Hash",
                "classification": info["classification"],
                "confidence_score": info["confidence"],
                "threat_family": info["family"],
                "actor_attribution": info["actor"],
                "details": info["verdict"],
                "is_known_threat": True
            }
        else:
            return {
                "ioc": clean_ioc,
                "type": "Cryptographic Hash",
                "classification": "UNKNOWN / CLEAN IN LOCAL FEED",
                "confidence_score": 15,
                "threat_family": "None Known",
                "actor_attribution": "None",
                "details": "Hash is not present in local threat intelligence blacklist. Verify against dynamic sandbox.",
                "is_known_threat": False
            }

    elif ioc_type == "ip":
        if clean_ioc in KNOWN_MALICIOUS_IPS:
            info = KNOWN_MALICIOUS_IPS[clean_ioc]
            return {
                "ioc": clean_ioc,
                "type": "IPv4 Address",
                "classification": info["reputation"],
                "confidence_score": info["score"],
                "threat_family": info["threat"],
                "actor_attribution": f"{info['asn']} ({info['country']})",
                "details": f"Flagged in threat feeds: {info['threat']}",
                "is_known_threat": True
            }
        elif clean_ioc.startswith(("10.", "192.168.", "172.16.")):
            return {
                "ioc": clean_ioc,
                "type": "Private RFC1918 IP",
                "classification": "INTERNAL NETWORK",
                "confidence_score": 0,
                "threat_family": "Internal Host",
                "actor_attribution": "Local LAN",
                "details": "Private non-routable IPv4 address.",
                "is_known_threat": False
            }
        else:
            return {
                "ioc": clean_ioc,
                "type": "Public IPv4",
                "classification": "UNRATED / NEUTRAL",
                "confidence_score": 20,
                "threat_family": "Unknown",
                "actor_attribution": "Standard Public Host",
                "details": "No abuse reports in local threat database.",
                "is_known_threat": False
            }

    elif ioc_type == "domain":
        is_dga = False
        if len(clean_ioc) > 16:
            # Simple entropy check
            import math
            counts = {}
            for c in clean_ioc: counts[c] = counts.get(c, 0) + 1
            ent = -sum((cnt/len(clean_ioc))*math.log2(cnt/len(clean_ioc)) for cnt in counts.values())
            if ent > 3.8: is_dga = True

        if is_dga or "malwaredomain" in clean_ioc or ".onion" in clean_ioc:
            return {
                "ioc": clean_ioc,
                "type": "Domain Name",
                "classification": "MALICIOUS DGA / SUSPICIOUS C2",
                "confidence_score": 90,
                "threat_family": "DGA Algorithmic Domain / Tor Hidden Service",
                "actor_attribution": "Advanced Threat Actor / Ransomware Campaign",
                "details": "High entropy string structure strongly matches automated malware rendezvous.",
                "is_known_threat": True
            }
        else:
            return {
                "ioc": clean_ioc,
                "type": "Domain Name",
                "classification": "BENIGN / LOW RISK",
                "confidence_score": 10,
                "threat_family": "None",
                "actor_attribution": "Legitimate Top Level Domain",
                "details": "Standard domain entropy.",
                "is_known_threat": False
            }

    return {
        "ioc": clean_ioc,
        "type": "Unknown",
        "classification": "UNCLASSIFIED",
        "confidence_score": 0,
        "threat_family": "None",
        "actor_attribution": "N/A",
        "details": "Unsupported indicator format.",
        "is_known_threat": False
    }
