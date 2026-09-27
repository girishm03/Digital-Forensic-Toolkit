import os
import socket
import datetime
import math
from typing import Dict, Any, List, Optional
import dpkt

def inet_to_str(inet: bytes) -> str:
    """Convert raw IP bytes into human-readable string."""
    try:
        if len(inet) == 4:
            return socket.inet_ntoa(inet)
        elif len(inet) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet)
    except Exception:
        pass
    return "Unknown"

def calculate_string_entropy(s: str) -> float:
    """Calculate Shannon entropy for domain names to detect DGA (Domain Generation Algorithms)."""
    if not s:
        return 0.0
    byte_counts = {}
    for c in s:
        byte_counts[c] = byte_counts.get(c, 0) + 1
    entropy = 0.0
    total = len(s)
    for count in byte_counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def analyze_pcap(file_path: str, max_packets: int = 50000) -> Dict[str, Any]:
    """
    Forensic PCAP packet capture parser with protocol triage, conversation mapping, DNS, HTTP, and TLS SNI.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    stats = {
        "file_name": os.path.basename(file_path),
        "total_packets": 0,
        "total_bytes": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "protocols": {},
        "conversations": {},
        "dns_queries": [],
        "http_requests": [],
        "tls_sni": [],
        "suspicious_events": []
    }

    try:
        with open(file_path, "rb") as f:
            # Check pcap header
            magic = f.read(4)
            f.seek(0)
            
            if magic in [b"\xD4\xC3\xB2\xA1", b"\xA1\xB2\xC3\xD4"]:
                pcap_reader = dpkt.pcap.Reader(f)
            elif magic == b"\x0A\x0D\x0D\x0A":
                pcap_reader = dpkt.pcapng.Reader(f)
            else:
                try:
                    pcap_reader = dpkt.pcap.Reader(f)
                except Exception:
                    pcap_reader = dpkt.pcapng.Reader(f)

            count = 0
            for ts, buf in pcap_reader:
                count += 1
                if count > max_packets:
                    break

                pkt_len = len(buf)
                stats["total_packets"] += 1
                stats["total_bytes"] += pkt_len

                ts_iso = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
                if not stats["first_timestamp"]:
                    stats["first_timestamp"] = ts_iso
                stats["last_timestamp"] = ts_iso

                # Parse Ethernet frame
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    proto_name = "Non-IP / ARP"
                    stats["protocols"][proto_name] = stats["protocols"].get(proto_name, 0) + 1
                    continue

                ip = eth.data
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)

                transport = ip.data
                sport, dport = 0, 0
                proto_name = "IP Other"

                if isinstance(transport, dpkt.tcp.TCP):
                    proto_name = "TCP"
                    sport = transport.sport
                    dport = transport.dport

                    # Check HTTP
                    if dport in [80, 8080, 8000] or sport in [80, 8080, 8000]:
                        if len(transport.data) > 0:
                            try:
                                http_req = dpkt.http.Request(transport.data)
                                host = http_req.headers.get("host", dst_ip)
                                uri = http_req.uri
                                stats["http_requests"].append({
                                    "timestamp": ts_iso,
                                    "src_ip": src_ip,
                                    "method": http_req.method,
                                    "host": host,
                                    "uri": uri,
                                    "user_agent": http_req.headers.get("user-agent", "")
                                })
                            except Exception:
                                pass

                    # Check TLS Client Hello (SNI extraction)
                    if dport == 443 or sport == 443:
                        if len(transport.data) > 5 and transport.data[0] == 0x16:  # TLS Handshake
                            try:
                                tls_records, _ = dpkt.ssl.tls_multi_factory(transport.data)
                                for rec in tls_records:
                                    if isinstance(rec.data, dpkt.ssl.TLSHandshake):
                                        handshake = rec.data
                                        if isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                                            ch = handshake.data
                                            # Parse extensions for SNI (type 0)
                                            for ext_type, ext_data in ch.extensions:
                                                if ext_type == 0:
                                                    # Server Name Indication
                                                    sni_name = ext_data[5:].decode("ascii", errors="ignore")
                                                    stats["tls_sni"].append({
                                                        "timestamp": ts_iso,
                                                        "src_ip": src_ip,
                                                        "dst_ip": dst_ip,
                                                        "sni": sni_name
                                                    })
                            except Exception:
                                pass

                elif isinstance(transport, dpkt.udp.UDP):
                    proto_name = "UDP"
                    sport = transport.sport
                    dport = transport.dport

                    # Check DNS
                    if dport == 53 or sport == 53:
                        try:
                            dns = dpkt.dns.DNS(transport.data)
                            if dns.qr == dpkt.dns.DNS_Q:  # Query
                                for q in dns.qd:
                                    domain = q.name
                                    ent = calculate_string_entropy(domain)
                                    stats["dns_queries"].append({
                                        "timestamp": ts_iso,
                                        "src_ip": src_ip,
                                        "domain": domain,
                                        "entropy": ent,
                                        "is_dga_suspicious": ent > 4.2 and len(domain) > 15
                                    })
                                    if ent > 4.2 and len(domain) > 15:
                                        stats["suspicious_events"].append({
                                            "timestamp": ts_iso,
                                            "type": "High Entropy / DGA Domain",
                                            "details": f"Query: {domain} (Entropy: {ent})"
                                        })
                        except Exception:
                            pass

                elif isinstance(transport, dpkt.icmp.ICMP):
                    proto_name = "ICMP"

                stats["protocols"][proto_name] = stats["protocols"].get(proto_name, 0) + 1

                # Flow tracking
                flow_key = f"{src_ip} -> {dst_ip}"
                if flow_key not in stats["conversations"]:
                    stats["conversations"][flow_key] = {"packets": 0, "bytes": 0, "proto": proto_name}
                stats["conversations"][flow_key]["packets"] += 1
                stats["conversations"][flow_key]["bytes"] += pkt_len

    except Exception as e:
        stats["error"] = f"PCAP parsing encountered an error: {str(e)}"

    # Sort conversations by bytes transferred
    sorted_conv = sorted(
        [{"flow": k, **v} for k, v in stats["conversations"].items()],
        key=lambda x: x["bytes"],
        reverse=True
    )[:50]

    return {
        "file_name": stats["file_name"],
        "total_packets": stats["total_packets"],
        "total_bytes": stats["total_bytes"],
        "duration": {
            "start": stats["first_timestamp"],
            "end": stats["last_timestamp"]
        },
        "protocol_breakdown": stats["protocols"],
        "top_conversations": sorted_conv,
        "dns_queries": stats["dns_queries"][:100],
        "http_requests": stats["http_requests"][:100],
        "tls_sni_records": stats["tls_sni"][:100],
        "suspicious_network_events": stats["suspicious_events"][:50]
    }
