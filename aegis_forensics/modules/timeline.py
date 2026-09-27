import datetime
from typing import Dict, Any, List, Optional

class SuperTimeline:
    """
    Super-timeline aggregator and threat anomaly correlation engine.
    Combines File MACB, Windows Event Logs, Browser History, and Network telemetry.
    """
    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def add_event(
        self,
        timestamp: str,
        source: str,
        event_type: str,
        description: str,
        severity: str = "Info",
        details: Optional[Dict[str, Any]] = None
    ):
        """Add a single normalized forensic event to the timeline."""
        if not timestamp:
            return

        self.events.append({
            "timestamp": timestamp,
            "source": source,
            "event_type": event_type,
            "description": description,
            "severity": severity,
            "details": details or {}
        })

    def ingest_file_macb(self, file_path: str, stats: Dict[str, Any]):
        """Ingest Modified, Accessed, Created timestamps for a file."""
        import os
        fname = os.path.basename(file_path)
        
        if stats.get("modified_time"):
            m_iso = datetime.datetime.fromtimestamp(stats["modified_time"], tz=datetime.timezone.utc).isoformat()
            self.add_event(m_iso, "FileSystem", "FILE_MODIFIED", f"File '{fname}' content modified", "Info", {"path": file_path})
        
        if stats.get("created_time"):
            c_iso = datetime.datetime.fromtimestamp(stats["created_time"], tz=datetime.timezone.utc).isoformat()
            self.add_event(c_iso, "FileSystem", "FILE_CREATED", f"File '{fname}' created on disk", "Info", {"path": file_path})

        if stats.get("accessed_time"):
            a_iso = datetime.datetime.fromtimestamp(stats["accessed_time"], tz=datetime.timezone.utc).isoformat()
            self.add_event(a_iso, "FileSystem", "FILE_ACCESSED", f"File '{fname}' last accessed", "Info", {"path": file_path})

    def ingest_evtx_records(self, evtx_results: Dict[str, Any]):
        """Ingest parsed Windows Event Log records."""
        for rec in evtx_results.get("records_sample", []):
            self.add_event(
                timestamp=rec.get("timestamp", ""),
                source="EventLog",
                event_type=rec.get("event_name", "Windows Event"),
                description=f"Event ID {rec.get('event_id')} in {rec.get('channel')} on {rec.get('computer')}",
                severity=rec.get("severity", "Info"),
                details=rec.get("details", {})
            )

    def ingest_browser_history(self, browser_results: Dict[str, Any]):
        """Ingest browser history and downloads."""
        for item in browser_results.get("history", []):
            if item.get("last_visit_time"):
                self.add_event(
                    timestamp=item["last_visit_time"],
                    source="BrowserHistory",
                    event_type="URL_VISIT",
                    description=f"Visited: {item.get('title')} ({item.get('url')[:100]})",
                    severity="Info",
                    details=item
                )
        for dl in browser_results.get("downloads", []):
            if dl.get("start_time"):
                self.add_event(
                    timestamp=dl["start_time"],
                    source="BrowserDownload",
                    event_type="FILE_DOWNLOAD",
                    description=f"Downloaded '{dl.get('filename')}' from {dl.get('source_url')[:80]}",
                    severity="Medium",
                    details=dl
                )

    def ingest_pcap_events(self, pcap_results: Dict[str, Any]):
        """Ingest suspicious PCAP and DNS/HTTP telemetry."""
        for dns in pcap_results.get("dns_queries", [])[:50]:
            self.add_event(
                timestamp=dns.get("timestamp", ""),
                source="NetworkDNS",
                event_type="DNS_QUERY",
                description=f"DNS query for '{dns.get('domain')}' from {dns.get('src_ip')}",
                severity="High" if dns.get("is_dga_suspicious") else "Info",
                details=dns
            )
        for http in pcap_results.get("http_requests", [])[:50]:
            self.add_event(
                timestamp=http.get("timestamp", ""),
                source="NetworkHTTP",
                event_type="HTTP_REQUEST",
                description=f"{http.get('method')} http://{http.get('host')}{http.get('uri')[:60]}",
                severity="Info",
                details=http
            )

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Run forensic correlation heuristics to detect high-confidence attack sequences.
        """
        anomalies = []
        sorted_events = sorted(self.events, key=lambda x: x.get("timestamp") or "")

        # 1. Anti-forensics: Security Log Cleared
        for ev in sorted_events:
            if "cleared" in ev["event_type"].lower() or "cleared" in ev["description"].lower():
                anomalies.append({
                    "timestamp": ev["timestamp"],
                    "threat_type": "ANTI-FORENSICS / EVIDENCE TAMPERING",
                    "severity": "CRITICAL",
                    "details": f"Audit logs were deliberately purged ({ev['description']}). Strongly indicates adversary covering tracks."
                })

        # 2. Brute-Force to Logon Success correlation
        failed_count = 0
        last_failed_user = None
        for ev in sorted_events:
            if ev["event_type"] == "Failed Logon":
                failed_count += 1
                last_failed_user = ev.get("details", {}).get("TargetUserName")
            elif ev["event_type"] == "Successful Logon" and failed_count >= 3:
                curr_user = ev.get("details", {}).get("TargetUserName")
                anomalies.append({
                    "timestamp": ev["timestamp"],
                    "threat_type": "POTENTIAL BRUTE FORCE SUCCESS",
                    "severity": "HIGH",
                    "details": f"{failed_count} consecutive failed logon attempts followed immediately by a successful logon for account '{curr_user}'."
                })
                failed_count = 0
            elif ev["event_type"] == "Successful Logon":
                failed_count = 0

        # 3. Off-hours activity detection (Between 01:00 and 05:00 UTC)
        for ev in sorted_events:
            try:
                dt = datetime.datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
                if dt.hour >= 1 and dt.hour <= 5 and ev["severity"] in ["Medium", "High", "Critical"]:
                    anomalies.append({
                        "timestamp": ev["timestamp"],
                        "threat_type": "SUSPICIOUS OFF-HOURS ACTIVITY",
                        "severity": "MEDIUM",
                        "details": f"High severity event executed during unusual early morning hours ({dt.strftime('%H:%M:%S')} UTC): {ev['description']}"
                    })
            except Exception:
                pass

        return anomalies

    def build_timeline(self, limit: int = 1000) -> Dict[str, Any]:
        """Return the compiled, chronologically sorted super-timeline and detected anomalies."""
        sorted_events = sorted(self.events, key=lambda x: x.get("timestamp") or "", reverse=True)
        anomalies = self.detect_anomalies()

        return {
            "total_events": len(sorted_events),
            "timeline": sorted_events[:limit],
            "anomalies_detected": anomalies,
            "anomalies_count": len(anomalies)
        }
