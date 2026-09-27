import os
import sqlite3
import shutil
import tempfile
import datetime
from typing import Dict, Any, List, Optional

def webkit_time_to_datetime(webkit_timestamp: int) -> str:
    """Convert WebKit/Chrome timestamp (microseconds since 1601-01-01) to ISO UTC."""
    if not webkit_timestamp:
        return ""
    try:
        # Microseconds between 1601-01-01 and 1970-01-01 is 11644473600 * 1000000
        epoch_seconds = (webkit_timestamp / 1000000.0) - 11644473600
        if epoch_seconds < 0:
            return ""
        return datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc).isoformat()
    except Exception:
        return ""

def firefox_time_to_datetime(firefox_timestamp: int) -> str:
    """Convert Firefox PRTime (microseconds since 1970-01-01) to ISO UTC."""
    if not firefox_timestamp:
        return ""
    try:
        epoch_seconds = firefox_timestamp / 1000000.0
        return datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc).isoformat()
    except Exception:
        return ""

def parse_browser_database(db_path: str, max_records: int = 500) -> Dict[str, Any]:
    """
    Forensic parser for Chrome/Edge/Chromium 'History' or Firefox 'places.sqlite' database.
    Copies to temp location to avoid database locked errors when browser is active.
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Browser database not found: {db_path}")

    # Copy to temporary file to unlock
    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "browser_forensics_copy.db")
    shutil.copy2(db_path, temp_db)

    results = {
        "browser_family": "Unknown",
        "database_file": os.path.basename(db_path),
        "history": [],
        "downloads": [],
        "search_terms": [],
        "total_history_count": 0,
        "total_downloads_count": 0
    }

    try:
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check tables present
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row["name"] for row in cursor.fetchall()]

        if "urls" in tables and "visits" in tables:
            # Chromium (Chrome, Edge, Brave)
            results["browser_family"] = "Chromium (Chrome / Edge / Brave / Opera)"
            
            # History
            query = """
                SELECT id, url, title, visit_count, typed_count, last_visit_time 
                FROM urls 
                ORDER BY last_visit_time DESC 
                LIMIT ?
            """
            cursor.execute(query, (max_records,))
            for row in cursor.fetchall():
                ts_iso = webkit_time_to_datetime(row["last_visit_time"])
                results["history"].append({
                    "id": row["id"],
                    "url": row["url"],
                    "title": row["title"] or "(Untitled)",
                    "visit_count": row["visit_count"],
                    "typed_count": row["typed_count"],
                    "last_visit_time": ts_iso
                })
            results["total_history_count"] = len(results["history"])

            # Downloads
            if "downloads" in tables:
                dl_query = """
                    SELECT id, current_path, target_path, start_time, end_time, total_bytes, received_bytes, tab_url
                    FROM downloads
                    ORDER BY start_time DESC
                    LIMIT ?
                """
                try:
                    cursor.execute(dl_query, (max_records,))
                    for row in cursor.fetchall():
                        results["downloads"].append({
                            "id": row["id"],
                            "filename": os.path.basename(row["target_path"] or row["current_path"] or "Unknown"),
                            "path": row["target_path"] or row["current_path"],
                            "source_url": row["tab_url"] if "tab_url" in row.keys() else "",
                            "total_bytes": row["total_bytes"],
                            "start_time": webkit_time_to_datetime(row["start_time"]),
                            "end_time": webkit_time_to_datetime(row["end_time"])
                        })
                    results["total_downloads_count"] = len(results["downloads"])
                except Exception:
                    pass

            # Search terms
            if "keyword_search_terms" in tables:
                search_query = """
                    SELECT term FROM keyword_search_terms ORDER BY url_id DESC LIMIT 100
                """
                try:
                    cursor.execute(search_query)
                    results["search_terms"] = [r["term"] for r in cursor.fetchall()]
                except Exception:
                    pass

        elif "moz_places" in tables:
            # Firefox
            results["browser_family"] = "Mozilla Firefox"
            query = """
                SELECT id, url, title, visit_count, last_visit_date
                FROM moz_places
                WHERE last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT ?
            """
            cursor.execute(query, (max_records,))
            for row in cursor.fetchall():
                results["history"].append({
                    "id": row["id"],
                    "url": row["url"],
                    "title": row["title"] or "(Untitled)",
                    "visit_count": row["visit_count"],
                    "last_visit_time": firefox_time_to_datetime(row["last_visit_date"])
                })
            results["total_history_count"] = len(results["history"])

            # Firefox downloads
            if "moz_annos" in tables:
                pass

        conn.close()
    except Exception as e:
        results["error"] = str(e)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results

def discover_installed_browsers() -> List[Dict[str, Any]]:
    """
    Automatically search standard Windows / User directory locations for live browser artifact databases.
    """
    discovered = []
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    app_data = os.environ.get("APPDATA", "")

    candidates = [
        ("Google Chrome", os.path.join(local_app_data, r"Google\Chrome\User Data\Default\History")),
        ("Microsoft Edge", os.path.join(local_app_data, r"Microsoft\Edge\User Data\Default\History")),
        ("Brave Browser", os.path.join(local_app_data, r"BraveSoftware\Brave-Browser\User Data\Default\History")),
    ]

    for name, path in candidates:
        if os.path.exists(path):
            discovered.append({
                "browser": name,
                "history_path": path,
                "size_bytes": os.path.getsize(path),
                "modified": datetime.datetime.fromtimestamp(os.path.getmtime(path), tz=datetime.timezone.utc).isoformat()
            })

    # Firefox search in Roaming
    ff_profiles = os.path.join(app_data, r"Mozilla\Firefox\Profiles")
    if os.path.exists(ff_profiles):
        for profile in os.listdir(ff_profiles):
            places_path = os.path.join(ff_profiles, profile, "places.sqlite")
            if os.path.exists(places_path):
                discovered.append({
                    "browser": f"Firefox ({profile})",
                    "history_path": places_path,
                    "size_bytes": os.path.getsize(places_path),
                    "modified": datetime.datetime.fromtimestamp(os.path.getmtime(places_path), tz=datetime.timezone.utc).isoformat()
                })

    return discovered
