"""
WideWolf — Database Module
SQLite database for scans, hosts, services, findings, and traffic summaries.
"""
import sqlite3
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "widewolf.db")


def get_db():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize database schema."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'service',
            timing TEXT NOT NULL DEFAULT 'normal',
            status TEXT NOT NULL DEFAULT 'pending',
            nmap_command TEXT,
            tshark_command TEXT,
            capture_interface TEXT,
            capture_duration INTEGER DEFAULT 30,
            started_at TEXT,
            completed_at TEXT,
            duration_seconds REAL,
            error_message TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            hostname TEXT,
            os_guess TEXT,
            state TEXT DEFAULT 'up',
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            state TEXT DEFAULT 'open',
            service_name TEXT,
            product TEXT,
            version TEXT,
            extra_info TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            host_id INTEGER,
            severity TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            description TEXT,
            recommendation TEXT,
            port INTEGER,
            service TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS traffic_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            capture_file TEXT,
            total_packets INTEGER DEFAULT 0,
            protocols TEXT,
            cleartext_detected INTEGER DEFAULT 0,
            unexpected_traffic TEXT,
            duration_seconds REAL,
            summary_text TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS discovered_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            hostname TEXT,
            discovered_at TEXT DEFAULT (datetime('now','localtime')),
            last_seen TEXT DEFAULT (datetime('now','localtime')),
            hidden INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    # Auto-migrate: add hidden column if it doesn't exist (for existing databases)
    try:
        conn.execute("ALTER TABLE discovered_hosts ADD COLUMN hidden INTEGER DEFAULT 0")
    except Exception:
        pass  # Column already exists
    conn.commit()
    conn.close()


def save_scan(uuid, target, scan_type, timing, capture_interface, capture_duration):
    """Create a new scan record."""
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (uuid, target, scan_type, timing, status, capture_interface, capture_duration, created_at) "
        "VALUES (?, ?, ?, ?, 'running', ?, ?, datetime('now','localtime'))",
        (uuid, target, scan_type, timing, capture_interface, capture_duration)
    )
    conn.commit()
    scan_id = conn.execute("SELECT id FROM scans WHERE uuid=?", (uuid,)).fetchone()["id"]
    conn.close()
    return scan_id


def update_scan_status(scan_id, status, **kwargs):
    """Update scan status and optional fields."""
    conn = get_db()
    sets = ["status=?"]
    vals = [status]
    for k, v in kwargs.items():
        sets.append(f"{k}=?")
        vals.append(v)
    vals.append(scan_id)
    conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id=?", vals)
    conn.commit()
    conn.close()


def save_host(scan_id, ip_address, hostname=None, os_guess=None, state="up"):
    """Save a discovered host."""
    conn = get_db()
    conn.execute(
        "INSERT INTO hosts (scan_id, ip_address, hostname, os_guess, state) VALUES (?, ?, ?, ?, ?)",
        (scan_id, ip_address, hostname, os_guess, state)
    )
    conn.commit()
    host_id = conn.execute(
        "SELECT id FROM hosts WHERE scan_id=? AND ip_address=? ORDER BY id DESC LIMIT 1",
        (scan_id, ip_address)
    ).fetchone()["id"]
    conn.close()
    return host_id


def save_service(scan_id, host_id, port, protocol, state, service_name, product=None, version=None, extra_info=None):
    """Save a discovered service."""
    conn = get_db()
    conn.execute(
        "INSERT INTO services (scan_id, host_id, port, protocol, state, service_name, product, version, extra_info) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, host_id, port, protocol, state, service_name, product, version, extra_info)
    )
    conn.commit()
    conn.close()


def save_finding(scan_id, severity, title, description, recommendation, host_id=None, port=None, service=None):
    """Save a security finding."""
    conn = get_db()
    conn.execute(
        "INSERT INTO findings (scan_id, host_id, severity, title, description, recommendation, port, service) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, host_id, severity, title, description, recommendation, port, service)
    )
    conn.commit()
    conn.close()


def save_traffic_summary(scan_id, capture_file, total_packets, protocols, cleartext_detected, unexpected_traffic, duration_seconds, summary_text):
    """Save traffic capture summary."""
    conn = get_db()
    conn.execute(
        "INSERT INTO traffic_summaries (scan_id, capture_file, total_packets, protocols, cleartext_detected, unexpected_traffic, duration_seconds, summary_text) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, capture_file, total_packets, protocols, cleartext_detected, unexpected_traffic, duration_seconds, summary_text)
    )
    conn.commit()
    conn.close()


def get_scan(scan_id):
    """Get a single scan by ID."""
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return row


def get_scan_by_uuid(uuid):
    """Get a scan by UUID."""
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE uuid=?", (uuid,)).fetchone()
    conn.close()
    return row


def list_scans(limit=50):
    """List recent scans."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_scan_hosts(scan_id):
    """Get all hosts for a scan."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM hosts WHERE scan_id=? ORDER BY ip_address", (scan_id,)).fetchall()
    conn.close()
    return rows


def get_host_services(scan_id, host_id=None):
    """Get services for a scan or specific host."""
    conn = get_db()
    if host_id:
        rows = conn.execute("SELECT * FROM services WHERE scan_id=? AND host_id=? ORDER BY port", (scan_id, host_id)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM services WHERE scan_id=? ORDER BY port", (scan_id,)).fetchall()
    conn.close()
    return rows


def get_scan_findings(scan_id):
    """Get findings for a scan."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
        (scan_id,)
    ).fetchall()
    conn.close()
    return rows


def get_traffic_summary(scan_id):
    """Get traffic summary for a scan."""
    conn = get_db()
    row = conn.execute("SELECT * FROM traffic_summaries WHERE scan_id=?", (scan_id,)).fetchone()
    conn.close()
    return row


def get_scan_stats():
    """Get overall scan statistics."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    completed = conn.execute("SELECT COUNT(*) FROM scans WHERE status='completed'").fetchone()[0]
    hosts_found = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM hosts").fetchone()[0]
    open_ports = conn.execute("SELECT COUNT(*) FROM services WHERE state='open'").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0]
    conn.close()
    return {
        "total_scans": total,
        "completed_scans": completed,
        "hosts_discovered": hosts_found,
        "open_ports": open_ports,
        "critical_findings": critical,
        "high_findings": high,
        "total_reports": completed,
    }


def delete_scan(scan_id):
    """Delete a scan and all related data (cascade)."""
    conn = get_db()
    conn.execute("DELETE FROM traffic_summaries WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM services WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM hosts WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()


def get_setting(key, default=None):
    """Get a setting value."""
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    """Set a setting value."""
    conn = get_db()
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now','localtime')) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, str(value))
    )
    conn.commit()
    conn.close()


def get_all_settings():
    """Get all settings as a dict."""
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


def reset_stale_scans():
    """Reset any scans stuck in running state (from crashes)."""
    conn = get_db()
    conn.execute("UPDATE scans SET status='failed', error_message='Process interrupted' WHERE status='running'")
    conn.commit()
    conn.close()


def _migrate_auto_mode():
    """Add auto_mode column to scans table if missing."""
    conn = get_db()
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    if "auto_mode" not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN auto_mode INTEGER DEFAULT 0")
        conn.commit()
    conn.close()


def save_scan_auto(uuid, target, scan_type, timing, capture_interface, capture_duration):
    """Create a new scan record marked as automated."""
    _migrate_auto_mode()
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (uuid, target, scan_type, timing, status, capture_interface, capture_duration, auto_mode, created_at) "
        "VALUES (?, ?, ?, ?, 'running', ?, ?, 1, datetime('now','localtime'))",
        (uuid, target, scan_type, timing, capture_interface, capture_duration)
    )
    conn.commit()
    scan_id = conn.execute("SELECT id FROM scans WHERE uuid=?", (uuid,)).fetchone()["id"]
    conn.close()
    return scan_id


def list_auto_scans(limit=50):
    """List automated scans only."""
    _migrate_auto_mode()
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans WHERE auto_mode=1 ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def list_manual_scans(limit=50):
    """List manual scans only."""
    _migrate_auto_mode()
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans WHERE auto_mode=0 OR auto_mode IS NULL ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def save_discovered_host(ip_address, hostname=""):
    """Save or update a discovered host. Does NOT unhide hidden hosts."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO discovered_hosts (ip_address, hostname, discovered_at, last_seen, hidden) "
            "VALUES (?, ?, datetime('now','localtime'), datetime('now','localtime'), 0)",
            (ip_address, hostname)
        )
    except sqlite3.IntegrityError:
        # Host already exists — update last_seen and hostname but DO NOT touch hidden flag
        conn.execute(
            "UPDATE discovered_hosts SET last_seen=datetime('now','localtime'), hostname=? WHERE ip_address=?",
            (hostname, ip_address)
        )
    conn.commit()
    conn.close()


def get_discovered_hosts():
    """Get all non-hidden discovered hosts, ordered by most recently seen."""
    conn = get_db()
    rows = conn.execute(
        "SELECT ip_address, hostname, discovered_at, last_seen FROM discovered_hosts "
        "WHERE hidden=0 ORDER BY last_seen DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def hide_discovered_host(ip_address):
    """Persistently hide a host — survives page navigation and server restarts."""
    conn = get_db()
    conn.execute("UPDATE discovered_hosts SET hidden=1 WHERE ip_address=?", (ip_address,))
    conn.commit()
    conn.close()


def unhide_discovered_host(ip_address):
    """Unhide a previously hidden host."""
    conn = get_db()
    conn.execute("UPDATE discovered_hosts SET hidden=0 WHERE ip_address=?", (ip_address,))
    conn.commit()
    conn.close()


def clear_discovered_hosts():
    """Clear all non-hidden discovered hosts."""
    conn = get_db()
    conn.execute("DELETE FROM discovered_hosts WHERE hidden=0")
    conn.commit()
    conn.close()


def get_latest_scan_hosts():
    """Get hosts from the most recent completed scan (not from discovered_hosts table)."""
    conn = get_db()
    # Get the latest completed scan
    latest_scan = conn.execute(
        "SELECT id FROM scans WHERE status='completed' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    if not latest_scan:
        conn.close()
        return []
    scan_id = latest_scan['id']
    # Get all hosts from that scan
    rows = conn.execute(
        "SELECT DISTINCT ip_address, hostname FROM hosts WHERE scan_id=? ORDER BY ip_address",
        (scan_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
