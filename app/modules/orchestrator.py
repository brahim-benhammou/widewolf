"""
WideWolf — Orchestrator Module
ITP 258 — Network Intrusion Testing Appliance
Controls all tool execution. Validates inputs, prevents duplicates,
enforces scope/timeouts, tracks state, handles errors, cleans up.
"""
import uuid
import time
import threading
import logging
import os
from datetime import datetime

def _now():
    """Return current local datetime as ISO string."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

from .nmap_scanner import validate_target, run_nmap, parse_nmap_xml, build_nmap_command, get_scan_types, kill_nmap_process
from .tshark_capture import run_tshark, analyze_capture, build_tshark_command, get_available_interfaces
from .database import (
    save_scan, update_scan_status, save_host, save_service,
    save_finding, save_traffic_summary, get_scan_by_uuid, reset_stale_scans
)
from .report_generator import generate_report

logger = logging.getLogger("widewolf.orchestrator")

# Global state
_active_scans = {}    # dict of {uuid: thread} for concurrent scans
_active_scan = None   # kept for backwards compat (last started)
_paused_scan = None   # uuid of paused scan
_paused_state = {}    # saved state for resume: {uuid: {target, scan_type, timing, iface, dur, scan_id}}
_cancel_flags = {}    # {uuid: bool} cancel signals per scan
_pause_flags = {}     # {uuid: bool} pause signals per scan
_cancel_flag = False  # legacy compat
_pause_flag = False   # legacy compat
MAX_CONCURRENT_SCANS = 5
SCAN_COOLDOWN_SECONDS = 5
_scan_lock = threading.Lock()
_scan_progress = {}
_last_scan_time = 0


# ─── Risky port database ───────────────────────────────────────────────────────
# Format: port -> (severity, title, description, recommendation)
RISKY_PORTS = {
    # Critical — cleartext credential services
    21:   ("critical", "FTP — Cleartext File Transfer",
           "FTP transmits credentials and data in cleartext. Any attacker on the network can capture usernames, passwords, and file contents.",
           "Disable FTP immediately. Use SFTP (SSH File Transfer Protocol) or SCP instead."),
    23:   ("critical", "Telnet — Cleartext Remote Shell",
           "Telnet transmits all data including passwords in cleartext. This is a severe security risk.",
           "Disable Telnet immediately. Use SSH for all remote administration."),
    69:   ("critical", "TFTP — Trivial File Transfer",
           "TFTP has no authentication and transmits data in cleartext.",
           "Disable TFTP unless absolutely required. Restrict with firewall rules."),
    512:  ("critical", "rexec — Remote Execution (cleartext)",
           "rexec transmits credentials in cleartext and allows remote command execution.",
           "Disable rexec. Use SSH instead."),
    513:  ("critical", "rlogin — Remote Login (cleartext)",
           "rlogin is an insecure legacy remote login protocol.",
           "Disable rlogin. Use SSH instead."),
    514:  ("critical", "rsh — Remote Shell (cleartext)",
           "rsh allows remote command execution without strong authentication.",
           "Disable rsh. Use SSH instead."),

    # High — attack surface services
    22:   ("medium", "SSH — Remote Shell Access",
           "SSH is open. Ensure it is properly hardened — disable root login, use key-based auth, restrict to lab network.",
           "Harden SSH: disable PasswordAuthentication, disable PermitRootLogin, restrict AllowUsers."),
    25:   ("medium", "SMTP — Mail Server",
           "SMTP server is exposed. May be used for spam relay or phishing if misconfigured.",
           "Restrict SMTP relay. Require authentication. Use TLS."),
    53:   ("info", "DNS — Name Resolution Service",
           "DNS server is running. Ensure it is not an open resolver.",
           "Restrict DNS to authorised clients only. Disable recursion for external clients."),
    80:   ("info", "HTTP — Unencrypted Web Server",
           "Web server running on port 80 (unencrypted HTTP).",
           "Redirect HTTP to HTTPS. Disable HTTP if not needed."),
    110:  ("medium", "POP3 — Cleartext Mail Retrieval",
           "POP3 may transmit email credentials in cleartext.",
           "Use POP3S (port 995) with TLS/SSL encryption."),
    135:  ("high", "Microsoft RPC — Remote Procedure Call",
           "Windows RPC endpoint mapper is exposed. Used by many Windows services and historically exploited (MS03-026, BlasterWorm).",
           "Block port 135 at the firewall. Restrict to internal hosts only."),
    137:  ("medium", "NetBIOS Name Service",
           "NetBIOS name service leaks information about the Windows workgroup/domain.",
           "Disable NetBIOS over TCP/IP if not required. Block at firewall."),
    138:  ("medium", "NetBIOS Datagram Service",
           "NetBIOS datagram service is exposed.",
           "Disable NetBIOS over TCP/IP if not required."),
    139:  ("high", "NetBIOS Session Service — SMB Legacy",
           "NetBIOS session service is used by legacy SMB. Historically exploited.",
           "Disable SMBv1. Block port 139 at the firewall."),
    143:  ("medium", "IMAP — Cleartext Mail Access",
           "IMAP may transmit email credentials in cleartext.",
           "Use IMAPS (port 993) with TLS/SSL encryption."),
    161:  ("medium", "SNMP — Network Management",
           "SNMP is exposed. Default community strings (public/private) allow full device information disclosure.",
           "Change default community strings. Use SNMPv3 with authentication. Restrict to management hosts."),
    389:  ("medium", "LDAP — Directory Service",
           "LDAP directory service is exposed. May leak user account information.",
           "Use LDAPS (port 636) with TLS. Restrict access to authorised hosts."),
    443:  ("info", "HTTPS — Encrypted Web Server",
           "HTTPS web server is running. Verify TLS configuration and certificate validity.",
           "Ensure TLS 1.2+ is used. Disable SSLv3 and TLS 1.0/1.1."),
    445:  ("high", "SMB — Windows File Sharing",
           "SMB (Server Message Block) is exposed. This is the attack vector for EternalBlue (MS17-010), WannaCry, and NotPetya ransomware.",
           "Block SMB at the firewall (ports 139, 445). Disable SMBv1. Apply MS17-010 patch."),
    1433: ("high", "MSSQL — Microsoft SQL Server",
           "SQL Server is directly accessible on the network. Database servers should never be publicly exposed.",
           "Restrict MSSQL to application server IPs only. Disable sa account. Use Windows Authentication."),
    1521: ("high", "Oracle Database",
           "Oracle database is directly accessible on the network.",
           "Restrict Oracle listener to application server IPs only."),
    2179: ("high", "Hyper-V RDP — Virtual Machine Remote Desktop",
           "Hyper-V Virtual Machine Connection port is exposed. Allows remote access to virtual machines.",
           "Restrict Hyper-V RDP access to authorised management hosts only."),
    3306: ("high", "MySQL — Database Server",
           "MySQL database is directly accessible on the network.",
           "Restrict MySQL to localhost or application server IPs. Never expose databases to the network."),
    3389: ("high", "RDP — Windows Remote Desktop",
           "Remote Desktop Protocol is exposed. RDP is a primary target for brute-force attacks, credential stuffing, and exploitation (BlueKeep CVE-2019-0708).",
           "Restrict RDP to VPN or management network only. Enable Network Level Authentication (NLA). Apply all Windows patches."),
    5040: ("info", "Unknown Windows Service (5040)",
           "Port 5040 is open. This is commonly used by Windows 10 Mobile Device Management or background services.",
           "Identify the service using: netstat -ano | findstr 5040. Disable if not required."),
    5432: ("high", "PostgreSQL — Database Server",
           "PostgreSQL database is directly accessible on the network.",
           "Restrict PostgreSQL to localhost or application server IPs only."),
    5900: ("high", "VNC — Virtual Network Computing",
           "VNC remote desktop is exposed. VNC often uses weak authentication and transmits data with minimal encryption.",
           "Disable VNC or restrict access. Use SSH tunneling for VNC access."),
    5931: ("info", "Unknown Service (5931)",
           "Port 5931 is open. This may be a custom application or background service.",
           "Identify the service and disable if not required."),
    6379: ("critical", "Redis — In-Memory Database",
           "Redis is exposed without authentication by default. Allows full data access and remote code execution.",
           "Bind Redis to localhost only. Enable authentication. Never expose Redis to the network."),
    7680: ("info", "Windows Update Delivery Optimisation (7680)",
           "Windows Update Delivery Optimisation (WUDO) peer-to-peer port is open.",
           "This is normal for Windows 10/11. Restrict to local subnet if not needed externally."),
    8080: ("info", "HTTP Alternate — Web Server",
           "Alternate HTTP port 8080 is open. May be a development server or proxy.",
           "Verify this is an authorised service. Apply same hardening as port 80."),
    8443: ("info", "HTTPS Alternate — Web Server",
           "Alternate HTTPS port 8443 is open.",
           "Verify this is an authorised service. Check TLS configuration."),
    27017: ("critical", "MongoDB — Database Server",
            "MongoDB is exposed. Default MongoDB installations have no authentication.",
            "Enable MongoDB authentication. Bind to localhost only. Never expose to the network."),
}


def get_scan_progress(scan_uuid: str) -> dict:
    """Return current progress dict for a scan, including target."""
    prog = dict(_scan_progress.get(scan_uuid, {"phase": "unknown", "percent": 0, "message": "No data"}))
    # Include target from paused_state or active_scans state
    if "target" not in prog:
        state = _paused_state.get(scan_uuid)
        if state:
            prog["target"] = state.get("target", "")
        else:
            # Try to get from active scan state
            prog["target"] = ""
    return prog


def _update_progress(scan_uuid, phase, percent, message):
    """Update scan progress while preserving the target field."""
    existing = _scan_progress.get(scan_uuid, {})
    _scan_progress[scan_uuid] = {
        "phase": phase,
        "percent": percent,
        "message": message,
        "target": existing.get("target", "")
    }


def is_scan_running() -> bool:
    """Check if a scan is currently active."""
    return len(_active_scans) > 0


def _ping_check(target: str) -> bool:
    """Quick ping check to see if host is reachable. Returns True if reachable."""
    # Strip CIDR notation for ping
    host = target.split('/')[0]
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def start_scan(target: str, scan_type: str, timing: str, capture_iface: str, capture_duration: int) -> dict:
    """Start a new scan — validates everything first."""
    global _active_scan, _last_scan_time

    # Validate target
    valid, reason = validate_target(target)
    if not valid:
        return {"success": False, "error": f"Target rejected: {reason}"}

    with _scan_lock:
        if len(_active_scans) >= MAX_CONCURRENT_SCANS:
            return {"success": False, "error": f"Maximum {MAX_CONCURRENT_SCANS} concurrent scans reached. Wait for one to complete."}

        valid_types = [st["id"] for st in get_scan_types()]
        if scan_type not in valid_types:
            return {"success": False, "error": f"Invalid scan type: {scan_type}"}

        available_ifaces = get_available_interfaces()
        if capture_iface not in available_ifaces:
            capture_iface = available_ifaces[0]

        capture_duration = min(max(int(capture_duration), 5), 120)
        scan_uuid = uuid.uuid4().hex[:12]
        _active_scan = scan_uuid
        _active_scans[scan_uuid] = None
        _cancel_flags[scan_uuid] = False
        _pause_flags[scan_uuid] = False

    scan_id = save_scan(scan_uuid, target, scan_type, timing, capture_iface, capture_duration)

    # Pre-scan connectivity check (non-blocking, just informational)
    ping_reachable = _ping_check(target)

    thread = threading.Thread(
        target=_execute_scan,
        args=(scan_id, scan_uuid, target, scan_type, timing, capture_iface, capture_duration),
        daemon=True
    )
    thread.start()
    _active_scans[scan_uuid] = thread

    msg = "Scan started"
    if not ping_reachable:
        msg = "Scan started (note: host did not respond to ping — it may have ICMP blocked, scan will still proceed with -Pn)"
    return {"success": True, "scan_uuid": scan_uuid, "scan_id": scan_id, "message": msg, "ping_reachable": ping_reachable}


def _execute_scan(scan_id, scan_uuid, target, scan_type, timing, capture_iface, capture_duration):
    """Execute the full scan pipeline in background."""
    global _last_scan_time, _paused_state
    start_time = time.time()
    # Save state for potential resume
    _paused_state[scan_uuid] = {
        "scan_id": scan_id, "target": target, "scan_type": scan_type,
        "timing": timing, "iface": capture_iface, "dur": capture_duration
    }

    try:
        _scan_progress[scan_uuid] = {"phase": "nmap", "percent": 5, "message": "Initialising scan...", "target": target}
        update_scan_status(scan_id, "running", started_at=_now())

        # Phase 1: Nmap
        _update_progress(scan_uuid, "nmap", 15, "Running Nmap network scan...")
        nmap_result = run_nmap(target, scan_type, timing, scan_uuid)
        update_scan_status(scan_id, "running", nmap_command=nmap_result["command"])

        if not nmap_result["success"]:
            err_detail = nmap_result.get('error', 'Unknown')
            stderr_info = nmap_result.get('stderr', '')
            if stderr_info:
                err_detail += f" | stderr: {stderr_info[:200]}"
            _fail_scan(scan_id, scan_uuid, f"Nmap failed: {err_detail}", start_time)
            return

        # Log nmap output for debugging
        logger.info(f"Nmap scan {scan_uuid} completed. stdout: {nmap_result.get('stdout', '')[:200]}")
        logger.info(f"Nmap stderr: {nmap_result.get('stderr', '')[:200]}")

        _update_progress(scan_uuid, "nmap", 45, "Nmap complete. Parsing results...")

        # Phase 2: Parse nmap XML
        parsed = parse_nmap_xml(nmap_result["output_file"])
        _store_nmap_results(scan_id, parsed)

        # Phase 3: tshark capture (run in parallel with analysis)
        _update_progress(scan_uuid, "tshark", 55, f"Capturing network traffic ({capture_duration}s)...")
        tshark_result = run_tshark(capture_iface, capture_duration, target, scan_uuid)
        update_scan_status(scan_id, "running", tshark_command=tshark_result["command"])

        # Phase 4: Analyse traffic
        _update_progress(scan_uuid, "analysis", 75, "Analysing traffic patterns...")
        traffic_data = None
        if tshark_result["success"]:
            traffic = analyze_capture(tshark_result["capture_file"])
            traffic_data = traffic
            save_traffic_summary(
                scan_id,
                tshark_result["capture_file"],
                traffic["total_packets"],
                str(traffic["protocols"]),
                1 if traffic["cleartext_detected"] else 0,
                str(traffic.get("unexpected_traffic", [])),
                tshark_result["duration"],
                traffic["summary_text"]
            )

        # Phase 5: Generate findings from real data
        _update_progress(scan_uuid, "findings", 85, "Generating security findings...")
        _generate_findings(scan_id, parsed, tshark_result if tshark_result["success"] else None, traffic_data)

        # Phase 6: Generate report
        _update_progress(scan_uuid, "report", 92, "Generating report...")
        generate_report(scan_id)

        duration = time.time() - start_time
        update_scan_status(scan_id, "completed",
                           completed_at=_now(),
                           duration_seconds=round(duration, 1))
        _update_progress(scan_uuid, "done", 100, "Scan complete")

    except Exception as e:
        logger.exception("Scan execution error")
        _fail_scan(scan_id, scan_uuid, str(e)[:500], start_time)
    finally:
        with _scan_lock:
            # Only clean up THIS scan's state — never touch other concurrent scans
            _active_scans.pop(scan_uuid, None)
            _cancel_flags.pop(scan_uuid, None)
            _pause_flags.pop(scan_uuid, None)
            _paused_state.pop(scan_uuid, None)
            _last_scan_time = time.time()


def _fail_scan(scan_id, scan_uuid, error_msg, start_time):
    duration = time.time() - start_time
    update_scan_status(scan_id, "failed",
                       error_message=error_msg,
                       completed_at=_now(),
                       duration_seconds=round(duration, 1))
    _scan_progress[scan_uuid] = {"phase": "error", "percent": 0, "message": error_msg}


def _store_nmap_results(scan_id, parsed):
    """Store parsed nmap results in database."""
    for host in parsed.get("hosts", []):
        host_id = save_host(
            scan_id,
            host["ip"],
            host.get("hostname"),
            host.get("os"),
            host.get("state", "up")
        )
        for port in host.get("ports", []):
            save_service(
                scan_id, host_id,
                port["port"], port["protocol"], port["state"],
                port["service"], port.get("product"), port.get("version"), port.get("extra")
            )


def _generate_findings(scan_id, parsed, tshark_result, traffic_data):
    """Generate real security findings from nmap and tshark data."""
    from .database import get_db

    for host in parsed.get("hosts", []):
        conn = get_db()
        host_row = conn.execute(
            "SELECT id FROM hosts WHERE scan_id=? AND ip_address=?",
            (scan_id, host["ip"])
        ).fetchone()
        conn.close()
        host_id = host_row["id"] if host_row else None

        open_ports = [p for p in host.get("ports", []) if "open" in p.get("state", "")]

        for port in open_ports:
            port_num = port["port"]
            service_name = port.get("service", "")
            product = port.get("product", "")
            version = port.get("version", "")

            if port_num in RISKY_PORTS:
                sev, title, desc, rec = RISKY_PORTS[port_num]
                full_desc = f"{desc}"
                if product or version:
                    full_desc += f" Detected: {product} {version}".strip()
                save_finding(scan_id, sev, f"{title} on {host['ip']}:{port_num}",
                             full_desc, rec, host_id, port_num, service_name)
            else:
                # Generic open port finding
                svc_str = service_name or "unknown"
                if product:
                    svc_str += f" ({product}"
                    if version:
                        svc_str += f" {version}"
                    svc_str += ")"
                save_finding(
                    scan_id, "info",
                    f"Open port {port_num}/{port['protocol']} on {host['ip']}",
                    f"Service: {svc_str}. Review whether this port needs to be open.",
                    "Disable the service if not required. Apply firewall rules to restrict access.",
                    host_id, port_num, service_name
                )

            # NSE script findings (vuln scan results)
            for script in port.get("scripts", []):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                if not script_output:
                    continue
                # Determine severity from script name
                if any(x in script_id for x in ["vuln", "exploit", "backdoor", "malware"]):
                    script_sev = "critical"
                elif any(x in script_id for x in ["brute", "auth", "default"]):
                    script_sev = "high"
                else:
                    script_sev = "medium"
                save_finding(
                    scan_id, script_sev,
                    f"NSE Script: {script_id} on {host['ip']}:{port_num}",
                    script_output[:800],
                    "Review the script output and apply recommended patches or configuration changes.",
                    host_id, port_num, service_name
                )

        # Host-level script findings
        for script in host.get("scripts", []):
            script_id = script.get("id", "")
            script_output = script.get("output", "")
            if script_output:
                save_finding(
                    scan_id, "medium",
                    f"Host script: {script_id} on {host['ip']}",
                    script_output[:800],
                    "Review this finding and apply recommended remediation.",
                    host_id, None, None
                )

        # Summary finding: open port count
        if len(open_ports) > 10:
            save_finding(
                scan_id, "medium",
                f"Large attack surface on {host['ip']}",
                f"{len(open_ports)} open ports detected. A large number of open ports increases the attack surface.",
                "Disable all services that are not required. Apply the principle of least privilege.",
                host_id, None, None
            )

    # Traffic-based findings
    if traffic_data and traffic_data.get("cleartext_detected"):
        save_finding(
            scan_id, "high",
            "Cleartext network traffic detected",
            f"Unencrypted protocols observed during traffic capture: {', '.join(traffic_data.get('cleartext_services', []))}. "
            f"Credentials and data transmitted over these protocols can be intercepted by any attacker on the network.",
            "Migrate all cleartext services to encrypted alternatives: SFTP instead of FTP, SSH instead of Telnet, HTTPS instead of HTTP.",
            None, None, None
        )


def cancel_active_scan(scan_uuid=None):
    """Cancel a specific scan or all running scans."""
    global _active_scan, _cancel_flags, _paused_scan, _paused_state, _active_scans
    with _scan_lock:
        if scan_uuid:
            if scan_uuid in _active_scans:
                _cancel_flags[scan_uuid] = True
                _active_scans.pop(scan_uuid, None)
                _scan_progress[scan_uuid] = {"phase": "cancelled", "percent": 0, "message": "Scan cancelled by user"}
                if _active_scan == scan_uuid:
                    _active_scan = None
                return True
            if scan_uuid == _paused_scan:
                _paused_scan = None
                _paused_state.pop(scan_uuid, None)
                _scan_progress[scan_uuid] = {"phase": "cancelled", "percent": 0, "message": "Scan cancelled by user"}
                return True
            return False
        else:
            cancelled = False
            for u in list(_active_scans.keys()):
                _cancel_flags[u] = True
                _scan_progress[u] = {"phase": "cancelled", "percent": 0, "message": "Scan cancelled by user"}
                cancelled = True
            _active_scans.clear()
            _active_scan = None
            if _paused_scan:
                u = _paused_scan
                _paused_scan = None
                _paused_state.pop(u, None)
                _scan_progress[u] = {"phase": "cancelled", "percent": 0, "message": "Scan cancelled by user"}
                cancelled = True
            return cancelled

def get_active_scans():
    """Return list of all active scan uuids with their progress."""
    result = []
    for u in list(_active_scans.keys()):
        prog = _scan_progress.get(u, {})
        target = prog.get("target") or _paused_state.get(u, {}).get("target", u[:8]+"...")
        result.append({"scan_uuid": u, "target": target, "progress": prog})
    return result


# ─── Automated Scheduler ──────────────────────────────────────────────────────

_auto_thread = None
_auto_running = False
_auto_status = {"state": "stopped", "runs": 0, "last_run": None, "current_scan_uuid": None, "next_run_in": 0}


def start_auto_scheduler(target, scan_type, timing, iface, capture_duration, interval):
    """Start the automated scanning loop."""
    global _auto_thread, _auto_running, _auto_status
    if _auto_running:
        return {"success": False, "error": "Automated scanner is already running"}

    _auto_running = True
    _auto_status = {"state": "running", "runs": 0, "last_run": None, "current_scan_uuid": None, "next_run_in": 0,
                    "target": target, "scan_type": scan_type, "timing": timing, "iface": iface,
                    "capture_duration": capture_duration, "interval": interval}

    _auto_thread = threading.Thread(
        target=_auto_loop,
        args=(target, scan_type, timing, iface, capture_duration, interval),
        daemon=True
    )
    _auto_thread.start()
    return {"success": True, "message": "Automated scanner started"}


def stop_auto_scheduler():
    """Stop the automated scanning loop."""
    global _auto_running, _auto_status
    _auto_running = False
    _auto_status["state"] = "stopped"
    return {"success": True, "message": "Automated scanner stopped"}


def get_auto_status():
    """Get current automated scanner status."""
    return dict(_auto_status)


def _auto_loop(target, scan_type, timing, iface, capture_duration, interval):
    """Main automated scan loop — runs until stopped."""
    global _auto_running, _auto_status
    from .database import save_scan_auto, update_scan_status

    while _auto_running:
        # Start a scan using the same pipeline as manual scans
        scan_uuid = uuid.uuid4().hex[:12]
        _auto_status["current_scan_uuid"] = scan_uuid
        _auto_status["state"] = "scanning"

        scan_id = save_scan_auto(scan_uuid, target, scan_type, timing, iface, capture_duration)

        # Register in active scans
        with _scan_lock:
            _active_scans[scan_uuid] = None
            _cancel_flags[scan_uuid] = False
            _pause_flags[scan_uuid] = False

        # Execute scan in current thread (blocking — we want sequential)
        _execute_scan(scan_id, scan_uuid, target, scan_type, timing, iface, capture_duration)

        _auto_status["runs"] += 1
        _auto_status["last_run"] = _now()
        _auto_status["current_scan_uuid"] = None

        if not _auto_running:
            break

        # Wait the interval, checking every second if we should stop
        _auto_status["state"] = "waiting"
        for i in range(int(interval)):
            if not _auto_running:
                break
            _auto_status["next_run_in"] = int(interval) - i
            time.sleep(1)

        _auto_status["next_run_in"] = 0

    _auto_status["state"] = "stopped"
