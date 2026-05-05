"""
WideWolf — Report Generator Module
Generates human-readable reports for non-security readers.
Includes hosts, ports, services, findings, anomalies, scan time, tool status, limitations.
"""
import os
from datetime import datetime
from .database import get_scan, get_scan_hosts, get_host_services, get_scan_findings, get_traffic_summary

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "reports")


def generate_report(scan_id: int) -> str:
    """Generate a full text report for a scan."""
    os.makedirs(REPORT_DIR, exist_ok=True)

    scan = get_scan(scan_id)
    if not scan:
        return ""

    hosts = get_scan_hosts(scan_id)
    findings = get_scan_findings(scan_id)
    traffic = get_traffic_summary(scan_id)

    report_file = os.path.join(REPORT_DIR, f"report_{scan['uuid']}.txt")

    lines = []
    lines.append("=" * 72)
    lines.append("  WIDEWOLF — NETWORK INTRUSION TESTING REPORT")
    lines.append("  ITP 258 — Network Intrusion Testing Appliance")
    lines.append("=" * 72)
    lines.append("")
    lines.append("  FOR EDUCATIONAL USE ONLY — Authorized Lab Environment")
    lines.append("")
    lines.append("-" * 72)
    lines.append("  SCAN SUMMARY")
    lines.append("-" * 72)
    lines.append(f"  Report Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Target           : {scan['target']}")
    lines.append(f"  Scan Type        : {scan['scan_type']}")
    lines.append(f"  Timing Profile   : {scan['timing']}")
    lines.append(f"  Status           : {scan['status'].upper()}")
    lines.append(f"  Started          : {scan['started_at'] or 'N/A'}")
    lines.append(f"  Completed        : {scan['completed_at'] or 'N/A'}")
    lines.append(f"  Duration         : {scan['duration_seconds'] or 0}s")
    lines.append(f"  Capture Interface: {scan['capture_interface'] or 'N/A'}")
    try:
        source = "AUTOMATED SYSTEM" if scan['auto_mode'] else "MANUAL"
    except (KeyError, IndexError):
        source = "MANUAL"
    lines.append(f"  Scan Source      : {source}")
    lines.append("")

    # Tool commands
    lines.append("-" * 72)
    lines.append("  TOOL COMMANDS EXECUTED")
    lines.append("-" * 72)
    lines.append(f"  Nmap   : {scan['nmap_command'] or 'N/A'}")
    lines.append(f"  tshark : {scan['tshark_command'] or 'N/A'}")
    lines.append("")

    # Hosts discovered
    lines.append("-" * 72)
    lines.append(f"  DISCOVERED HOSTS ({len(hosts)})")
    lines.append("-" * 72)
    if hosts:
        for h in hosts:
            lines.append(f"  [{h['state'].upper()}] {h['ip_address']}" +
                        (f" ({h['hostname']})" if h['hostname'] else "") +
                        (f" — OS: {h['os_guess']}" if h['os_guess'] else ""))
            services = get_host_services(scan_id, h['id'])
            if services:
                lines.append(f"        Open Ports: {len([s for s in services if s['state'] == 'open'])}")
                for svc in services:
                    if svc['state'] == 'open':
                        svc_info = f"{svc['service_name'] or 'unknown'}"
                        if svc['product']:
                            svc_info += f" ({svc['product']}"
                            if svc['version']:
                                svc_info += f" {svc['version']}"
                            svc_info += ")"
                        lines.append(f"          {svc['port']}/{svc['protocol']}  {svc['state']:8s}  {svc_info}")
            lines.append("")
    else:
        lines.append("  No hosts discovered.")
        lines.append("")

    # Security findings
    lines.append("-" * 72)
    lines.append(f"  SECURITY FINDINGS ({len(findings)})")
    lines.append("-" * 72)
    if findings:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f['severity'] or 'info').lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append(f"  Critical: {severity_counts['critical']}  |  High: {severity_counts['high']}  |  "
                    f"Medium: {severity_counts['medium']}  |  Low: {severity_counts['low']}  |  Info: {severity_counts['info']}")
        lines.append("")

        for f in findings:
            sev_tag = f"[{(f['severity'] or 'INFO').upper():8s}]"
            lines.append(f"  {sev_tag} {f['title']}")
            if f['description']:
                lines.append(f"             {f['description']}")
            if f['recommendation']:
                lines.append(f"             Recommendation: {f['recommendation']}")
            lines.append("")
    else:
        lines.append("  No findings generated.")
        lines.append("")

    # Traffic analysis
    lines.append("-" * 72)
    lines.append("  TRAFFIC ANALYSIS")
    lines.append("-" * 72)
    if traffic:
        lines.append(f"  Packets Captured  : {traffic['total_packets']}")
        lines.append(f"  Protocols         : {traffic['protocols']}")
        lines.append(f"  Cleartext Traffic : {'YES — WARNING' if traffic['cleartext_detected'] else 'None detected'}")
        lines.append(f"  Capture Duration  : {traffic['duration_seconds']}s")
        if traffic['summary_text']:
            lines.append(f"  Summary           : {traffic['summary_text']}")
    else:
        lines.append("  No traffic data available (tshark may not have captured packets).")
    lines.append("")

    # Limitations
    lines.append("-" * 72)
    lines.append("  LIMITATIONS AND NOTES")
    lines.append("-" * 72)
    lines.append("  - This scan was performed in an authorized lab environment only.")
    lines.append("  - Results are limited to the configured target scope.")
    lines.append("  - tshark captures are time-limited and may miss intermittent traffic.")
    lines.append("  - Vulnerability assessment is based on service detection, not exploitation.")
    lines.append("  - OS detection accuracy depends on target response characteristics.")
    lines.append("  - This tool is for educational purposes (ITP 258) and must not be used")
    lines.append("    on production networks without explicit written authorization.")
    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF REPORT — WideWolf v2.0")
    lines.append("=" * 72)

    report_text = "\n".join(lines)

    with open(report_file, "w") as f:
        f.write(report_text)

    return report_file


def get_report_path(scan_id: int) -> str:
    """Get the report file path for a scan."""
    scan = get_scan(scan_id)
    if not scan:
        return ""
    path = os.path.join(REPORT_DIR, f"report_{scan['uuid']}.txt")
    if os.path.exists(path):
        return path
    return ""
