"""
WideWolf — tshark Capture Module
ITP 258 — Network Intrusion Testing Appliance
Passive traffic capture with real interface detection, duration/size limits,
cleartext protocol detection, and protocol distribution analysis.
"""
import subprocess
import os
import shutil
from typing import Dict, List

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "captures")
MAX_DURATION = 120   # seconds — hard cap
MAX_FILESIZE_MB = 50  # MB — hard cap


def get_available_interfaces() -> List[str]:
    """Get real network interfaces from the system, preferring eth0/wlan0."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                iface = parts[1].strip().split("@")[0].strip()
                if iface and iface not in ("lo", "") and not iface.startswith("docker") and not iface.startswith("br-"):
                    interfaces.append(iface)
    except Exception:
        pass

    if not interfaces:
        interfaces = ["eth0"]

    # Put eth0 first if present (Raspberry Pi wired interface)
    if "eth0" in interfaces:
        interfaces.remove("eth0")
        interfaces.insert(0, "eth0")
    elif "wlan0" in interfaces:
        interfaces.remove("wlan0")
        interfaces.insert(0, "wlan0")

    return interfaces


def build_tshark_command(interface: str, duration: int, target: str, output_file: str) -> str:
    """Build a real tshark capture command with safety limits."""
    duration = min(max(int(duration), 5), MAX_DURATION)

    # BPF capture filter — only traffic to/from the target
    if "/" in target:
        capture_filter = f"net {target}"
    else:
        capture_filter = f"host {target}"

    # tshark needs to run as root for raw capture — use sudo
    cmd = (
        f"sudo tshark -i {interface} "
        f"-a duration:{duration} "
        f"-a filesize:{MAX_FILESIZE_MB * 1024} "
        f"-f \"{capture_filter}\" "
        f"-w {output_file} "
        f"-q"
    )
    return cmd


def run_tshark(interface: str, duration: int, target: str, scan_uuid: str) -> Dict:
    """Execute tshark capture. Returns result dict with success flag."""
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    output_file = os.path.join(CAPTURE_DIR, f"capture_{scan_uuid}.pcap")

    duration = min(max(int(duration), 5), MAX_DURATION)
    # Add buffer for tshark startup/shutdown
    timeout = duration + 20

    result = {
        "command": "",
        "capture_file": output_file,
        "success": False,
        "error": None,
        "duration": duration,
    }

    # Check tshark is installed
    if not shutil.which("tshark"):
        result["command"] = "tshark (not found)"
        result["error"] = "tshark not installed. Run: sudo apt install tshark"
        return result

    cmd_str = build_tshark_command(interface, duration, target, output_file)
    result["command"] = cmd_str

    try:
        proc = subprocess.run(
            ["bash", "-c", cmd_str],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            result["success"] = True
        else:
            stderr = proc.stderr.strip() if proc.stderr else ""
            # Common permission error — try without sudo as fallback
            if "permission" in stderr.lower() or "operation not permitted" in stderr.lower():
                result["error"] = "Permission denied — ensure tshark has capture permissions (sudo usermod -aG wireshark $USER)"
            elif "no such device" in stderr.lower() or "doesn't exist" in stderr.lower():
                result["error"] = f"Interface '{interface}' not found. Check available interfaces."
            else:
                result["error"] = stderr[:300] or "No packets captured (target may be unreachable)"

    except subprocess.TimeoutExpired:
        # Partial capture is still useful
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            result["success"] = True
            result["error"] = f"Capture stopped after {timeout}s — partial results saved"
        else:
            result["error"] = f"Capture timed out with no data"
    except Exception as e:
        result["error"] = str(e)[:300]

    return result


def analyze_capture(capture_file: str) -> Dict:
    """Analyze a pcap file — real protocol distribution and cleartext detection."""
    summary = {
        "total_packets": 0,
        "protocols": {},
        "cleartext_detected": False,
        "cleartext_services": [],
        "unexpected_traffic": [],
        "top_talkers": [],
        "summary_text": "No capture data.",
    }

    if not os.path.exists(capture_file):
        return summary

    if not shutil.which("tshark"):
        summary["summary_text"] = "tshark not available for analysis."
        return summary

    try:
        # Total packet count
        r = subprocess.run(
            ["tshark", "-r", capture_file, "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in r.stdout.strip().split("\n") if l.strip()]
        summary["total_packets"] = len(lines)

        if summary["total_packets"] == 0:
            summary["summary_text"] = "No packets captured — target may be unreachable or no traffic during capture window."
            return summary

        # Protocol distribution using tshark statistics
        r = subprocess.run(
            ["tshark", "-r", capture_file, "-T", "fields", "-e", "frame.protocols"],
            capture_output=True, text=True, timeout=30
        )
        proto_counts = {}
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            # Get the highest-level protocol in the stack
            protos = [p.upper() for p in line.split(":") if p]
            # Prefer application-layer protocols
            app_protos = ["HTTP", "FTP", "TELNET", "SSH", "SMTP", "DNS",
                          "DHCP", "SNMP", "RDP", "SMB", "SMB2", "NBSS",
                          "TLS", "SSL", "IMAP", "POP", "LDAP", "KERBEROS"]
            top_proto = "OTHER"
            for ap in reversed(protos):
                if any(ap.startswith(x) for x in app_protos):
                    top_proto = ap
                    break
            else:
                if protos:
                    top_proto = protos[-1]
            proto_counts[top_proto] = proto_counts.get(top_proto, 0) + 1
        summary["protocols"] = proto_counts

        # Cleartext protocol detection
        cleartext_check = {
            "HTTP":   "http",
            "FTP":    "ftp",
            "TELNET": "telnet",
            "SMTP":   "smtp",
            "POP":    "pop",
            "IMAP":   "imap",
        }
        for label, display_filter in cleartext_check.items():
            r2 = subprocess.run(
                ["tshark", "-r", capture_file, "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=15
            )
            if r2.stdout.strip():
                summary["cleartext_detected"] = True
                if label not in summary["cleartext_services"]:
                    summary["cleartext_services"].append(label)

        # Top talkers (source IPs by packet count)
        r3 = subprocess.run(
            ["tshark", "-r", capture_file, "-T", "fields", "-e", "ip.src"],
            capture_output=True, text=True, timeout=20
        )
        src_counts = {}
        for line in r3.stdout.strip().split("\n"):
            ip = line.strip()
            if ip:
                src_counts[ip] = src_counts.get(ip, 0) + 1
        top = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        summary["top_talkers"] = [{"ip": ip, "packets": cnt} for ip, cnt in top]

        # Build summary text
        parts = [f"Packets captured: {summary['total_packets']}"]
        if summary["protocols"]:
            top5 = sorted(summary["protocols"].items(), key=lambda x: x[1], reverse=True)[:5]
            parts.append("Protocols: " + ", ".join(f"{k}({v})" for k, v in top5))
        if summary["cleartext_detected"]:
            parts.append(f"CLEARTEXT DETECTED: {', '.join(summary['cleartext_services'])}")
        if summary["top_talkers"]:
            parts.append("Top talker: " + summary["top_talkers"][0]["ip"])
        summary["summary_text"] = " | ".join(parts)

    except subprocess.TimeoutExpired:
        summary["summary_text"] = "Analysis timed out — capture file may be large."
    except FileNotFoundError:
        summary["summary_text"] = "tshark not available for analysis."
    except Exception as e:
        summary["summary_text"] = f"Analysis error: {str(e)[:200]}"

    return summary
