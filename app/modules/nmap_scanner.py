"""
WideWolf — Nmap Scanner Module
ITP 258 — Network Intrusion Testing Appliance
Builds real nmap commands, executes them, parses XML output.
"""
import subprocess
import os
import re
import shutil
import xml.etree.ElementTree as ET
import ipaddress
from typing import Tuple, List, Dict

# Approved lab networks — only these targets are allowed
APPROVED_NETWORKS = [
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("192.168.1.0/24"),
    ipaddress.ip_network("172.16.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
]

# Real scan types with correct nmap flags
# Note: -sS (SYN stealth) requires root — we use sudo automatically on Pi
SCAN_TYPES = [
    {
        "id": "service",
        "name": "Service Detection",
        "description": "TCP connect scan with service/version detection on ports 1-10000 (-sT -sV -p 1-10000)",
        "flags": "-sT -sV -p 1-10000",
        "needs_root": False,
        "timeout": 300,
    },
    {
        "id": "quick",
        "name": "Quick Scan",
        "description": "Fast scan of top 100 most common ports (-sT -F)",
        "flags": "-sT -F",
        "needs_root": False,
        "timeout": 120,
    },
    {
        "id": "full",
        "name": "Full Port Scan",
        "description": "All 65535 TCP ports with service detection (-sT -sV -p-)",
        "flags": "-sT -sV -p-",
        "needs_root": False,
        "timeout": 600,
    },
    {
        "id": "stealth",
        "name": "SYN Stealth Scan",
        "description": "Half-open SYN scan — harder to detect, requires root (-sS -sV)",
        "flags": "-sS -sV -p 1-10000",
        "needs_root": True,
        "timeout": 300,
    },
    {
        "id": "udp",
        "name": "UDP Scan",
        "description": "Top 100 UDP ports — finds DNS, SNMP, DHCP, TFTP (-sU --top-ports 100)",
        "flags": "-sU --top-ports 100",
        "needs_root": True,
        "timeout": 300,
    },
    {
        "id": "vuln",
        "name": "Vulnerability Scan",
        "description": "Service detection + NSE vulnerability scripts (-sT -sV --script=vuln)",
        "flags": "-sT -sV -p 1-10000 --script=vuln --script-timeout 30s",
        "needs_root": False,
        "timeout": 600,
    },
]

TIMING_PROFILES = {
    "paranoid": {"flag": "-T0", "desc": "Extremely slow — IDS evasion"},
    "sneaky":   {"flag": "-T1", "desc": "Slow — reduced detection risk"},
    "polite":   {"flag": "-T2", "desc": "Polite — low network impact"},
    "normal":   {"flag": "-T3", "desc": "Default speed"},
    "aggressive": {"flag": "-T4", "desc": "Fast — may trigger IDS alerts"},
    "insane":   {"flag": "-T5", "desc": "Maximum speed — very noisy"},
}

SCAN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "scans")

# Active nmap process registry — allows external cancellation
_nmap_processes = {}  # {scan_uuid: subprocess.Popen}
_nmap_proc_lock = __import__('threading').Lock()

def _register_nmap_process(scan_uuid, proc):
    with _nmap_proc_lock:
        _nmap_processes[scan_uuid] = proc

def _unregister_nmap_process(scan_uuid):
    with _nmap_proc_lock:
        _nmap_processes.pop(scan_uuid, None)

def kill_nmap_process(scan_uuid):
    """Kill the nmap process for a given scan UUID if it is running."""
    with _nmap_proc_lock:
        proc = _nmap_processes.get(scan_uuid)
    if proc:
        try:
            proc.kill()
        except Exception:
            pass
        _unregister_nmap_process(scan_uuid)



def ping_sweep(network: str) -> List[str]:
    """Perform ping sweep to find active hosts in a network."""
    import subprocess
    active_hosts = []
    try:
        # Use nmap for fast ping sweep: -sn (no port scan, just host discovery)
        cmd = f"nmap -sn {network} -oG - 2>/dev/null | grep 'Status: Up' | awk '{{print $2}}'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if result.stdout:
            active_hosts = [ip.strip() for ip in result.stdout.strip().split('\n') if ip.strip()]
    except Exception as e:
        print(f"Ping sweep error: {e}")
    return active_hosts

def discover_infrastructure() -> Dict:
    """Auto-discover all hosts, services, and infrastructure in lab networks."""
    import subprocess
    discovery = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "networks": {},
        "total_hosts": 0,
        "services_found": 0,
    }
    
    for net in APPROVED_NETWORKS:
        net_str = str(net)
        discovery["networks"][net_str] = {
            "hosts": [],
            "services": [],
            "vmware_detected": False,
            "docker_detected": False,
        }
        
        # Ping sweep to find active hosts
        active = ping_sweep(net_str)
        
        for ip in active:
            host_info = {
                "ip": ip,
                "hostname": "",
                "os": "",
                "services": [],
                "type": "unknown",
            }
            
            # Quick service detection
            cmd = f"nmap -sT -F -Pn {ip} -oX - 2>/dev/null"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                if "open" in result.stdout:
                    # Parse for VMware indicators
                    if "vmware" in result.stdout.lower() or "esxi" in result.stdout.lower():
                        host_info["type"] = "vmware_host"
                        discovery["networks"][net_str]["vmware_detected"] = True
                    # Parse for Docker indicators
                    if "docker" in result.stdout.lower() or "2375" in result.stdout:
                        host_info["type"] = "docker_host"
                        discovery["networks"][net_str]["docker_detected"] = True
                    
                    # Extract services
                    import re
                    ports = re.findall(r'<port protocol="tcp" portid="(\d+)"><state state="open"', result.stdout)
                    host_info["services"] = [int(p) for p in ports[:10]]
                    discovery["networks"][net_str]["services_found"] += len(ports)
            except:
                pass
            
            discovery["networks"][net_str]["hosts"].append(host_info)
            discovery["total_hosts"] += 1
    
    return discovery


def get_scan_types() -> List[Dict]:
    """Return available scan types."""
    return SCAN_TYPES


def get_timing_profiles() -> Dict:
    """Return timing profile options."""
    return TIMING_PROFILES


def validate_target(target: str) -> Tuple[bool, str]:
    """Validate target is within approved lab scope."""
    target = target.strip()
    if not target:
        return False, "Target cannot be empty."

    # Block public internet targets
    public_blocked = [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "google.com", "facebook.com", "amazon.com", "microsoft.com"
    ]
    if target.lower() in public_blocked:
        return False, "Public internet targets are not allowed. Lab use only."

    # Try to parse as IP or network
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            # Block huge subnets (larger than /16)
            if net.prefixlen < 16:
                return False, "Subnet too large. Use /16 or smaller."
            for approved in APPROVED_NETWORKS:
                if net.subnet_of(approved) or net.overlaps(approved):
                    return True, f"Valid lab network: {target}"
            return False, f"Network {target} is outside approved lab scope."
        else:
            ip = ipaddress.ip_address(target)
            # Block loopback/multicast
            if ip.is_loopback or ip.is_multicast:
                return False, "Loopback and multicast addresses are not valid targets."
            for approved in APPROVED_NETWORKS:
                if ip in approved:
                    return True, f"Valid lab target: {target}"
            return False, f"IP {target} is outside approved lab scope."
    except ValueError:
        # Hostname — allow internal-looking hostnames
        if re.match(r'^[a-zA-Z0-9\-\.]+$', target):
            public_tlds = ['.com', '.org', '.net', '.io', '.edu', '.gov', '.co', '.uk']
            if not any(target.lower().endswith(ext) for ext in public_tlds):
                return True, f"Internal hostname accepted: {target}"
        return False, f"Invalid target format: {target}"


def build_nmap_command(target: str, scan_type: str, timing: str, output_file: str) -> str:
    """Build the real nmap command string."""
    # Find scan type config
    scan_cfg = next((s for s in SCAN_TYPES if s["id"] == scan_type), SCAN_TYPES[0])
    scan_flags = scan_cfg["flags"]
    needs_root = scan_cfg["needs_root"]

    # Timing flag
    timing_flag = TIMING_PROFILES.get(timing, TIMING_PROFILES["normal"])["flag"]

    # Scale timeout for subnet scans
    host_timeout = "90s"
    if "/" in target:
        host_timeout = "30s"  # shorter per-host timeout for subnet scans

    # Build command
    parts = []
    if needs_root:
        parts.append("sudo")
    parts.append("nmap")
    parts.extend(scan_flags.split())
    # -Pn: skip host discovery (ping check)
    # Required for Windows VMs/hosts that block ICMP — without this nmap
    # marks the host as 'down' and skips port scanning entirely, returning
    # instantly with no results. -Pn forces nmap to scan ports regardless.
    parts.append("-Pn")
    parts.extend([timing_flag, "-oX", output_file,
                  "--host-timeout", host_timeout,
                  "--max-retries", "2",
                  target])

    return " ".join(parts)


def run_nmap(target: str, scan_type: str, timing: str, scan_uuid: str) -> Dict:
    """Execute nmap scan and return result info."""
    os.makedirs(SCAN_DIR, exist_ok=True)
    output_file = os.path.join(SCAN_DIR, f"nmap_{scan_uuid}.xml")

    # Check nmap is installed
    if not shutil.which("nmap"):
        return {
            "command": "nmap (not found)",
            "output_file": output_file,
            "success": False,
            "error": "nmap is not installed. Run: sudo apt install nmap",
        }

    cmd_str = build_nmap_command(target, scan_type, timing, output_file)

    # Get timeout from scan type config
    scan_cfg = next((s for s in SCAN_TYPES if s["id"] == scan_type), SCAN_TYPES[0])
    timeout = scan_cfg["timeout"]

    # Scale timeout for subnet scans
    if "/" in target:
        timeout = timeout * 3

    result = {
        "command": cmd_str,
        "output_file": output_file,
        "success": False,
        "error": None,
        "stdout": "",
        "stderr": "",
    }

    try:
        proc = subprocess.Popen(
            cmd_str.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _register_nmap_process(scan_uuid, proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        finally:
            _unregister_nmap_process(scan_uuid)
        result["stdout"] = stdout[:1000] if stdout else ""
        result["stderr"] = stderr[:500] if stderr else ""
        rc = proc.returncode
        if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
            result["success"] = True
        elif rc == 0:
            result["success"] = True
        elif rc in (-9, -15, 1) and os.path.exists(output_file):
            # Killed (cancel/pause) — partial results
            result["success"] = True
            result["error"] = "Scan interrupted — partial results saved"
        else:
            result["error"] = result["stderr"] or f"nmap exited with code {rc}"

    except subprocess.TimeoutExpired:
        # Even if timed out, partial XML may exist
        if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
            result["success"] = True
            result["error"] = f"Scan timed out after {timeout}s — partial results saved"
        else:
            result["error"] = f"Scan timed out after {timeout}s with no results"
    except FileNotFoundError:
        result["error"] = "nmap not found — install with: sudo apt install nmap"
    except Exception as e:
        result["error"] = str(e)[:500]

    return result


def parse_nmap_xml(xml_file: str) -> Dict:
    """Parse nmap XML output into structured data."""
    result = {"hosts": [], "scan_info": {}}

    if not os.path.exists(xml_file):
        result["scan_info"]["error"] = "XML output file not found"
        return result

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # Scan metadata
        result["scan_info"]["command"] = root.get("args", "")
        result["scan_info"]["start_time"] = root.get("startstr", "")
        runstats = root.find(".//finished")
        if runstats is not None:
            result["scan_info"]["elapsed"] = runstats.get("elapsed", "")
            result["scan_info"]["summary"] = runstats.get("summary", "")

        # Parse each host
        for host_elem in root.findall(".//host"):
            # Only include hosts that are up
            status = host_elem.find("status")
            if status is not None and status.get("state") != "up":
                continue

            host_data = {
                "ip": "",
                "hostname": "",
                "os": "",
                "os_accuracy": "",
                "state": "up",
                "ports": [],
                "scripts": [],
            }

            # IP address
            addr = host_elem.find("address[@addrtype='ipv4']")
            if addr is not None:
                host_data["ip"] = addr.get("addr", "")

            # MAC address
            mac = host_elem.find("address[@addrtype='mac']")
            if mac is not None:
                host_data["mac"] = mac.get("addr", "")
                host_data["vendor"] = mac.get("vendor", "")

            # Hostname
            hostname_elem = host_elem.find(".//hostname[@type='PTR']") or host_elem.find(".//hostname")
            if hostname_elem is not None:
                host_data["hostname"] = hostname_elem.get("name", "")

            # OS detection
            osmatch = host_elem.find(".//osmatch")
            if osmatch is not None:
                host_data["os"] = osmatch.get("name", "")
                host_data["os_accuracy"] = osmatch.get("accuracy", "")

            # Ports
            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue

                port_state = state_elem.get("state", "unknown")
                # Include open and open|filtered
                if "open" not in port_state:
                    continue

                port_data = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": port_state,
                    "service": "",
                    "product": "",
                    "version": "",
                    "extra": "",
                    "cpe": "",
                    "scripts": [],
                }

                svc = port_elem.find("service")
                if svc is not None:
                    port_data["service"] = svc.get("name", "")
                    port_data["product"] = svc.get("product", "")
                    port_data["version"] = svc.get("version", "")
                    port_data["extra"] = svc.get("extrainfo", "")
                    cpe = svc.find("cpe")
                    if cpe is not None:
                        port_data["cpe"] = cpe.text or ""

                # NSE script output (for vuln scan)
                for script in port_elem.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    if script_output:
                        port_data["scripts"].append({
                            "id": script_id,
                            "output": script_output[:500],
                        })

                host_data["ports"].append(port_data)

            # Host-level scripts
            for script in host_elem.findall(".//hostscript/script"):
                host_data["scripts"].append({
                    "id": script.get("id", ""),
                    "output": script.get("output", "")[:500],
                })

            if host_data["ip"]:
                result["hosts"].append(host_data)

    except ET.ParseError as e:
        result["scan_info"]["parse_error"] = str(e)
    except Exception as e:
        result["scan_info"]["error"] = str(e)

    return result
