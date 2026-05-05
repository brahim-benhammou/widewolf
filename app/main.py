"""
WideWolf — Network Intrusion Testing Appliance
ITP 258 Final Project — Main Flask Application

FOR EDUCATIONAL USE ONLY — Authorized Lab Environment
"""
import os
import sys
import hashlib
import logging
import socket
import functools
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash
)

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modules.database import (
    get_latest_scan_hosts,
    init_db, get_db, list_scans, get_scan, get_scan_hosts,
    get_host_services, get_scan_findings, get_traffic_summary,
    get_scan_stats, delete_scan, reset_stale_scans,
    get_setting, set_setting, get_all_settings,
    save_discovered_host, get_discovered_hosts, clear_discovered_hosts,
    hide_discovered_host, unhide_discovered_host
)
from modules.orchestrator import (
    start_scan, get_scan_progress, is_scan_running, cancel_active_scan,
    get_active_scans
)
from modules.nmap_scanner import get_scan_types, get_timing_profiles, validate_target
from modules.tshark_capture import get_available_interfaces
from modules.report_generator import get_report_path, generate_report

# Flask app
app = Flask(__name__, template_folder="templates")

@app.template_filter('fmt_time')
def fmt_time_filter(value):
    """Format datetime string to 12-hour AM/PM format."""
    if not value:
        return '—'
    try:
        from datetime import datetime as _dt
        # Handle both 'YYYY-MM-DD HH:MM:SS' and 'YYYY-MM-DDTHH:MM:SS' formats
        s = str(value).replace('T', ' ').split('.')[0]
        dt = _dt.strptime(s, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%b %d, %Y %I:%M %p')
    except:
        return str(value)[:16]

# Use a persistent secret key so sessions survive server restarts
_sk_file = os.path.join(BASE_DIR, '..', 'data', '.secret_key')
if os.path.exists(_sk_file):
    app.secret_key = open(_sk_file, 'rb').read()
else:
    app.secret_key = os.urandom(32)
    open(_sk_file, 'wb').write(app.secret_key)

# Logging — both console and file
os.makedirs(os.path.join(BASE_DIR, "..", "data"), exist_ok=True)
_log_file = os.path.join(BASE_DIR, "..", "data", "widewolf.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(_log_file, mode='a')
    ]
)
logger = logging.getLogger("widewolf")

# Data directories
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
PASSWORD_FILE = os.path.join(DATA_DIR, ".admin_password")

# ─── Password Management ───────────────────────────────────────────────────────

def _hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def _get_stored_password():
    if os.path.exists(PASSWORD_FILE):
        return open(PASSWORD_FILE).read().strip()
    return None

def _save_password(pw):
    os.makedirs(os.path.dirname(PASSWORD_FILE), exist_ok=True)
    with open(PASSWORD_FILE, "w") as f:
        f.write(_hash_pw(pw))

def _check_password(pw):
    stored = _get_stored_password()
    if not stored:
        return False
    return _hash_pw(pw) == stored

def _first_run():
    return _get_stored_password() is None

# ─── Auth Decorator ────────────────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ─── Utility ───────────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.10.10.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ─── Page Routes ───────────────────────────────────────────────────────────────

@app.route("/setup", methods=["GET", "POST"])
def setup_page():
    if not _first_run():
        return redirect(url_for("login_page"))
    error = None
    if request.method == "POST":
        pw1 = request.form.get("password", "")
        pw2 = request.form.get("confirm", "")
        if len(pw1) < 8:
            error = "Password must be at least 8 characters."
        elif pw1 != pw2:
            error = "Passwords do not match."
        else:
            _save_password(pw1)
            session["authenticated"] = True
            return redirect(url_for("dashboard"))
    return render_template("setup.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if _first_run():
        return redirect(url_for("setup_page"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and _check_password(password):
            session["authenticated"] = True
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
def welcome():
    if _first_run():
        return redirect(url_for("setup_page"))
    return render_template("welcome.html", local_ip=get_local_ip())


@app.route("/dashboard")
@login_required
def dashboard():
    stats = get_scan_stats()
    recent = list_scans(limit=5)
    return render_template("dashboard.html", stats=stats, recent_scans=recent, local_ip=get_local_ip())


@app.route("/scan")
@login_required
def scan_page():
    return render_template("scan.html",
                           scan_types=get_scan_types(),
                           timing_profiles=get_timing_profiles(),
                           interfaces=get_available_interfaces(),
                           scan_running=is_scan_running(),
                           saved_hosts=get_discovered_hosts())


@app.route("/results")
@login_required
def results_page():
    scans = list_scans(limit=50)
    return render_template("results.html", scans=scans)


@app.route("/results/<int:scan_id>")
@login_required
def result_detail(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return render_template("404.html"), 404
    hosts = get_scan_hosts(scan_id)
    services = get_host_services(scan_id)
    findings = get_scan_findings(scan_id)
    traffic = get_traffic_summary(scan_id)
    return render_template("result_detail.html",
                           scan=scan, hosts=hosts, services=services,
                           findings=findings, traffic=traffic)


@app.route("/reports")
@login_required
def reports_page():
    scans = list_scans(limit=50)
    return render_template("reports.html", scans=scans)


@app.route("/hardening")
@login_required
def hardening_page():
    # Load persisted hardening state from DB
    all_settings = get_all_settings()
    harden_state = {k.replace("harden:", ""): (v == "1") for k, v in all_settings.items() if k.startswith("harden:")}
    return render_template("hardening.html", harden_state=harden_state)

# ─── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    import shutil
    return jsonify({
        "status": "online",
        "nmap_available": shutil.which("nmap") is not None,
        "tshark_available": shutil.which("tshark") is not None,
        "scan_running": is_scan_running(),
        "local_ip": get_local_ip(),
        "timestamp": datetime.now().isoformat(),
    })

@app.route("/api/discover/saved")
@login_required
def api_get_saved_discovery():
    """Get currently discovered hosts (cleared and refreshed on each discovery scan)."""
    hosts = get_discovered_hosts()
    return jsonify({"hosts": hosts, "count": len(hosts)})

@app.route("/api/discover/hide", methods=["POST"])
@login_required
def api_discover_hide():
    """Hide a discovered host permanently."""
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400
    hide_discovered_host(ip)
    return jsonify({"success": True, "message": f"Host {ip} hidden"})

@app.route("/api/discover/unhide", methods=["POST"])
@login_required
def api_discover_unhide():
    """Unhide a previously hidden host."""
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({"success": False, "error": "Missing ip"}), 400
    unhide_discovered_host(ip)
    return jsonify({"success": True, "message": f"Host {ip} unhidden"})

@app.route("/api/discover/clear", methods=["POST"])
@login_required
def api_discover_clear():
    """Clear all non-hidden discovered hosts."""
    clear_discovered_hosts()
    return jsonify({"success": True})

@app.route("/api/discover/hosts", methods=["POST"])
@login_required
def api_discover_hosts():
    """Discover all active hosts using multiple methods with fallbacks."""
    import subprocess
    import ipaddress
    import concurrent.futures
    import shutil

    # Detect which local networks to scan based on actual interfaces
    def get_local_networks():
        nets = []
        try:
            result = subprocess.run("ip addr show", shell=True, capture_output=True, text=True)
            import re
            # Find all inet addresses except loopback
            for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout):
                ip_str, prefix = m.group(1), int(m.group(2))
                if not ip_str.startswith('127.') and not ip_str.startswith('169.254.'):
                    net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
                    nets.append(str(net))
        except:
            pass
        # Only include lab networks if we have a route to them
        # (don't add networks that don't exist on this system)
        return nets

    def ping_host(ip):
        """Ping a single host, return True if up."""
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                capture_output=True, timeout=3
            )
            return r.returncode == 0
        except:
            return False

    def get_hostname(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""

    def discover_via_nmap(network):
        """Use nmap ICMP ping sweep - only returns hosts that actually respond to ping."""
        found = []
        try:
            # Use sudo + -PE (ICMP echo only) for accurate host detection
            # -sn = no port scan, -PE = ICMP echo ping only, -n = no DNS
            # This prevents nmap from using TCP fallback which causes false positives
            r = subprocess.run(
                ["sudo", "nmap", "-sn", "-PE", "-n", "--host-timeout", "2s", network, "-oG", "-"],
                capture_output=True, text=True, timeout=120
            )
            for line in r.stdout.splitlines():
                if "Status: Up" in line and line.startswith("Host:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        try:
                            import ipaddress as _ip
                            _ip.ip_address(ip)
                            found.append(ip)
                        except:
                            pass
        except Exception as e:
            pass
        return found

    def discover_via_arp(network):
        """Read ARP table for already-known hosts."""
        found = []
        try:
            net_obj = ipaddress.ip_network(network, strict=False)
            r = subprocess.run("arp -n 2>/dev/null || ip neigh show 2>/dev/null", shell=True, capture_output=True, text=True)
            import re
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', r.stdout):
                ip = m.group(1)
                try:
                    if ipaddress.ip_address(ip) in net_obj:
                        found.append(ip)
                except:
                    pass
        except:
            pass
        return found

    def discover_via_ping_sweep(network):
        """Parallel ping sweep — works without nmap."""
        found = []
        try:
            net_obj = ipaddress.ip_network(network, strict=False)
            # Limit to /24 or smaller to avoid huge sweeps
            if net_obj.prefixlen < 24:
                return found
            hosts_to_ping = list(net_obj.hosts())
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                results = list(ex.map(lambda h: (str(h), ping_host(str(h))), hosts_to_ping))
            for ip, up in results:
                if up:
                    found.append(ip)
        except Exception as e:
            logging.error(f"Ping sweep error: {e}")
        return found

    hosts_seen = set()
    hosts = []
    networks = get_local_networks()

    for net in networks:
        active_ips = []

        # Method 1: nmap ICMP ping sweep (fastest, only finds currently alive hosts)
        if shutil.which("nmap"):
            active_ips = discover_via_nmap(net)
        # Method 2: Parallel ping sweep (fallback if nmap not available)
        if not active_ips:
            active_ips = discover_via_ping_sweep(net)

        for ip in active_ips:
            if ip not in hosts_seen:
                hosts_seen.add(ip)
                hostname = get_hostname(ip)
                hosts.append({"ip": ip, "hostname": hostname})

    # Also include the local machine itself
    try:
        local_ip = subprocess.run("hostname -I | awk '{print $1}'", shell=True, capture_output=True, text=True).stdout.strip()
        if local_ip and local_ip not in hosts_seen:
            hostname = socket.gethostname() + " (this device)"
            hosts.append({"ip": local_ip, "hostname": hostname})
            save_discovered_host(local_ip, hostname)
    except:
        pass

    # Clear old discovered hosts and save only the current scan results
    clear_discovered_hosts()
    for host in hosts:
        save_discovered_host(host["ip"], host["hostname"])
    return jsonify({"hosts": hosts, "count": len(hosts)})


def _validate_target_scope(target):
    """Check target IP/network is within the appliance's /24 network scope."""
    import ipaddress
    try:
        local_ip = get_local_ip()
        local_net = ipaddress.ip_network(local_ip + '/24', strict=False)
        # Parse target — could be single IP or CIDR
        target = target.strip()
        if '/' in target:
            target_net = ipaddress.ip_network(target, strict=False)
            # Check if target network overlaps with local /24
            if not target_net.overlaps(local_net):
                return False, f"Target network {target} is outside the appliance scope ({local_net}). Only targets within {local_net} are allowed."
        else:
            target_ip = ipaddress.ip_address(target)
            if target_ip not in local_net:
                return False, f"Target IP {target} is outside the appliance scope ({local_net}). Only IPs within {local_net} are allowed."
        return True, None
    except ValueError:
        # Not a valid IP — let it through (could be hostname)
        return True, None
    except Exception:
        return True, None

@app.route("/api/scan/start", methods=["POST"])
@login_required
def api_start_scan():
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "service")
    timing = data.get("timing", "normal")
    capture_iface = data.get("capture_iface", "eth0")
    capture_duration = int(data.get("capture_duration", 30))
    valid, err = _validate_target_scope(target)
    if not valid:
        return jsonify({"success": False, "error": err})
    result = start_scan(target, scan_type, timing, capture_iface, capture_duration)
    return jsonify(result)


@app.route("/api/scan/progress/<scan_uuid>")
@login_required
def api_scan_progress(scan_uuid):
    return jsonify(get_scan_progress(scan_uuid))


@app.route("/api/scan/cancel", methods=["POST"])
@login_required
def api_scan_cancel():
    data = request.get_json(force=True) or {}
    scan_uuid = data.get("scan_uuid")
    cancelled = cancel_active_scan(scan_uuid)
    return jsonify({"success": cancelled})


@app.route("/api/scan/delete", methods=["POST"])
@login_required
def api_scan_delete():
    data = request.get_json(force=True) or {}
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"success": False, "error": "scan_id required"})
    try:
        delete_scan(int(scan_id))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/scan/active")
@login_required
def api_scan_active():
    scans = get_active_scans()
    return jsonify({"scans": scans, "count": len(scans)})


@app.route("/api/scan/status")
@login_required
def api_scan_status():
    return jsonify({"running": is_scan_running()})


@app.route("/api/report/<int:scan_id>")
@login_required
def api_download_report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    # Always regenerate to ensure latest data (including MANUAL/AUTO label)
    generated = generate_report(scan_id)
    path = generated if generated else get_report_path(scan_id)
    if path and os.path.exists(path):
        filename = f"widewolf_report_{scan['target'].replace('/', '_')}_{scan_id}.txt"
        try:
            # Flask 2.x
            return send_file(path, as_attachment=True, download_name=filename)
        except TypeError:
            # Flask 1.x fallback
            return send_file(path, as_attachment=True, attachment_filename=filename)
    return jsonify({"error": "Could not generate report"}), 404


@app.route("/api/report/<int:scan_id>/delete", methods=["POST"])
@login_required
def api_delete_report(scan_id):
    try:
        scan = get_scan(scan_id)
        if scan:
            # Delete report file
            path = get_report_path(scan_id)
            if path and os.path.exists(path):
                os.remove(path)
            # Delete scan data
            delete_scan(scan_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/results/<int:scan_id>")
@login_required
def api_result_detail(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    hosts = get_scan_hosts(scan_id)
    services = get_host_services(scan_id)
    findings = get_scan_findings(scan_id)
    traffic = get_traffic_summary(scan_id)
    return jsonify({
        "scan": dict(scan),
        "hosts": [dict(h) for h in hosts],
        "services": [dict(s) for s in services],
        "findings": [dict(f) for f in findings],
        "traffic": dict(traffic) if traffic else None,
    })


# ─── Hardening API ─────────────────────────────────────────────────────────────

HARDENING_CONTROLS = {
    "ufw-enable": {
        "enable": "sudo ufw --force reset > /dev/null 2>&1; sudo ufw default deny incoming; sudo ufw default allow outgoing; sudo ufw allow from 127.0.0.1 to any port 5000 comment WideWolf-localhost; sudo ufw allow from 127.0.0.1 to any port 22 comment WideWolf-ssh-local; sudo ufw --force enable; sudo ufw status verbose",
        "disable": "sudo ufw --force disable; echo UFW-disabled-all-traffic-now-allowed",
        "desc": "Enable UFW firewall with default deny incoming",
        "verify": "sudo ufw status verbose 2>&1",
    },
    "ufw-ssh": {
        "enable": "sudo ufw allow from 10.10.10.0/24 to any port 22 proto tcp comment WideWolf-SSH; sudo ufw status | grep 22",
        "disable": "sudo ufw delete allow from 10.10.10.0/24 to any port 22 proto tcp 2>/dev/null; echo SSH-lab-rule-removed",
        "desc": "Allow SSH from Lab Network (10.10.10.0/24)",
        "verify": "sudo ufw status | grep 22 || echo no-ssh-rule",
    },
    "ufw-web": {
        "enable": "sudo ufw allow from 10.10.10.0/24 to any port 5000 proto tcp comment WideWolf-GUI; sudo ufw allow from 127.0.0.1 to any port 5000 comment WideWolf-localhost; sudo ufw status | grep 5000",
        "disable": "sudo ufw delete allow from 10.10.10.0/24 to any port 5000 proto tcp 2>/dev/null; sudo ufw allow from 127.0.0.1 to any port 5000 comment WideWolf-localhost 2>/dev/null; echo Web-GUI-blocked-for-external-Pi-localhost-still-works",
        "desc": "Allow Web GUI from Lab Network (10.10.10.0/24) — Pi localhost always works",
        "verify": "sudo ufw status | grep 5000 || echo no-gui-rule",
    },
    "ssh-root": {
        "enable": "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true",
        "disable": "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true",
        "desc": "Disable root SSH login",
        "verify": "grep '^PermitRootLogin' /etc/ssh/sshd_config",
    },
    "ssh-password": {
        "enable": "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true",
        "disable": "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || true",
        "desc": "Require SSH key-based auth only",
        "verify": "grep '^PasswordAuthentication' /etc/ssh/sshd_config",
    },
    "password-policy": {
        "enable": "sudo sed -i 's/^# *minlen.*/minlen = 12/' /etc/security/pwquality.conf 2>/dev/null || echo 'minlen = 12' | sudo tee -a /etc/security/pwquality.conf",
        "disable": "sudo sed -i 's/^minlen.*/# minlen = 8/' /etc/security/pwquality.conf 2>/dev/null || true",
        "desc": "Enforce strong password policy (min 12 chars)",
        "verify": "grep 'minlen' /etc/security/pwquality.conf 2>/dev/null || echo 'not configured'",
    },
    "login-timeout": {
        "enable": "echo 'TMOUT=300' | sudo tee /etc/profile.d/timeout.sh > /dev/null && sudo chmod +x /etc/profile.d/timeout.sh",
        "disable": "sudo rm -f /etc/profile.d/timeout.sh",
        "desc": "Auto-logout after 300s inactivity",
        "verify": "cat /etc/profile.d/timeout.sh 2>/dev/null || echo 'not set'",
    },
    "icmp-disable": {
        "enable": "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null && sudo sysctl -w net.ipv4.conf.default.accept_redirects=0 > /dev/null && echo 'net.ipv4.conf.all.accept_redirects=0' | sudo tee -a /etc/sysctl.d/99-widewolf.conf > /dev/null",
        "disable": "sudo sysctl -w net.ipv4.conf.all.accept_redirects=1 > /dev/null && sudo sed -i '/accept_redirects/d' /etc/sysctl.d/99-widewolf.conf 2>/dev/null || true",
        "desc": "Disable ICMP redirects",
        "verify": "sysctl net.ipv4.conf.all.accept_redirects",
    },
    "ip-forward": {
        "enable": "sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null && echo 'net.ipv4.ip_forward=0' | sudo tee -a /etc/sysctl.d/99-widewolf.conf > /dev/null",
        "disable": "sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null && sudo sed -i '/ip_forward/d' /etc/sysctl.d/99-widewolf.conf 2>/dev/null || true",
        "desc": "Disable IP forwarding",
        "verify": "sysctl net.ipv4.ip_forward",
    },
    "disable-avahi": {
        "enable": "sudo systemctl stop avahi-daemon 2>/dev/null; sudo systemctl disable avahi-daemon 2>/dev/null; sudo systemctl mask avahi-daemon 2>/dev/null || true",
        "disable": "sudo systemctl unmask avahi-daemon 2>/dev/null; sudo systemctl enable --now avahi-daemon 2>/dev/null || true",
        "desc": "Disable Avahi/mDNS daemon",
        "verify": "systemctl is-active avahi-daemon 2>/dev/null || echo 'inactive'",
    },
    "disable-cups": {
        "enable": "sudo systemctl stop cups 2>/dev/null; sudo systemctl disable cups 2>/dev/null; sudo systemctl mask cups 2>/dev/null || true",
        "disable": "sudo systemctl unmask cups 2>/dev/null; sudo systemctl enable --now cups 2>/dev/null || true",
        "desc": "Disable CUPS print service",
        "verify": "systemctl is-active cups 2>/dev/null || echo 'inactive'",
    },
    "disable-bluetooth": {
        "enable": "sudo systemctl stop bluetooth 2>/dev/null; sudo systemctl disable bluetooth 2>/dev/null; sudo systemctl mask bluetooth 2>/dev/null || true",
        "disable": "sudo systemctl unmask bluetooth 2>/dev/null; sudo systemctl enable --now bluetooth 2>/dev/null || true",
        "desc": "Disable Bluetooth service",
        "verify": "systemctl is-active bluetooth 2>/dev/null || echo 'inactive'",
    },
    "auto-updates": {
        "enable": "sudo apt-get install -y unattended-upgrades > /dev/null 2>&1 && echo 'APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null",
        "disable": "sudo rm -f /etc/apt/apt.conf.d/20auto-upgrades",
        "desc": "Enable automatic security updates",
        "verify": "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo 'disabled'",
    },
    "tmp-noexec": {
        "enable": "sudo mount -o remount,noexec,nosuid /tmp 2>/dev/null || echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0' | sudo tee -a /etc/fstab > /dev/null",
        "disable": "sudo mount -o remount,exec /tmp 2>/dev/null || sudo sed -i '/tmpfs.*\\/tmp/d' /etc/fstab",
        "desc": "Mount /tmp with noexec (prevent binary execution)",
        "verify": "mount | grep '/tmp' || echo 'default mount'",
    },
    "core-dumps": {
        "enable": "echo '* hard core 0' | sudo tee /etc/security/limits.d/widewolf-nodump.conf > /dev/null && sudo sysctl -w kernel.core_pattern=/dev/null > /dev/null 2>&1 || true",
        "disable": "sudo rm -f /etc/security/limits.d/widewolf-nodump.conf && sudo sysctl -w kernel.core_pattern=core > /dev/null 2>&1 || true",
        "desc": "Disable core dumps (prevent memory leak)",
        "verify": "cat /etc/security/limits.d/widewolf-nodump.conf 2>/dev/null || echo 'not set'",
    },
}


@app.route("/api/hardening/apply", methods=["POST"])
@login_required
def api_hardening_apply():
    import subprocess
    data = request.get_json(force=True)
    control = data.get("control", "")
    enabled = bool(data.get("enabled", True))
    if control not in HARDENING_CONTROLS:
        return jsonify({"success": False, "message": f"Unknown control: {control}"})
    ctrl = HARDENING_CONTROLS[control]
    action = "enable" if enabled else "disable"
    cmd = ctrl[action]
    try:
        result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=15)
        exit_code = result.returncode
        output = result.stdout.strip() or result.stderr.strip() or ""
        # Persist state to DB so it survives page refresh
        set_setting(f"harden:{control}", "1" if enabled else "0")
        state_word = "APPLIED" if enabled else "REVERTED"
        msg = f"{ctrl['desc']} — {state_word}"
        if output:
            msg += f" | {output[:120]}"
        logger.info("Hardening: %s -> %s (exit=%s)", control, action, exit_code)
        return jsonify({
            "success": True,
            "message": msg,
            "command": cmd,
            "exit_code": exit_code,
            "output": output,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Command timed out (15s)", "command": cmd})
    except Exception as e:
        return jsonify({"success": False, "message": str(e), "command": cmd})


@app.route("/api/hardening/verify", methods=["POST"])
@login_required
def api_hardening_verify():
    """Run verify command for a control and return output."""
    data = request.get_json(force=True)
    control = data.get("control", "")

    if control not in HARDENING_CONTROLS:
        return jsonify({"success": False, "output": "Unknown control"})

    import subprocess
    cmd = HARDENING_CONTROLS[control].get("verify", "echo 'no verify command'")
    try:
        result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=10)
        output = result.stdout.strip() or result.stderr.strip() or "(no output)"
        return jsonify({"success": True, "output": output, "command": cmd})
    except Exception as e:
        return jsonify({"success": False, "output": str(e)})


# ─── Chart API ─────────────────────────────────────────────────────────────────

@app.route("/api/chart/port-distribution")
@login_required
def api_port_distribution():
    conn = get_db()
    open_c = conn.execute("SELECT COUNT(*) FROM services WHERE state='open'").fetchone()[0]
    filtered_c = conn.execute("SELECT COUNT(*) FROM services WHERE state='filtered'").fetchone()[0]
    closed_c = conn.execute("SELECT COUNT(*) FROM services WHERE state='closed'").fetchone()[0]
    conn.close()
    return jsonify({"open": open_c, "filtered": filtered_c, "closed": closed_c})


@app.route("/api/chart/vulnerability-breakdown")
@login_required
def api_vuln_breakdown():
    conn = get_db()
    rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity").fetchall()
    conn.close()
    data = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in rows:
        sev = (row["severity"] or "info").lower()
        if sev in data:
            data[sev] = row["cnt"]
    return jsonify(data)



@app.route("/discover", methods=["GET"])
@login_required
def discover_page():
    """Infrastructure discovery page."""
    return render_template("discover.html")

@app.route("/api/discover/start", methods=["POST"])
@login_required
def start_discovery():
    """Start infrastructure discovery scan."""
    from modules.nmap_scanner import discover_infrastructure
    import threading
    import uuid
    
    discovery_id = str(uuid.uuid4())
    
    def run_discovery():
        try:
            result = discover_infrastructure()
            session[f"discovery_{discovery_id}"] = result
        except Exception as e:
            session[f"discovery_{discovery_id}"] = {"error": str(e)}
    
    # Run discovery in background thread
    thread = threading.Thread(target=run_discovery, daemon=True)
    thread.start()
    
    return {"discovery_id": discovery_id, "status": "started"}

@app.route("/api/discover/<discovery_id>", methods=["GET"])
@login_required
def get_discovery(discovery_id):
    """Get discovery results."""
    result = session.get(f"discovery_{discovery_id}", {"status": "running"})
    return result

@app.route("/api/chart/weekly-activity")
@login_required
def api_weekly_activity():
    import datetime as dt
    conn = get_db()
    rows = conn.execute(
        "SELECT DATE(created_at) as day, COUNT(*) as cnt FROM scans "
        "WHERE created_at >= DATE('now','-6 days') GROUP BY day ORDER BY day"
    ).fetchall()
    conn.close()
    days = []
    for i in range(6, -1, -1):
        d = (dt.datetime.now() - dt.timedelta(days=i)).strftime("%Y-%m-%d")
        days.append(d)
    counts = {r["day"]: r["cnt"] for r in rows}
    return jsonify([{"day": d, "count": counts.get(d, 0)} for d in days])


# ─── Automated Scanner ────────────────────────────────────────────────────────

@app.route("/automated")
@login_required
def automated_page():
    """Automated scanning system page."""
    from modules.database import list_auto_scans
    from modules.orchestrator import get_auto_status
    scans = list_auto_scans(limit=50)
    status = get_auto_status()
    return render_template("automated.html", scans=scans, auto_status=status)


@app.route("/api/auto/start", methods=["POST"])
@login_required
def api_auto_start():
    """Start automated scanning."""
    from modules.orchestrator import start_auto_scheduler
    data = request.get_json() or {}
    target = data.get("target", "10.10.10.0/24")
    scan_type = data.get("scan_type", "service")
    timing = data.get("timing", "normal")
    iface = data.get("iface", "eth0")
    capture_duration = int(data.get("capture_duration", 30))
    interval = int(data.get("interval", 60))
    valid, err = _validate_target_scope(target)
    if not valid:
        return jsonify({"success": False, "error": err})
    result = start_auto_scheduler(target, scan_type, timing, iface, capture_duration, interval)
    return jsonify(result)


@app.route("/api/auto/stop", methods=["POST"])
@login_required
def api_auto_stop():
    """Stop automated scanning."""
    from modules.orchestrator import stop_auto_scheduler
    result = stop_auto_scheduler()
    return jsonify(result)


@app.route("/api/auto/status", methods=["GET"])
@login_required
def api_auto_status():
    """Get automated scanner status including recent scan history."""
    from modules.orchestrator import get_auto_status
    from modules.database import list_auto_scans
    status = get_auto_status()
    # Include recent auto scans for live history update
    scans = list_auto_scans(limit=20)
    history = []
    for s in scans:
        history.append({
            'id': s['id'],
            'target': s['target'],
            'scan_type': s['scan_type'],
            'status': s['status'],
            'duration_seconds': s['duration_seconds'],
            'created_at': s['created_at']
        })
    status['history'] = history
    return jsonify(status)


# ─── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500

@app.route("/api/scan/results", methods=["GET"])
@login_required
def api_scan_results():
    """Get recent scan results."""
    from modules.database import list_scans
    rows = list_scans(limit=20)
    scans = [dict(r) for r in rows]
    return jsonify({"scans": scans, "count": len(scans)})


# ─── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    reset_stale_scans()
    logger.info("WideWolf starting on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)

