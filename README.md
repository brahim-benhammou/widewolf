# WideWolf — Network Intrusion Detection Appliance

A professional-grade network security appliance built on Raspberry Pi with automated scanning, real-time threat detection, live dashboard, and comprehensive reporting.

**Status:** v1.0 Stable | **License:** GPL v3.0 | **Author:** Brahim Benhammou

---

## 🎯 What It Does

WideWolf automatically discovers and monitors all active devices on your network. It performs continuous security scanning, generates detailed reports, and provides a live dashboard to track threats in real-time.

### Core Features

✅ **Automated Network Discovery** — Discovers all active hosts on your network automatically (no manual entry needed)  
✅ **Live Host Detection** — Shows which devices are currently online and responding  
✅ **Port Scanning** — Service identification and vulnerability assessment  
✅ **Packet Capture & Analysis** — Real-time traffic analysis with tshark  
✅ **OS Hardening Recommendations** — Security best practices and hardening guides  
✅ **24/7 Automated Monitoring** — Continuous scanning with configurable intervals  
✅ **Professional Reports** — Export detailed findings as TXT (PDF coming soon)  
✅ **Live Web Dashboard** — Real-time monitoring with no page refresh needed  
✅ **Manual & Automated Scans** — Track which scans are manual vs automated system  
✅ **Network Accessibility** — Access from any device on your network (localhost, 10.10.10.x, 172.x.x.x)

### What It Does NOT Do

❌ Exploit vulnerabilities (detection and analysis only)  
❌ Require Docker or complex containerization  
❌ Need special hardware or high system resources  
❌ Scan outside your configured network scope (security feature)

---

## 📋 System Requirements

| Requirement | Details |
|---|---|
| **Hardware** | Raspberry Pi 4 (primary) or any Linux system |
| **OS** | Raspberry Pi OS, Ubuntu, Debian, or compatible Linux |
| **Python** | 3.8+ |
| **Storage** | 500MB minimum |
| **Network** | Ethernet or WiFi connection |
| **Access** | From localhost or any device on your network |

---

## ⚡ Quick Start (3 Steps)

```bash
# 1. Extract and navigate
unzip widewolf-v13-final.zip
cd widewolf

# 2. Install dependencies
bash setup.sh

# 3. Start the appliance
bash start.sh
```

Then open your browser to any of these:
- **http://localhost:5000** (from the Pi)
- **http://10.10.10.x:5000** (from your network)
- **http://172.x.x.x:5000** (if on 172.x network)

### First Time Setup
1. Create admin password when prompted
2. Configure target network (e.g., 10.10.10.0/24)
3. Select scan type and timing preferences
4. Start scanning

---

## 🚀 Usage Guide

### Manual Scanning

1. Navigate to **Launch Scan**
2. Enter target IP or network (must be in your configured scope)
3. Select scan type:
   - **Quick Scan** — Fast port enumeration
   - **Service Detection** — Identify running services
   - **Comprehensive** — Full vulnerability assessment
4. Click **Launch Scan**
5. View results in real-time as they come in

### Automated Scanning (24/7)

1. Navigate to **Automated System**
2. Configure:
   - Target network (e.g., 10.10.10.0/24)
   - Scan type (Quick, Service Detection, etc.)
   - Timing profile (Normal, Aggressive, etc.)
   - Scan interval in seconds (minimum 10 seconds)
3. Click **Start Automated Scanning**
4. System runs continuously until stopped
5. View live history and results in real-time

### Viewing Results

| Page | Purpose |
|---|---|
| **Dashboard** | Overview of all scans, system status, and statistics |
| **Scan Results** | Detailed results with filtering, sorting, and host details |
| **Reports** | Download comprehensive TXT reports with all findings |
| **Automated System** | Monitor 24/7 scanning, view history, adjust settings |

### Exporting Reports

**Current Version (v1.0):**
- Download detailed **TXT reports** with:
  - Scan summary (target, type, timing, duration)
  - Source (MANUAL or AUTOMATED SYSTEM)
  - All discovered hosts and open ports
  - Service versions and OS information
  - Scan commands used

**Future Version (v1.1+):**
- PDF export with formatted layout
- HTML reports
- JSON export for API integration

---

## 🔒 Network Scope & Security

### Current Version (v1.0)
- Scans restricted to your configured network subnet (e.g., 10.10.10.0/24)
- This is a **security feature** to prevent unauthorized scanning
- Hostnames are allowed (not blocked by IP validation)
- Out-of-scope targets show clear error message
- Appliance accessible from any device on your network

### Future Versions (v1.1+)
- Multi-subnet scanning support
- VPN integration
- Remote network scanning
- Advanced firewall rules

---

## 📊 Architecture

```
WideWolf/
├── app/
│   ├── main.py                    # Flask web server & routing
│   ├── modules/
│   │   ├── database.py            # SQLite database layer
│   │   ├── nmap_scanner.py        # Nmap integration & scanning
│   │   ├── tshark_capture.py      # Packet capture & analysis
│   │   ├── orchestrator.py        # Scan orchestration & scheduling
│   │   └── report_generator.py    # Report generation (TXT)
│   └── templates/                 # HTML/CSS/JavaScript UI
│       ├── base.html              # Layout template
│       ├── dashboard.html         # Dashboard page
│       ├── scan.html              # Manual scanning page
│       ├── results.html           # Scan results page
│       ├── reports.html           # Reports page
│       └── automated.html         # Automated system page
├── data/
│   ├── widewolf.db                # SQLite database
│   ├── reports/                   # Generated TXT reports
│   └── captures/                  # Packet capture files
├── setup.sh                       # Installation script
├── start.sh                       # Startup script
└── requirements.txt               # Python dependencies
```

---

## 🛠 Technologies Used

| Component | Technology |
|---|---|
| **Backend** | Python 3.11, Flask |
| **Database** | SQLite3 |
| **Scanning** | Nmap, tshark |
| **Frontend** | HTML5, CSS3, JavaScript (vanilla) |
| **OS** | Linux (Raspberry Pi OS, Ubuntu, Debian) |
| **Deployment** | Standalone, no Docker required |

---

## 🗺 Roadmap

### v1.0 ✅ (Current - Stable)
- ✅ Automated network discovery
- ✅ Manual & automated scanning
- ✅ Live web dashboard
- ✅ TXT report export
- ✅ 24/7 monitoring with scheduling
- ✅ Real-time results without page refresh
- ✅ Network scope validation
- ✅ MANUAL/AUTO scan labeling

### v1.1 (In Development)
- 🔄 Multi-subnet scanning
- 🔄 User role-based access control
- 🔄 Email notifications for critical findings
- 🔄 Vulnerability database integration
- 🔄 PDF report export

### v1.2 (Planned)
- 📋 REST API for third-party integrations
- 📋 Advanced filtering and search
- 📋 Custom scan templates
- 📋 Historical trend analysis
- 📋 Performance metrics

### v2.0 (Future)
- 🚀 Web-based cloud deployment
- 🚀 Mobile app (iOS/Android)
- 🚀 Advanced threat intelligence
- 🚀 Machine learning anomaly detection

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
sudo lsof -i :5000
sudo kill -9 <PID>
bash start.sh
```

### Nmap Not Found
```bash
sudo apt-get update
sudo apt-get install nmap
```

### Scans Failing
- Verify network connectivity: `ping 10.10.10.1`
- Check target is in configured scope
- View logs: `tail -f data/widewolf.log`

### Cannot Access Dashboard
- From Pi: `http://localhost:5000`
- From network: `http://<pi-ip>:5000`
- Check firewall: `sudo ufw allow 5000`

### Database Issues
```bash
# Reset database (WARNING: deletes all scans)
rm data/widewolf.db
bash start.sh
```

### Set Timezone (for correct timestamps)
```bash
sudo timedatectl set-timezone America/New_York
# Or your timezone: Europe/London, Asia/Dubai, etc.
```

---

## ⚠️ Security & Legal

**Lab Use Only** — Designed for authorized lab networks only  
**Scanning Authorization** — Only scan networks you own or have permission to scan  
**Credentials** — Change default admin password immediately  
**Network Isolation** — Run on isolated lab networks, not production networks  
**Compliance** — Ensure compliance with your organization's security policies

---

## 📝 License

**GNU General Public License v3.0**

This means:
- You can use, modify, and distribute this code
- You must credit the original author (Brahim Benhammou)
- Any improvements must also be open-sourced
- No warranty or liability

See LICENSE file for full details.

---

## 👤 Author

**Brahim Benhammou**  
Virginia Western Community College  
ITP 258 — Intrusion Appliance Project  
May 2026

---

## 📞 Support & Contributing

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section above

Contributions and improvements are welcome!

---

**Status:** Stable v1.0 | **Last Updated:** May 5, 2026 | **License:** GPL v3.0 | **Accessible:** localhost, 10.10.10.x, 172.x.x.x
