#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# WideWolf — Network Intrusion Testing Appliance
# ITP 258 — First-Time Setup Script
# FOR EDUCATIONAL USE ONLY
# ═══════════════════════════════════════════════════════════════════════════

set -e
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  WideWolf — Network Intrusion Testing Appliance${NC}"
echo -e "${CYAN}  ITP 258 — Setup Script${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if running as root for system tools
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Running without root. Some features (nmap, tshark) need sudo.${NC}"
    echo -e "${YELLOW}    Run with: sudo ./setup.sh${NC}"
    echo ""
fi

# 1. System packages
echo -e "${GREEN}[1/4]${NC} Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq nmap tshark python3 python3-pip ufw > /dev/null 2>&1
echo -e "${GREEN}[OK]${NC} nmap, tshark, python3, ufw installed"

# 2. Set capture permissions (so tshark works without root)
echo -e "${GREEN}[2/4]${NC} Setting capture permissions..."
sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap) 2>/dev/null || true
echo -e "${GREEN}[OK]${NC} Capture permissions set"

# 3. Python packages
echo -e "${GREEN}[3/4]${NC} Installing Python packages..."
pip3 install -q flask
echo -e "${GREEN}[OK]${NC} Python packages ready"

# 4. Create data directories
echo -e "${GREEN}[4/4]${NC} Creating data directories..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$SCRIPT_DIR/data/scans" "$SCRIPT_DIR/data/captures" "$SCRIPT_DIR/data/reports"
echo -e "${GREEN}[OK]${NC} Data directories created"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete! Run ./start.sh to launch WideWolf.${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
