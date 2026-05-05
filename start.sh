#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# WideWolf — One-Click Launcher
# ═══════════════════════════════════════════════════════════════════════════
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  WideWolf — Network Intrusion Testing Appliance${NC}"
echo -e "${CYAN}  ITP 258 — Starting...${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""
# Check dependencies
MISSING=""
which nmap > /dev/null 2>&1 || MISSING="$MISSING nmap"
which tshark > /dev/null 2>&1 || MISSING="$MISSING tshark"
which python3 > /dev/null 2>&1 || MISSING="$MISSING python3"
if [ -n "$MISSING" ]; then
    echo -e "${YELLOW}[!] Missing:${MISSING}${NC}"
    echo -e "${YELLOW}    Running setup first...${NC}"
    echo ""
    chmod +x setup.sh && sudo ./setup.sh
fi
# Check Flask
python3 -c "import flask" 2>/dev/null || {
    echo -e "${YELLOW}[!] Flask not found. Installing...${NC}"
    pip3 install -q flask
}
# Create data dirs
mkdir -p data/scans data/captures data/reports
# Get local IP
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$LOCAL_IP" ] && LOCAL_IP="127.0.0.1"
echo -e "${GREEN}  WideWolf is LIVE${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Open browser on your admin PC:"
echo -e "    ${CYAN}http://${LOCAL_IP}:5000${NC}"
echo ""
echo -e "  Also accessible at:   http://127.0.0.1:5000"
echo ""
echo -e "  Press Ctrl+C to stop WideWolf."
echo ""
echo -e "${YELLOW}  FOR EDUCATIONAL USE ONLY — ITP 258${NC}"
echo ""
# Launch Flask from project root (NOT from app/ subdirectory)
python3 app/main.py
