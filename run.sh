#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
BOLD="\033[1m"; CYAN="\033[1;36m"; GREEN="\033[1;32m"
YELLOW="\033[1;33m"; RED="\033[1;31m"; RESET="\033[0m"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
ask() {
    local prompt="$1" var="$2" default="$3" secret="$4"
    while true; do
        if [[ -n "$default" ]]; then
            printf "${CYAN}%s${RESET} [%s]: " "$prompt" "$default"
        else
            printf "${CYAN}%s${RESET}: " "$prompt"
        fi
        if [[ "$secret" == "1" ]]; then
            IFS= read -rs value; echo
        else
            IFS= read -r value
        fi
        value="${value:-$default}"
        if [[ -n "$value" ]]; then
            eval "$var=\"$value\""
            break
        fi
        echo -e "${RED}Required — please enter a value.${RESET}"
    done
}

ask_optional() {
    local prompt="$1" var="$2" default="$3"
    if [[ -n "$default" ]]; then
        printf "${CYAN}%s${RESET} [%s]: " "$prompt" "$default"
    else
        printf "${CYAN}%s${RESET} (optional, press Enter to skip): " "$prompt"
    fi
    IFS= read -r value
    value="${value:-$default}"
    eval "$var=\"$value\""
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo
echo -e "${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║      Net_mesh — IP-over-Rocket.Chat      ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo

# ---------------------------------------------------------------------------
# Step 1 — virtual environment
# ---------------------------------------------------------------------------
echo -e "${BOLD}[1/4] Python environment${RESET}"
if [[ ! -d ".venv" ]]; then
    echo "Creating virtual environment…"
    python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
echo "Installing dependencies…"
pip install -q cryptography requests websocket-client
echo -e "${GREEN}✓ Dependencies ready${RESET}"
echo

# ---------------------------------------------------------------------------
# Step 2 — Node role (which side of the tunnel is this machine?)
# ---------------------------------------------------------------------------
echo -e "${BOLD}[2/5] Tunnel role${RESET}"
echo -e "  ${YELLOW}A)${RESET} Node A — local ${CYAN}10.0.0.1${RESET} → peer ${CYAN}10.0.0.2${RESET}"
echo -e "  ${YELLOW}B)${RESET} Node B — local ${CYAN}10.0.0.2${RESET} → peer ${CYAN}10.0.0.1${RESET}"
echo
printf "${CYAN}Which node is this machine?${RESET} [A/b]: "
read -r node_choice
node_choice="${node_choice:-A}"
if [[ "$(echo "$node_choice" | tr '[:upper:]' '[:lower:]')" == "b" ]]; then
    TUN_LOCAL_IP="10.0.0.2"
    TUN_PEER_IP="10.0.0.1"
else
    TUN_LOCAL_IP="10.0.0.1"
    TUN_PEER_IP="10.0.0.2"
fi
echo -e "${GREEN}✓ This machine: ${TUN_LOCAL_IP}  Peer: ${TUN_PEER_IP}${RESET}"
echo

# ---------------------------------------------------------------------------
# Step 3 — Rocket.Chat connection details
# ---------------------------------------------------------------------------
echo -e "${BOLD}[3/5] Rocket.Chat server${RESET}"
ask "Server URL (e.g. https://chat.example.com)" RC_URL "${RC_URL:-chat.byparham.com}"
ask_optional "Channel name (without #)" RC_CHANNEL "${RC_CHANNEL:-tunnel}"
echo

# ---------------------------------------------------------------------------
# Step 4 — authentication
# ---------------------------------------------------------------------------
echo -e "${BOLD}[4/5] Authentication${RESET}"
echo -e "  ${YELLOW}A)${RESET} Personal Access Token  ${GREEN}← recommended${RESET}"
echo -e "  ${YELLOW}B)${RESET} Username + Password"
echo
printf "${CYAN}Choose auth method${RESET} [A/b]: "
read -r auth_choice
auth_choice="${auth_choice:-A}"

if [[ "$(echo "$auth_choice" | tr '[:upper:]' '[:lower:]')" == "b" ]]; then
    # Password auth
    ask          "Username"  RC_USERNAME "${RC_USERNAME:-}"
    ask          "Password"  RC_PASSWORD "${RC_PASSWORD:-}" 1
    RC_AUTH_TOKEN=""
    RC_USER_ID=""
else
    # Token auth
    echo
    echo -e "  Go to ${CYAN}My Account → Profile → Personal Access Tokens → Add${RESET}"
    echo
    ask "Auth Token"  RC_AUTH_TOKEN "${RC_AUTH_TOKEN:-}" 1
    ask "User ID"     RC_USER_ID    "${RC_USER_ID:-z2kJnLeuyTYqFcC9P}"
    ask_optional "Username (to suppress echo of own messages)" RC_USERNAME "${RC_USERNAME:-}"
    RC_PASSWORD=""
fi
echo

# ---------------------------------------------------------------------------
# Step 5 — TUN / root check
# ---------------------------------------------------------------------------
echo -e "${BOLD}[5/5] Network interface${RESET}"
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${YELLOW}⚠  TUN interface requires root. Re-launching with sudo…${RESET}"
    echo

    exec sudo \
        RC_URL="$RC_URL" \
        RC_AUTH_TOKEN="$RC_AUTH_TOKEN" \
        RC_USER_ID="$RC_USER_ID" \
        RC_USERNAME="$RC_USERNAME" \
        RC_PASSWORD="$RC_PASSWORD" \
        RC_CHANNEL="$RC_CHANNEL" \
        TUN_LOCAL_IP="$TUN_LOCAL_IP" \
        TUN_PEER_IP="$TUN_PEER_IP" \
        "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/main.py"
fi

# Already root — just export and run
export RC_URL RC_AUTH_TOKEN RC_USER_ID RC_USERNAME RC_PASSWORD RC_CHANNEL TUN_LOCAL_IP TUN_PEER_IP
echo -e "${GREEN}✓ Running as root${RESET}"
echo

exec python "$SCRIPT_DIR/main.py"
