#!/data/data/com.termux/files/usr/bin/bash
# KittySploit Framework - Termux (Android) Installer
# ===================================================
# Handles packages that fail to compile on Termux:
#   psutil, cryptography, bcrypt, Pillow, scapy, etc.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              KittySploit Framework                          ║"
echo "║              Termux (Android) Installer                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ---------------------------------------------------------------------------
# 1. Sanity checks
# ---------------------------------------------------------------------------
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}[!]${NC} This script is intended for Termux on Android."
    echo -e "${RED}[!]${NC} Use install.sh for standard Linux/macOS."
    exit 1
fi

if ! command -v pkg &>/dev/null; then
    echo -e "${RED}[!]${NC} 'pkg' not found. Are you running inside Termux?"
    exit 1
fi

echo -e "${YELLOW}[*]${NC} Detected Termux environment"
echo

# ---------------------------------------------------------------------------
# 2. Install system-level dependencies via pkg
#    These provide the C libraries / headers that pip packages need.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[*]${NC} Updating package repositories..."
pkg update -y && pkg upgrade -y

echo -e "${YELLOW}[*]${NC} Installing system dependencies..."
pkg install -y \
    python \
    python-pip \
    git \
    clang \
    make \
    pkg-config \
    openssl \
    libffi \
    libjpeg-turbo \
    libpng \
    freetype \
    libxml2 \
    libxslt \
    libzmq \
    rust \
    binutils \
    libcrypt \
    zlib \
    postgresql \
    mariadb \
    2>/dev/null || true

echo -e "${GREEN}[+]${NC} System dependencies installed"
echo

# ---------------------------------------------------------------------------
# 3. Environment variables needed for native compilation in Termux
# ---------------------------------------------------------------------------
export CARGO_BUILD_TARGET=""
export CFLAGS="-Wno-error -Wno-incompatible-function-pointer-types"
export LDFLAGS="-L/data/data/com.termux/files/usr/lib"
export CPPFLAGS="-I/data/data/com.termux/files/usr/include"
export PKG_CONFIG_PATH="/data/data/com.termux/files/usr/lib/pkgconfig"
export CRYPTOGRAPHY_DONT_BUILD_RUST=0
export SODIUM_INSTALL="system"

# ---------------------------------------------------------------------------
# 4. Determine project root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/../kittyconsole.py" ]; then
    PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -f "kittyconsole.py" ]; then
    PROJECT_DIR="$(pwd)"
elif [ -f "install/requirements.txt" ]; then
    PROJECT_DIR="$(pwd)"
else
    echo -e "${RED}[!]${NC} Cannot find project root. Run this script from the KittySploit directory"
    echo -e "${RED}[!]${NC} or from install/  (e.g.  bash install/install-termux.sh)"
    exit 1
fi

cd "$PROJECT_DIR"
echo -e "${GREEN}[+]${NC} Project directory: $PROJECT_DIR"
echo

# ---------------------------------------------------------------------------
# 5. Virtual environment
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[*]${NC} Setting up Python virtual environment..."

if [ -z "$VIRTUAL_ENV" ]; then
    python -m venv venv 2>/dev/null || python3 -m venv venv 2>/dev/null || {
        echo -e "${YELLOW}[!]${NC} venv creation failed, installing globally instead"
    }
    if [ -d "venv" ]; then
        source venv/bin/activate
        echo -e "${GREEN}[+]${NC} Virtual environment created & activated"
    fi
else
    echo -e "${GREEN}[+]${NC} Already inside venv: $VIRTUAL_ENV"
fi

PIP="pip"
if command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
    PIP="pip3"
fi

$PIP install --upgrade pip setuptools wheel
echo

# ---------------------------------------------------------------------------
# 6. Install packages in ordered groups so failures are isolated
# ---------------------------------------------------------------------------

TERMUX_TMP="${TMPDIR:-${PREFIX:-/data/data/com.termux/files/usr}/tmp}"
mkdir -p "$TERMUX_TMP"

install_pkg() {
    local name="$1"
    shift
    echo -ne "  ${YELLOW}→${NC} $name ... "
    if $PIP install "$@" 2>"$TERMUX_TMP/kittysploit_pip_err.log"; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
}

install_or_warn() {
    local name="$1"
    shift
    if ! install_pkg "$name" "$@"; then
        echo -e "    ${YELLOW}[!] Skipping $name (not critical on Termux)${NC}"
        SKIPPED+=("$name")
    fi
}

SKIPPED=()

# -- Group A: Core (must succeed) ------------------------------------------
echo -e "${YELLOW}[*]${NC} Installing core dependencies..."

install_pkg "requests"          requests
install_pkg "msgpack"           msgpack
install_pkg "colorama"          colorama
install_pkg "prompt_toolkit"    prompt_toolkit
install_pkg "six"               six
install_pkg "toml"              toml
install_pkg "websockets"        websockets
install_pkg "websocket-client"  websocket-client
install_pkg "aiohttp"           aiohttp
install_pkg "dnslib"            dnslib
install_pkg "netaddr"           netaddr
install_pkg "xmltodict"         xmltodict
install_pkg "paho-mqtt"         paho-mqtt
echo

# -- Group B: Crypto (needs rust + openssl) ---------------------------------
echo -e "${YELLOW}[*]${NC} Installing cryptography packages (needs Rust compiler)..."
echo -e "${YELLOW}[*]${NC} This may take several minutes on first install..."

install_or_warn "cryptography"  cryptography
install_or_warn "pycryptodome"  pycryptodome
install_or_warn "bcrypt"        bcrypt
install_or_warn "paramiko"      paramiko
install_or_warn "pyjwt"         pyjwt
echo

# -- Group C: Web frameworks -----------------------------------------------
echo -e "${YELLOW}[*]${NC} Installing web frameworks..."

install_pkg "flask"             flask
install_pkg "flask-cors"        flask-cors
install_pkg "flask-socketio"    flask-socketio
install_pkg "fastapi"           fastapi
install_pkg "python-multipart"  python-multipart
install_pkg "uvicorn"           uvicorn
echo

# -- Group D: Network / security --------------------------------------------
echo -e "${YELLOW}[*]${NC} Installing network & security packages..."

install_or_warn "scapy"         scapy
install_or_warn "dnspython"     dnspython
install_or_warn "python-whois"  python-whois
echo

# -- Group E: System utilities (psutil is the big one) ----------------------
echo -e "${YELLOW}[*]${NC} Installing system utilities..."

install_or_warn "psutil"        psutil
install_or_warn "Pillow"        Pillow
install_or_warn "pyserial"      pyserial
install_or_warn "docker"        docker
install_or_warn "boto3"         boto3
echo

# -- Group F: Database clients ----------------------------------------------
echo -e "${YELLOW}[*]${NC} Installing database clients..."

install_or_warn "sqlalchemy"    sqlalchemy
install_or_warn "pymysql"       pymysql
install_or_warn "redis"         redis
install_or_warn "pymongo"       pymongo
install_or_warn "ldap3"         ldap3
install_or_warn "elasticsearch" elasticsearch

# psycopg2-binary often fails on Termux; try psycopg2 with pkg-installed libpq
if ! install_pkg "psycopg2-binary" psycopg2-binary 2>/dev/null; then
    install_or_warn "psycopg2" psycopg2
fi

install_or_warn "pymssql"       pymssql
echo

# -- Group G: Misc / optional -----------------------------------------------
echo -e "${YELLOW}[*]${NC} Installing optional packages..."

install_or_warn "bs4"              bs4
install_or_warn "reportlab"        reportlab
install_or_warn "pure-python-adb"  pure-python-adb
install_or_warn "pyftpdlib"        pyftpdlib
install_or_warn "pyngrok"          pyngrok
install_or_warn "pysnmp"           pysnmp
install_or_warn "pysmb"            pysmb
install_or_warn "mcp"              mcp
echo

# -- Group H: Packages unlikely to work on Termux (skip gracefully) ---------
echo -e "${YELLOW}[*]${NC} Attempting platform-specific packages (may be skipped)..."

install_or_warn "asyncio-mqtt"     asyncio-mqtt
install_or_warn "bleak"            bleak
install_or_warn "nava"             nava
install_or_warn "pychromecast"     pychromecast
install_or_warn "python-can"       python-can
install_or_warn "mitmproxy"        mitmproxy
echo

# ---------------------------------------------------------------------------
# 7. Create start script
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[*]${NC} Creating start script..."

cat > "$PROJECT_DIR/start_kittysploit.sh" << 'STARTEOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")"
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python kittyconsole.py "$@"
STARTEOF

chmod +x "$PROJECT_DIR/start_kittysploit.sh"
echo -e "${GREEN}[+]${NC} start_kittysploit.sh created"
echo

# ---------------------------------------------------------------------------
# 8. Create Termux shortcut (widget / launcher)
# ---------------------------------------------------------------------------
SHORTCUT_DIR="$HOME/.shortcuts"
if [ -d "$SHORTCUT_DIR" ] || command -v termux-widget &>/dev/null; then
    mkdir -p "$SHORTCUT_DIR"
    cat > "$SHORTCUT_DIR/KittySploit" << WIDGETEOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$PROJECT_DIR"
if [ -d "venv" ]; then source venv/bin/activate; fi
python kittyconsole.py
WIDGETEOF
    chmod +x "$SHORTCUT_DIR/KittySploit"
    echo -e "${GREEN}[+]${NC} Termux widget shortcut created (~/.shortcuts/KittySploit)"
fi

# ---------------------------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------------------------
echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}   KittySploit Framework installed on Termux!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo
echo -e "${BLUE}How to start:${NC}"
echo -e "  ./start_kittysploit.sh"
echo -e "  # or"
echo -e "  source venv/bin/activate && python kittyconsole.py"
echo

if [ ${#SKIPPED[@]} -gt 0 ]; then
    echo -e "${YELLOW}Packages skipped (not critical or unsupported on Termux):${NC}"
    for s in "${SKIPPED[@]}"; do
        echo -e "  - $s"
    done
    echo
    echo -e "${YELLOW}You can retry any of them later with:${NC}"
    echo -e "  source venv/bin/activate"
    echo -e "  pip install <package>"
    echo
fi

echo -e "${BLUE}Troubleshooting tips:${NC}"
echo -e "  - If cryptography failed  : pkg install rust openssl && pip install cryptography"
echo -e "  - If psutil failed        : pkg install clang python-dev && pip install psutil"
echo -e "  - If Pillow failed        : pkg install libjpeg-turbo libpng && pip install Pillow"
echo -e "  - If psycopg2 failed      : pkg install postgresql && pip install psycopg2"
echo -e "  - For Bluetooth (bleak)   : not supported on stock Termux"
echo
