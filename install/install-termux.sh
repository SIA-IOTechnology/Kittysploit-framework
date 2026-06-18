#!/data/data/com.termux/files/usr/bin/bash
# KittySploit Framework - Termux (Android) Installer
# ===================================================
# Handles packages that fail to compile on Termux:
#   psutil, cryptography, bcrypt, Pillow, pymssql, etc.
#
# NOTE: no "set -e" — individual failures are caught per-package
#       so the entire script always runs to completion.

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
    cmake \
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
    freetds \
    2>/dev/null || true

echo -e "${GREEN}[+]${NC} System dependencies installed"
echo

# ---------------------------------------------------------------------------
# 3. Environment variables needed for native compilation in Termux
# ---------------------------------------------------------------------------
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
export CARGO_BUILD_TARGET=""
export CFLAGS="-Wno-error -Wno-incompatible-function-pointer-types"
export LDFLAGS="-L${PREFIX}/lib"
export CPPFLAGS="-I${PREFIX}/include"
export PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig"
export OPENSSL_DIR="$PREFIX"
export OPENSSL_INCLUDE_DIR="${PREFIX}/include"
export OPENSSL_LIB_DIR="${PREFIX}/lib"
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

$PIP install --upgrade pip setuptools wheel 2>/dev/null || true
echo

# ---------------------------------------------------------------------------
# 6. Helpers
# ---------------------------------------------------------------------------

TERMUX_TMP="${TMPDIR:-${PREFIX}/tmp}"
mkdir -p "$TERMUX_TMP"

SKIPPED=()
INSTALLED=()
FAILED=()

install_pkg() {
    local name="$1"
    shift
    echo -ne "  ${YELLOW}→${NC} $name ... "
    if $PIP install "$@" 2>"$TERMUX_TMP/kittysploit_pip_err.log"; then
        echo -e "${GREEN}OK${NC}"
        INSTALLED+=("$name")
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
}

install_or_skip() {
    local name="$1"
    shift
    if ! install_pkg "$name" "$@"; then
        echo -e "    ${YELLOW}[!] Skipped $name${NC}"
        SKIPPED+=("$name")
    fi
}

# ---------------------------------------------------------------------------
# 7. Install ALL packages from requirements.txt, grouped by build complexity
# ---------------------------------------------------------------------------

# -- Group A: Pure-Python core (should always succeed) ----------------------
echo -e "${YELLOW}[*]${NC} [1/8] Core pure-Python packages..."
install_or_skip "requests"          requests
install_or_skip "msgpack"           msgpack
install_or_skip "colorama"          colorama
install_or_skip "prompt_toolkit"    prompt_toolkit
install_or_skip "six"               six
install_or_skip "toml"              toml
install_or_skip "websockets"        websockets
install_or_skip "websocket-client"  websocket-client
install_or_skip "dnslib"            dnslib
install_or_skip "netaddr"           netaddr
install_or_skip "xmltodict"         xmltodict
install_or_skip "paho-mqtt"         paho-mqtt
echo

# -- Group B: Crypto (needs rust + openssl) ---------------------------------
echo -e "${YELLOW}[*]${NC} [2/8] Cryptography packages (may take several minutes)..."

if ! install_pkg "cryptography" cryptography --only-binary :all: 2>/dev/null; then
    echo -e "  ${YELLOW}→${NC} No binary wheel, building from source..."
    if ! install_pkg "cryptography" cryptography --no-build-isolation 2>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Retrying without Rust backend..."
        CRYPTOGRAPHY_DONT_BUILD_RUST=1 install_or_skip "cryptography" cryptography
    fi
fi

install_or_skip "pycryptodome"  pycryptodome
install_or_skip "bcrypt"        "bcrypt==4.0.1" --no-build-isolation
install_or_skip "paramiko"      paramiko
install_or_skip "pyjwt"         pyjwt
echo

# -- Group C: Web frameworks -----------------------------------------------
echo -e "${YELLOW}[*]${NC} [3/8] Web frameworks..."
install_or_skip "flask"             flask
install_or_skip "flask-cors"        flask-cors
install_or_skip "flask-socketio"    flask-socketio
install_or_skip "fastapi"           fastapi
install_or_skip "python-multipart"  python-multipart
install_or_skip "uvicorn"           uvicorn
echo

# -- Group D: Network & security -------------------------------------------
echo -e "${YELLOW}[*]${NC} [4/8] Network & security..."
install_or_skip "aiohttp"           aiohttp
install_or_skip "scapy"             scapy
install_or_skip "dnspython"         dnspython
install_or_skip "python-whois"      python-whois
echo

# -- Group E: System utilities ----------------------------------------------
echo -e "${YELLOW}[*]${NC} [5/8] System utilities..."
install_or_skip "psutil"            psutil
install_or_skip "Pillow"            Pillow
install_or_skip "pyserial"          pyserial
install_or_skip "docker"            docker
install_or_skip "boto3"             boto3
install_or_skip "reportlab"         reportlab
echo

# -- Group F: Database clients ----------------------------------------------
echo -e "${YELLOW}[*]${NC} [6/8] Database clients..."
install_or_skip "sqlalchemy"        sqlalchemy
install_or_skip "pymysql"           pymysql
install_or_skip "redis"             redis
install_or_skip "pymongo"           pymongo
install_or_skip "ldap3"             ldap3
install_or_skip "elasticsearch"     elasticsearch

# psycopg2-binary: try binary first, then source build with Termux libpq
if ! install_pkg "psycopg2-binary" psycopg2-binary 2>/dev/null; then
    install_or_skip "psycopg2" psycopg2
fi

# pymssql needs FreeTDS (sqlfront.h). Try with pkg-installed freetds headers.
if [ -f "${PREFIX}/include/sqlfront.h" ] || [ -f "${PREFIX}/include/freetds/sqlfront.h" ]; then
    install_or_skip "pymssql" pymssql
else
    echo -e "  ${YELLOW}→${NC} pymssql ... ${RED}SKIPPED${NC} (FreeTDS/sqlfront.h not available on Termux)"
    SKIPPED+=("pymssql")
fi
echo

# -- Group G: Misc / optional -----------------------------------------------
echo -e "${YELLOW}[*]${NC} [7/8] Optional packages..."
install_or_skip "bs4"              bs4
install_or_skip "pure-python-adb"  pure-python-adb
install_or_skip "pyftpdlib"        pyftpdlib
install_or_skip "pyngrok"          pyngrok
install_or_skip "pysnmp"           pysnmp
install_or_skip "pysmb"            pysmb
install_or_skip "mcp"              mcp
echo

# -- Group H: Platform-specific (unlikely to work on Android) ---------------
echo -e "${YELLOW}[*]${NC} [8/8] Platform-specific packages (may be skipped)..."
install_or_skip "aiomqtt"          aiomqtt
install_or_skip "bleak"            bleak
install_or_skip "nava"             nava
install_or_skip "pychromecast"     pychromecast
install_or_skip "python-can"       python-can
install_or_skip "mitmproxy"        mitmproxy
echo

# ---------------------------------------------------------------------------
# 8. Create start script
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
# 9. Create Termux shortcut (widget / launcher)
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
# 10. Summary
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

echo -e "${GREEN}Installed: ${#INSTALLED[@]} packages${NC}"

if [ ${#SKIPPED[@]} -gt 0 ]; then
    echo -e "${YELLOW}Skipped: ${#SKIPPED[@]} packages:${NC}"
    for s in "${SKIPPED[@]}"; do
        echo -e "  - $s"
    done
    echo
    echo -e "${YELLOW}You can retry any later with:${NC}"
    echo -e "  source venv/bin/activate"
    echo -e "  pip install <package>"
    echo
fi

echo -e "${BLUE}Troubleshooting:${NC}"
echo -e "  cryptography : pkg install rust openssl && pip install cryptography --no-build-isolation"
echo -e "  psutil       : pkg install clang && pip install psutil"
echo -e "  Pillow       : pkg install libjpeg-turbo libpng && pip install Pillow"
echo -e "  psycopg2     : pkg install postgresql && pip install psycopg2"
echo -e "  pymssql      : needs FreeTDS (sqlfront.h) — not in Termux repos, skip it"
echo -e "  bleak        : Bluetooth not supported on stock Termux"
echo
echo -e "${YELLOW}Note:${NC} If cryptography could not be installed, the framework will"
echo -e "  still work but without database encryption (data stored in plaintext)."
echo
