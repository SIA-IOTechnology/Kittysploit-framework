#!/bin/bash
# KittySploit Framework - One-line installer (curl | bash)
# Usage: curl -fsSL https://raw.githubusercontent.com/SIA-IOTechnology/kittysploit-framework/main/install/install-standalone.sh | bash
# Or:    curl -fsSL https://raw.githubusercontent.com/SIA-IOTechnology/kittysploit-framework/main/install/install-standalone.sh | bash -s -- ~/kittysploit-framework

set -e

# Config (update when repo URL changes)
REPO_URL="${KITTYSPLOIT_REPO:-https://github.com/SIA-IOTechnology/kittysploit-framework.git}"
BRANCH="${KITTYSPLOIT_BRANCH:-main}"
DEFAULT_DIR="${HOME}/kittysploit-framework"

# Install directory: first arg, or env, or default
INSTALL_DIR="${1:-${KITTYSPLOIT_INSTALL_DIR:-$DEFAULT_DIR}}"
# Expand ~
INSTALL_DIR="$(echo "$INSTALL_DIR" | sed "s|^~|$HOME|")"
# Resolve to absolute path if parent exists
if [ -d "$(dirname "$INSTALL_DIR")" ]; then
    INSTALL_DIR="$(cd "$(dirname "$INSTALL_DIR")" && pwd)/$(basename "$INSTALL_DIR")"
fi

echo ""
echo "  KittySploit Framework - One-line install"
echo "  Install directory: $INSTALL_DIR"
echo ""

if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/install/install.sh" ]; then
    echo "[*] Directory already exists and looks like KittySploit. Running installer..."
    cd "$INSTALL_DIR"
    chmod +x install/install.sh
    exec ./install/install.sh
fi

if [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
    echo "[!] Error: $INSTALL_DIR exists and is not empty. Use another path or remove it."
    exit 1
fi

# Prefer git clone; fallback to curl + tarball
if command -v git &>/dev/null; then
    echo "[*] Cloning repository..."
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
else
    echo "[*] Git not found. Downloading archive..."
    PARENT="$(dirname "$INSTALL_DIR")"
    DIRNAME="$(basename "$INSTALL_DIR")"
    TARBALL="https://github.com/SIA-IOTechnology/kittysploit-framework/archive/refs/heads/${BRANCH}.tar.gz"
    EXTRACTED="kittysploit-framework-${BRANCH}"
    mkdir -p "$PARENT"
    if command -v curl &>/dev/null; then
        ( cd "$PARENT" && curl -fsSL "$TARBALL" | tar xz && mv "$EXTRACTED" "$DIRNAME" )
    elif command -v wget &>/dev/null; then
        ( cd "$PARENT" && wget -qO- "$TARBALL" | tar xz && mv "$EXTRACTED" "$DIRNAME" )
    else
        echo "[!] Error: need 'git' or 'curl'/'wget' to download KittySploit."
        exit 1
    fi
fi

if [ ! -f "$INSTALL_DIR/install/install.sh" ]; then
    echo "[!] Error: install script not found in $INSTALL_DIR"
    exit 1
fi

echo "[*] Running KittySploit installer..."
cd "$INSTALL_DIR"
chmod +x install/install.sh
exec ./install/install.sh
