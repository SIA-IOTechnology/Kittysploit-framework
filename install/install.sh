#!/bin/bash
# KittySploit Framework Linux/macOS Installer
# ===========================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  KittySploit Framework                       ║"
echo "║                  Linux/macOS Installer                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if Python 3 is installed
echo -e "${YELLOW}[*]${NC} Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!]${NC} Error: Python 3 is not installed"
    echo -e "${RED}[!]${NC} Please install Python 3.8+ from your package manager"
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
    echo -e "${RED}[!]${NC} Error: Python 3.8 or higher is required"
    echo -e "${RED}[!]${NC} Current version: $python_version"
    exit 1
fi

echo -e "${GREEN}[+]${NC} Python version: $python_version - OK"
echo

# Check if pip is available (pip3 binary or python3 -m pip)
echo -e "${YELLOW}[*]${NC} Checking pip installation..."
USE_PIP_MODULE=0
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[+]${NC} pip3 found"
elif python3 -m pip --version &> /dev/null; then
    echo -e "${GREEN}[+]${NC} pip available via python3 -m pip"
    USE_PIP_MODULE=1
else
    echo -e "${YELLOW}[*]${NC} pip not found, attempting to bootstrap with ensurepip..."
    if python3 -m ensurepip --upgrade 2>/dev/null; then
        if python3 -m pip --version &> /dev/null; then
            echo -e "${GREEN}[+]${NC} pip installed via ensurepip"
            USE_PIP_MODULE=1
        else
            echo -e "${RED}[!]${NC} ensurepip ran but pip still not available"
            echo -e "${YELLOW}[*]${NC} Try: sudo apt-get install python3-pip  (Debian/Ubuntu)"
            exit 1
        fi
    else
        echo -e "${RED}[!]${NC} Error: pip is not available and ensurepip failed"
        echo -e "${YELLOW}[*]${NC} Try: sudo apt-get install python3-pip python3-venv  (Debian/Ubuntu)"
        exit 1
    fi
fi
echo

# Get project root directory
PROJECT_DIR=$(pwd)

# Check if we're in a virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}[*]${NC} Not in a virtual environment, checking venv support..."
    
    # Check if python3-venv is available
    if ! python3 -m venv --help &> /dev/null; then
        echo -e "${YELLOW}[*]${NC} python3-venv module not found, attempting to install..."
        
        # Try to install python3-venv based on the distribution
        if command -v apt-get &> /dev/null; then
            echo -e "${YELLOW}[*]${NC} Detected Debian/Ubuntu, installing python3-venv..."
            sudo apt-get update && sudo apt-get install -y python3-venv
        elif command -v yum &> /dev/null; then
            echo -e "${YELLOW}[*]${NC} Detected RHEL/CentOS, installing python3-venv..."
            sudo yum install -y python3-venv
        elif command -v dnf &> /dev/null; then
            echo -e "${YELLOW}[*]${NC} Detected Fedora, installing python3-venv..."
            sudo dnf install -y python3-venv
        elif command -v pacman &> /dev/null; then
            echo -e "${YELLOW}[*]${NC} Detected Arch Linux, installing python-venv..."
            sudo pacman -S --noconfirm python-venv
        elif command -v brew &> /dev/null; then
            echo -e "${YELLOW}[*]${NC} Detected macOS with Homebrew, venv should be available..."
        else
            echo -e "${YELLOW}[!]${NC} Could not detect package manager. Please install python3-venv manually."
            echo -e "${YELLOW}[!]${NC} Continuing without venv (packages will be installed globally)..."
            VENV_PATH=""
        fi
    fi
    
    # Create venv if python3-venv is now available
    if python3 -m venv --help &> /dev/null; then
        echo -e "${YELLOW}[*]${NC} Creating virtual environment..."
        python3 -m venv venv
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+]${NC} Virtual environment created: venv/"
            VENV_PATH="$PROJECT_DIR/venv"
            # Activate venv
            source "$VENV_PATH/bin/activate"
            echo -e "${GREEN}[+]${NC} Virtual environment activated"
        else
            echo -e "${RED}[!]${NC} Failed to create virtual environment"
            echo -e "${YELLOW}[!]${NC} Continuing without venv (packages will be installed globally)..."
            VENV_PATH=""
        fi
    else
        VENV_PATH=""
    fi
else
    echo -e "${GREEN}[+]${NC} Already in a virtual environment: $VIRTUAL_ENV"
    VENV_PATH="$VIRTUAL_ENV"
fi
echo

# Determine which pip/python to use
if [ -n "$VENV_PATH" ] && [ -f "$VENV_PATH/bin/pip" ]; then
    PIP_CMD="$VENV_PATH/bin/pip"
    PYTHON_CMD="$VENV_PATH/bin/python"
else
    if [ "$USE_PIP_MODULE" = "1" ]; then
        PIP_CMD="python3 -m pip"
        PYTHON_CMD="python3"
    else
        PIP_CMD="pip3"
        PYTHON_CMD="python3"
    fi
fi

# Install requirements
echo -e "${YELLOW}[*]${NC} Installing Python requirements..."
$PIP_CMD install --upgrade pip
$PIP_CMD install -r install/requirements.txt

if [ $? -ne 0 ]; then
    echo -e "${RED}[!]${NC} Error: Failed to install requirements"
    exit 1
fi

echo -e "${GREEN}[+]${NC} Requirements installed successfully"
echo

# Install Zig compiler
echo -e "${YELLOW}[*]${NC} Installing Zig compiler..."
$PYTHON_CMD -c "
import sys
from pathlib import Path
sys.path.insert(0, r'$PROJECT_DIR')
try:
    from core.lib.compiler.zig_installer import install_zig_if_needed
    if install_zig_if_needed(ask_confirmation=False):
        print('[+] Zig compiler installed successfully')
    else:
        print('[!] Warning: Zig compiler installation failed, but continuing...')
except Exception as e:
    print(f'[!] Warning: Could not install Zig compiler: {e}')
    print('[!] You can install Zig manually later or it will be installed automatically when needed')
"

echo

# Create start script
echo -e "${YELLOW}[*]${NC} Creating start script..."
if [ -n "$VENV_PATH" ]; then
    cat > start_kittysploit.sh << EOF
#!/bin/bash
cd "\$(dirname "\$0")"
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python3 kittyconsole.py
EOF
else
    cat > start_kittysploit.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
python3 kittyconsole.py
EOF
fi

chmod +x start_kittysploit.sh
echo -e "${GREEN}[+]${NC} Start script created: start_kittysploit.sh"
echo

# Create uninstall script
echo -e "${YELLOW}[*]${NC} Creating uninstall script..."
if [ -n "$VENV_PATH" ]; then
    cat > uninstall.sh << EOF
#!/bin/bash
echo "Uninstalling KittySploit Framework..."
echo ""
echo "This will remove:"
if [ -d "venv" ]; then
    echo "- Virtual environment (venv/)"
fi
echo "- Python packages installed for KittySploit"
echo "- Start scripts"
echo ""
read -p "Are you sure? (y/N): " confirm
if [[ \$confirm == [yY] ]]; then
    echo ""
    if [ -d "venv" ]; then
        echo "Removing virtual environment..."
        rm -rf venv
    fi
    echo "Removing Python packages..."
    if [ -d "venv" ] && [ -f "venv/bin/pip" ]; then
        venv/bin/pip uninstall -y -r install/requirements.txt
    else
        pip3 uninstall -y -r install/requirements.txt
    fi
    echo ""
    echo "Removing start scripts..."
    rm -f start_kittysploit.sh
    echo ""
    echo "KittySploit Framework uninstalled successfully!"
else
    echo "Uninstall cancelled."
fi
EOF
else
    cat > uninstall.sh << 'EOF'
#!/bin/bash
echo "Uninstalling KittySploit Framework..."
echo ""
echo "This will remove:"
echo "- Python packages installed for KittySploit"
echo "- Start scripts"
echo ""
read -p "Are you sure? (y/N): " confirm
if [[ $confirm == [yY] ]]; then
    echo ""
    echo "Removing Python packages..."
    pip3 uninstall -y -r install/requirements.txt
    echo ""
    echo "Removing start scripts..."
    rm -f start_kittysploit.sh
    echo ""
    echo "KittySploit Framework uninstalled successfully!"
else
    echo "Uninstall cancelled."
fi
EOF
fi

chmod +x uninstall.sh
echo -e "${GREEN}[+]${NC} Uninstall script created: uninstall.sh"
echo

# Create environment setup
echo -e "${YELLOW}[*]${NC} Creating environment setup..."
cat > env_setup.py << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittySploit Environment Setup
"""

import os
import sys
from pathlib import Path

def setup_environment():
    """Setup KittySploit environment"""
    print("Setting up KittySploit environment...")
    
    # Add current directory to Python path
    current_dir = Path(__file__).parent.absolute()
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    
    # Set environment variables
    os.environ['KITTYSPLOIT_HOME'] = str(current_dir)
    os.environ['KITTYSPLOIT_VERSION'] = '1.0.0'
    
    print(f"KittySploit home: {current_dir}")
    print("Environment setup complete!")

if __name__ == "__main__":
    setup_environment()
EOF

chmod +x env_setup.py
echo -e "${GREEN}[+]${NC} Environment setup created: env_setup.py"
echo

# Create desktop entry (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${YELLOW}[*]${NC} Creating desktop entry..."
    
    # Find icon file (PNG, SVG, or ICO)
    PROJECT_DIR=$(pwd)
    ICON_PATH=""
    
    # Try to find icon in order of preference
    for icon_file in "install/kittysploit.png" "install/kittysploit.svg" "install/kittysploit.ico" \
                     "kittysploit.png" "kittysploit.svg" "kittysploit.ico" \
                     "icon.png" "icon.svg" "icon.ico"; do
        if [ -f "$PROJECT_DIR/$icon_file" ]; then
            ICON_PATH="$PROJECT_DIR/$icon_file"
            break
        fi
    done
    
    # If no icon found, use a default or Python icon
    if [ -z "$ICON_PATH" ]; then
        # Try to use Python's icon or a system default
        if command -v python3 &> /dev/null; then
            PYTHON_PATH=$(which python3)
            # Some systems have Python icons in /usr/share/pixmaps
            if [ -f "/usr/share/pixmaps/python3.xpm" ]; then
                ICON_PATH="/usr/share/pixmaps/python3.xpm"
            elif [ -f "/usr/share/pixmaps/python3.png" ]; then
                ICON_PATH="/usr/share/pixmaps/python3.png"
            else
                # Fallback to a generic terminal icon
                ICON_PATH="utilities-terminal"
            fi
        else
            ICON_PATH="utilities-terminal"
        fi
    fi
    
    # Create desktop entry directory if it doesn't exist
    mkdir -p ~/.local/share/applications
    
    cat > ~/.local/share/applications/kittysploit.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=KittySploit Framework
Comment=Advanced penetration testing framework
Exec=$PROJECT_DIR/start_kittysploit.sh
Icon=$ICON_PATH
Terminal=true
Categories=Security;Network;
Keywords=security;penetration;testing;framework;hacking;
EOF
    
    # Make desktop entry executable
    chmod +x ~/.local/share/applications/kittysploit.desktop
    
    echo -e "${GREEN}[+]${NC} Desktop entry created: ~/.local/share/applications/kittysploit.desktop"
    if [ -n "$ICON_PATH" ] && [ "$ICON_PATH" != "utilities-terminal" ]; then
        echo -e "${GREEN}[+]${NC} Using icon: $ICON_PATH"
    fi
    echo
fi

# Success message
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}   KittySploit Framework installed successfully!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo
echo -e "${BLUE}📋 What was installed:${NC}"
if [ -n "$VENV_PATH" ]; then
    echo -e "  ✓ Virtual environment (venv/)"
fi
echo -e "  ✓ Python requirements"
echo -e "  ✓ Zig compiler (in core/lib/compiler/zig_executable/)"
echo -e "  ✓ Start script (start_kittysploit.sh)"
echo -e "  ✓ Uninstall script (uninstall.sh)"
echo -e "  ✓ Environment setup (env_setup.py)"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "  ✓ Desktop entry"
fi
echo
echo -e "${BLUE} How to start KittySploit:${NC}"
echo -e "  • Run: ./start_kittysploit.sh"
echo -e "  • Or run: python3 kittyconsole.py"
echo
echo -e "${BLUE}  To uninstall:${NC}"
echo -e "  • Run: ./uninstall.sh"
echo
