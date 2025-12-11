<div align="center">
  <img src="https://app.kittysploit.com/static/img/icon-72x72.png" alt="KittySploit Logo" width="72" height="72">
</div>

# KittySploit Framework

Modular penetration testing framework with CLI interface, REST API and RPC server.

## Requirements

- Python 3.8 or higher
- 500 MB of free disk space (recommended for comfortable usage because we install Zig compiler)
- Docker (optional, for Docker environment modules)

## Installation

### Automatic Installation (Recommended)

#### Windows
```batch
cd kittysploit-framework
install\install.bat
```

#### Linux / macOS
```bash
cd kittysploit-framework
chmod +x install/install.sh
./install/install.sh
```

The installer will:
- ✅ Check Python version (3.8+ required)
- ✅ Install all required dependencies
- ✅ Install Zig compiler (0.16)
- ✅ Create start scripts
- ✅ Create desktop shortcuts

### Manual Installation

```bash
git clone https://github.com/your-username/kittysploit-framework.git
cd kittysploit-framework
python -m venv venv
source venv/bin/activate
pip install -r install/requirements.txt
```

## Usage

### Quick Start

After installation, you can start KittySploit using:

**Windows:**
- Double-click `start_kittysploit.bat`
- Or double-click `KittySploit.lnk` (shortcut with icon)
- Or run: `python kittyconsole.py`

**Linux / macOS:**
- Run: `./start_kittysploit.sh`
- Or run: `python3 kittyconsole.py`

### CLI Mode
```bash
python kittyconsole.py
```

### API Mode
```bash
python kittyapi.py -H 0.0.0.0 -p 5000 -m "master_key"
```

### RPC Mode
```bash
python kittyrpc.py -H 0.0.0.0 -p 8888 -m "master_key"
```

## Components

### KittyProxy

KittyProxy is a web-based HTTP/HTTPS proxy interface that provides real-time traffic interception, analysis, and manipulation capabilities. It features:

- **Live Traffic Monitoring**: View and analyze HTTP/HTTPS requests and responses in real-time
- **Request/Response Modification**: Intercept and modify requests before they reach the target server
- **Repeater & Intruder Tools**: Replay and fuzz requests with customizable payloads
- **Technology Detection**: Automatically detect web technologies and frameworks
- **Endpoint Discovery**: Extract and visualize API endpoints, GraphQL queries, and more
- **Performance Monitoring**: Track response times and analyze request patterns
- **Plugin System**: Extensible architecture for custom interception plugins

Start KittyProxy:
```bash
python kittyproxy.py 
```

Access the web interface at `http://localhost:8000`

### KittyCollab

KittyCollab is a real-time collaborative code editor that enables multiple penetration testers to work together on the same exploit or module. It provides:

- **Room Management**: Create and join collaborative editing rooms
- **Real-time Code Editing**: Collaborative editing using Monaco Editor (VS Code-like interface)
- **Module/Exploit Development**: Edit and develop modules and exploits together in real-time
- **Chat System**: Communicate with team members during development
- **Socket.IO-based**: Real-time synchronization using Socket.IO connections
- **Local API Integration**: Connects to local KittySploit API to load and save modules

Start KittyCollab:
```bash
python kittycollab.py
```

Access the web interface at `http://localhost:5001`


## License

MIT License - See [LICENSE](LICENSE) file

## ⚠️ Disclaimer

**KittySploit is a penetration testing tool intended for educational and authorized security purposes only.**

Use only on systems you own or have explicit permission to test.
