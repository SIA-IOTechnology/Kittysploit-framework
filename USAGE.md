# Detailed Usage Guide for KittySploit

This document contains the detailed instructions and reference material originally found in the main README.

## Table of Contents
- [What is KittySploit?](#what-is-kittysploit)
- [Key Features](#key-features)
- [Installation](#installation)
- [Usage](#usage)
- [Autonomous Agent](#autonomous-agent)
- [Natural Language Client](#natural-language-client)
- [Architecture](#architecture)
- [Legal & Ethical Use](#legal--ethical-use)

---

## What is KittySploit?

KittySploit is a **next-generation penetration testing framework** that combines the power of traditional CLI tools with modern web interfaces, AI-assisted analysis, and real-time collaboration. Whether you're a solo researcher or part of a security team, KittySploit provides everything you need for effective penetration testing.

### Why Choose KittySploit?

- ** Fast & Modern** - Built with performance and usability in mind
- ** AI-Powered** - Intelligent vulnerability detection and module suggestions
- ** Collaborative** - Real-time team collaboration built-in
- ** Extensible** - Easy module development and marketplace integration
- ** Multi-Interface** - CLI, REST API, RPC, and Web interfaces
- ** Privacy-First** - Built-in Tor support for anonymous operations

## Key Features

### **KittyProxy** - Intelligent Web Proxy
- **AI-Powered Analysis** - Automatically detects technologies and suggests exploits
- **Real-Time Collaboration** - Work with your team on the same traffic
- **Smart Endpoint Discovery** - Extracts REST APIs, GraphQL, WebSockets automatically
- **Performance Analytics** - Deep insights into response times and bottlenecks
- **Request/Response Modification** - Intercept and modify traffic on-the-fly

### **KittyCollab** - Real-Time Collaboration
- **VS Code-like Editor** - Familiar editing experience with Monaco Editor
- **Live Synchronization** - Real-time code editing with your team
- **Integrated Chat** - Communicate while developing
- **Module Development** - Edit KittySploit modules directly in the browser

### **KittyOsint** - Intelligent Graph Mapping

### **Complete Module System**
- **Exploits** - Comprehensive exploit library for various vulnerabilities
- **Payloads** - Multi-platform payload generation (Python, Bash, PHP, Zig)
- **Scanners** - Fast vulnerability detection and assessment
- **Post-Exploitation** - Information gathering, pivoting, persistence
- **Workflows** - Automate complex attack chains
- **Browser Auxiliary** - Interact with hooked browsers (keylogging, cookie harvesting, form capture)
- **Browser Exploits** - Browser-based exploits via JavaScript injection
- **Auxiliary** - Scanners, fuzzers, enumerators, and DoS modules
- **Encoders** - Payload encoding and obfuscation (Base64, XOR, Unicode, etc.)

### **Multiple Interfaces**
- **CLI** - Powerful command-line interface
- **REST API** - Full framework control via HTTP
- **RPC Server** - Remote procedure calls for automation
- **Web Interfaces** - Beautiful web UIs for KittyProxy and KittyCollab

### **Privacy & Security**
- **Tor Integration** - Route all traffic through Tor
- **Session Management** - Secure multi-protocol session handling
- **Workspace Isolation** - Separate workspaces for different projects

---

## Installation

### Automatic Installation (Recommended)

**Linux / macOS — one line (clone + install):**
```bash
curl -fsSL https://raw.githubusercontent.com/SIA-IOTechnology/kittysploit-framework/main/install/install-standalone.sh | bash
```

**Windows:**
```batch
cd kittysploit-framework
install\install.bat
```

### Manual Installation

```bash
git clone https://github.com/SIA-IOTechnology/Kittysploit-framework
cd kittysploit-framework
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r install/requirements.txt
```

## Usage

### Start KittySploit

**CLI Mode (Interactive):**
```bash
python kittyconsole.py
```

**CLI Mode + Integrated Proxy:**
```bash
python kittyconsole.py --proxy --proxy-port 8888 --proxy-mode http
```

**REST API Server:**
```bash
python kittyapi.py -H 0.0.0.0 -p 5000 -m "master_key"
```

**RPC Server:**
```bash
python kittyrpc.py -H 0.0.0.0 -p 8888 -m "master_key"
```

### Autonomous Agent

The built-in **agent** command runs an autonomous reconnaissance, scanning, optional exploitation, and reporting workflow against a target.

```bash
kittysploit agent example.com --llm-local --llm-model llama3.1:8b
```

### Natural Language Client

`kittymcp_client.py` lets you control KittySploit in natural language.

```bash
python3 kittymcp_client.py --ollama --ollama-model mistral:7b-instruct-q4_0
```

---

## Architecture

KittySploit is built with a modular architecture:

```
┌─────────────────────────────────────────┐
│         KittySploit Framework           │
├─────────────────────────────────────────┤
│  CLI  │  REST API  │  RPC  │  Web UIs   │
├─────────────────────────────────────────┤
│  Module System  │  Sessions  │  Tor     │
│  Scanners       │  Payloads  │  Proxy   │
│  Workflows      │  Marketplace          │
└─────────────────────────────────────────┘
```

## ⚠️ Legal & Ethical Use

**KittySploit is a penetration testing tool intended for authorized security purposes only.**

- ✅ Use only on systems you own
- ✅ Get explicit written permission before testing
- ✅ Follow all applicable laws and regulations
- ❌ Never use for unauthorized access

---

<div align="center">
  <h3>Support KittySploit</h3>
  <p>If you'd like to support the development of this framework:</p>
  
  [![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/KittySploit/donate)
</div>
