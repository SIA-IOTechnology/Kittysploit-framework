<div align="center">
  <img src="static/logo.jpg" alt="KittySploit Logo" width="160">

  # KittySploit Framework
  ### *The Next-Gen Exploitation Engine for Modern Red Teams*

  [![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
  [![Zig](https://img.shields.io/badge/Payloads-Zig_0.16-orange.svg?style=for-the-badge&logo=zig)](https://ziglang.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
  [![Donate](https://img.shields.io/badge/Sponsor-Liberapay-yellow.svg?style=for-the-badge&logo=liberapay)](https://liberapay.com/KittySploit/donate)
  [![Stars](https://img.shields.io/github/stars/SIA-IOTechnology/Kittysploit-framework?style=for-the-badge&color=yellow)](https://github.com/SIA-IOTechnology/Kittysploit-framework/stargazers)

  **[Website](https://kittysploit.com) • [Wiki](https://github.com/SIA-IOTechnology/Kittysploit-framework/wiki) • [Usage Guide](USAGE.md) • [Marketplace](USAGE.md)**

  *Modular • Extensible • AI-Powered*
</div>

---

## Why KittySploit?

While traditional tools struggle with modern web architectures and automated defense, KittySploit redefines the offensive landscape with cutting-edge tech:

| **Autonomous AI** | **Zig Payloads** | **Live Collab** | **Smart Proxy** |
| :--- | :--- | :--- | :--- |
| AI agents that plan attacks via local LLMs (Ollama). | Stealthy payloads compiled with integrated Zig 0.16. | Real-time shared editor for seamless team operations. | Auto-detects tech and runs modules directly from traffic. |

---

## Key Features

- **Autonomous Agent**: Feed a target, and the AI handles reconnaissance and suggests exploitation paths.
- **Ultra-Fast Core**: Dependency-free x64 polymorphic encoders and a high-performance Python core.
- **Evasion-First**: Advanced obfuscation and multi-protocol session handling to bypass modern EDR/WAF.
- **KittyProxy**: Intelligent web proxy that auto-discovers REST APIs, GraphQL, and WebSockets.
- **Modern Web UI**: Beautiful and intuitive graphical interfaces for proxy analysis and collaborative editing.
- **Marketplace**: Easily install or share new modules through our community-driven marketplace.

---

## Vision: KittySploit 2.0

KittySploit **1.x** lays the groundwork — modular architecture, rapid iteration, and a growing ecosystem. The long-term goal is **version 2.0**: not just another pentest framework, but a genuinely best-in-class offensive platform.

**What 2.0 means for us:**

| **Powerful** | **Stable** | **Complete** |
| :--- | :--- | :--- |
| Deep coverage across web, network, cloud, and OT — with AI-assisted planning, evasion-first payloads, and workflows that scale from recon to post-exploitation. | A battle-tested core, predictable APIs, and reliability you can trust on real engagements — not just demos. | One cohesive toolchain: agent, proxy, OSINT, payloads, collaboration, and marketplace — fully integrated, not bolted together. |

We're building toward that north star release by release. Every module, every fix, and every contribution moves us closer to **2.0**.

---

## Screenshots

<div align="center">
  <img src="docs/screenshots/banner.png" alt="Banner" width="100%">
  <br><a href="https://github.com/SIA-IOTechnology/Kittysploit-framework/blob/main/docs/screenshots/banner.png">banner.png</a>
  <br><br>
  <table width="100%">
    <tr>
      <td width="50%"><img src="docs/screenshots/cli-interface.png" alt="CLI Interface"></td>
      <td width="50%"><img src="docs/screenshots/kittyproxy-1.png" alt="KittyProxy"></td>
    </tr>
    <tr>
      <td align="center"><i>Interactive CLI</i><br><a href="https://github.com/SIA-IOTechnology/Kittysploit-framework/blob/main/docs/screenshots/cli-interface.png">KittySploit Framework</a></td>
      <td align="center"><i>Traffic Analysis Detail</i><br><a href="https://github.com/SIA-IOTechnology/KittyProxy">Extension KittyProxy</a></td>
    </tr>
    <tr>
      <td width="50%"><img src="docs/screenshots/kittycollab.png" alt="KittyCollab"></td>
      <td width="50%"><img src="docs/screenshots/kittyosint.png" alt="KittyOsint"></td>
    </tr>
    <tr>
      <td align="center"><i>Collaborative Editor</i><br><a href="https://github.com/SIA-IOTechnology/Kittysploit-framework/blob/main/docs/screenshots/kittycollab.png">KittyCollab</a></td>
      <td align="center"><i>Intelligent OSINT Graph</i><br><a href="https://github.com/SIA-IOTechnology/KittyOsint">Extension KittyOsint</a></td>
    </tr>
    <tr>
      <td width="50%"><img src="docs/screenshots/marketplace.png" alt="Marketplace"></td>
      <td width="50%"><img src="docs/screenshots/kittyproxy-2.png" alt="KittyProxy Detail"></td>
    </tr>
    <tr>
      <td align="center"><i>GUI interface</i><br><a href="https://github.com/SIA-IOTechnology/KittyCosmic">Extension KittyCosmic</a></td>
      <td align="center"><i>AI-Powered Proxy</i><br><a href="https://github.com/SIA-IOTechnology/KittyProxy">Extension KittyProxy</a></td>
    </tr>
    <tr>
      <td width="50%"><img src="docs/screenshots/kittyv8.png" alt="Marketplace"></td>
      <td width="50%"><img src="docs/screenshots/kittyprotocol.png" alt="KittyProxy Detail"></td>
    </tr>
    <tr>
      <td align="center"><i>V8 Engine Debugger</i><br><a href="https://github.com/SIA-IOTechnology/KittyV8Debugger">Extension KittyV8DEbugger</a></td>
      <td align="center"><i>Protocol Analysis</i><br><a href="https://github.com/SIA-IOTechnology/KittyProtocol">Extension KittyProtocol</a></td>
    </tr>
  </table>
</div>

---

## Quick Start

**Linux / macOS One-Liner:**
```bash
curl -fsSL https://raw.githubusercontent.com/SIA-IOTechnology/kittysploit-framework/main/install/install-standalone.sh | bash
```
or 
```bash
git clone https://github.com/SIA-IOTechnology/Kittysploit-framework && cd Kittysploit-framework && ./install/install.sh
``` 

**Windows:**
```batch
git clone https://github.com/SIA-IOTechnology/Kittysploit-framework && cd Kittysploit-framework && install\install.bat
```

**Start:**
```bash
python kittyconsole.py
```

---

## Example: AI-Assisted Planning

Let the framework plan your attack using a local LLM:

```bash
kittysploit agent target.com --llm-local --llm-model llama3.1:8b
```

More examples are available in [USAGE.md](USAGE.md).

---

## How We Compare

| Feature | KittySploit | Metasploit | Cobalt Strike |
| :--- | :---: | :---: | :---: |
| **Language** | Python / Zig | Ruby | Java |
| **Live Collaboration** | ✅ | ❌ | ✅ |
| **AI/LLM Planning** | ✅ | ❌ | ❌ |
| **Modern Payloads** | ✅ (Zig/ASM) | ⚠️ (C/ASM) | ✅ |
| **Native Tor Routing** | ✅ | ❌ | ⚠️ |
| **Integrated Marketplace** | ✅ | ❌ | ❌ |
| **GUI / Web UI** | ✅ | ❌ | ✅ |
| **Complex Workflows** | ✅ | ⚠️ | ✅ |
| **Open Source** | ✅ | ✅ | ❌ |

---

<div align="center">
  <h3>Ready to upgrade your arsenal?</h3>
  <p>If you find this project useful, please consider giving it a ⭐. It helps others discover the framework!</p>
  
  [🌐 Official Website](https://kittysploit.com) • [📄 MIT License](LICENSE) • [💖 Donate](https://liberapay.com/KittySploit/donate)
  
  [![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/KittySploit/donate)
</div>
