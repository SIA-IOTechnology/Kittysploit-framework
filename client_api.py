#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interactive HTTP client for the KittySploit REST API (ApiServer)."""

# Add project root to path for imports (before importing venv_helper)
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure we're using the project's venv if it exists
from core.utils.venv_helper import ensure_venv

ensure_venv(__file__)

import argparse
import getpass
import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from colorama import Fore, Style, init
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style as PromptStyle

from core.output_handler import print_error, print_info, print_success, print_warning

init(autoreset=True)

DEFAULT_REGISTRY_URL = "https://app.kittysploit.com"
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".kittysploit")
REGISTRY_CONFIG = os.path.join(CONFIG_DIR, "registry_config.json")


class KittyApiClient:
    """KittySploit REST API client aligned with interfaces/api_server.py."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        api_key: Optional[str] = None,
        use_ssl: bool = False,
        mint_token: bool = True,
    ):
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}/api"
        self.bootstrap_key = (api_key or "").strip() or None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.session = requests.Session()
        self.session.timeout = 30

        self.prompt_style = PromptStyle.from_dict(
            {
                "prompt": "ansired bold",
                "completion-menu.completion": "bg:#008800 #ffffff",
                "completion-menu.completion.current": "bg:#00aaaa #000000",
            }
        )

        self.commands = {
            "help": self.show_help,
            "health": self.show_health,
            "whoami": self.show_whoami,
            "modules": self.list_modules,
            "use": self.use_module,
            "info": self.show_module_info,
            "set": self.set_option,
            "options": self.show_options,
            "run": self.run_module,
            "execute": self.execute_module,
            "sessions": self.list_sessions,
            "kill": self.kill_session,
            "interpreter": self.start_interpreter,
            "workspaces": self.list_workspaces,
            "workspace": self.switch_workspace,
            "workflows": self.list_workflows,
            "workflow": self.run_workflow,
            "market": self.market_command,
            "exit": self.exit_client,
            "quit": self.exit_client,
        }

        self.current_module: Optional[str] = None
        self.module_options: Dict[str, Any] = {}
        self.running = True
        self.registry_url = self._resolve_registry_url()

        if mint_token and self.bootstrap_key:
            self._mint_access_token()

    # ------------------------------------------------------------------ auth

    def _auth_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        elif self.bootstrap_key:
            headers["X-API-Key"] = self.bootstrap_key
        if extra:
            headers.update(extra)
        return headers

    def _mint_access_token(self) -> bool:
        """Exchange the bootstrap API key for a short-lived rotating token pair."""
        try:
            response = self.session.post(
                f"{self.base_url}/auth/token",
                json={"subject": "client_api", "roles": ["operator"]},
                headers={"X-API-Key": self.bootstrap_key},
                timeout=15,
            )
            if response.status_code in (200, 201):
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                if self.access_token:
                    print_success("Authenticated with rotating access token")
                    return True
            # Bootstrap key alone is still valid; token mint is optional.
            print_warning("Could not mint rotating token; using bootstrap API key")
        except requests.RequestException as exc:
            print_warning(f"Token mint skipped: {exc}")
        return False

    def _refresh_access_token(self) -> bool:
        if not self.refresh_token:
            return False
        try:
            response = self.session.post(
                f"{self.base_url}/auth/refresh",
                json={"refresh_token": self.refresh_token},
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token") or self.refresh_token
                return bool(self.access_token)
        except requests.RequestException:
            pass
        return False

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        stream: bool = False,
        timeout: Optional[float] = 30,
        headers: Optional[Dict[str, str]] = None,
        auth: bool = True,
    ) -> requests.Response:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        req_headers = self._auth_headers(headers) if auth else (headers or {})
        response = self.session.request(
            method,
            url,
            json=json_body,
            params=params,
            headers=req_headers,
            stream=stream,
            timeout=timeout,
        )
        if response.status_code == 401 and self.refresh_token and auth:
            if self._refresh_access_token():
                req_headers = self._auth_headers(headers)
                response = self.session.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=req_headers,
                    stream=stream,
                    timeout=timeout,
                )
        return response

    def _error_text(self, response: requests.Response) -> str:
        try:
            payload = response.json()
            if isinstance(payload, dict):
                return payload.get("message") or payload.get("error") or response.text
        except Exception:
            pass
        return response.text

    def connect(self) -> bool:
        """Probe /api/health and report connection status."""
        try:
            response = self._request("GET", "/health", auth=False, timeout=10)
            if response.status_code == 200:
                data = response.json() if response.content else {}
                status = data.get("status", "ok")
                print_success(f"Connected to {self.base_url} (health: {status})")
                return True
            print_error(f"Health check failed: {self._error_text(response)}")
        except requests.RequestException as exc:
            print_error(f"Cannot reach API at {self.base_url}: {exc}")
            print_info("Start the server with: python kittyapi.py -k <api-key>")
            print_info("Or: python kittyconsole.py -a --api-key <api-key>")
        return False

    # ------------------------------------------------------------------ helpers

    def get_prompt(self) -> str:
        if self.current_module:
            short = self.current_module.rsplit("/", 1)[-1]
            return f"kittyapi({short})> "
        return "kittyapi> "

    def _options_payload(self) -> Dict[str, Any]:
        """Flatten option metadata to {name: value} for POST /run and /execute."""
        payload: Dict[str, Any] = {}
        for name, info in self.module_options.items():
            if isinstance(info, dict):
                payload[name] = info.get("value", "")
            else:
                payload[name] = info
        return payload

    def _print_output_event(self, output: Dict[str, Any]) -> None:
        ts = datetime.fromtimestamp(output.get("timestamp", time.time()))
        stamp = f"[{ts:%H:%M:%S}]"
        kind = output.get("type", "unknown")
        if kind == "error":
            text = output.get("error") or output.get("text") or ""
            print(f"{Fore.RED}{stamp} {text}")
        elif kind == "result":
            text = output.get("result") if "result" in output else output.get("text", "")
            print(f"{Fore.GREEN}{stamp} {text}")
        elif kind == "stderr":
            print(f"{Fore.YELLOW}{stamp} {output.get('text', '')}")
        else:
            print(f"{Fore.WHITE}{stamp} {output.get('text', '')}")

    def _is_terminal_event(self, output: Dict[str, Any]) -> bool:
        return output.get("type") in ("result", "error")

    # ------------------------------------------------------------------ commands

    def show_help(self, *args):
        print(f"\n{Fore.CYAN}=== KittySploit API Client Help ===")
        print(f"{Fore.WHITE}Available commands:")
        rows = [
            ("help", "Show this help"),
            ("health", "Show API health"),
            ("whoami", "Show authenticated principal"),
            ("modules [type]", "List modules (?full=1)"),
            ("use <module>", "Select a module"),
            ("info", "Show current module info"),
            ("options", "Show module options"),
            ("set <opt> <value>", "Set a module option"),
            ("run", "Run module (async + stream)"),
            ("execute", "Run module synchronously"),
            ("sessions", "List active sessions"),
            ("kill <id>", "Destroy a session"),
            ("interpreter", "Remote Python interpreter"),
            ("workspaces", "List workspaces"),
            ("workspace <name>", "Switch workspace"),
            ("workflows", "List workflow library"),
            ("workflow <id> [target=..]", "Run a workflow"),
            ("market ...", "Remote extension marketplace"),
            ("exit / quit", "Exit the client"),
        ]
        for cmd, desc in rows:
            print(f"  {Fore.GREEN}{cmd:<28}{Fore.WHITE} {desc}")
        print()

    def show_health(self, *args):
        detailed = bool(args and args[0] in ("detailed", "-d", "--detailed"))
        path = "/health/detailed" if detailed else "/health"
        try:
            response = self._request("GET", path, auth=detailed)
            if response.status_code == 200:
                print(f"\n{Fore.CYAN}=== API Health ===")
                print(json.dumps(response.json(), indent=2, default=str))
                print()
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def show_whoami(self, *args):
        try:
            response = self._request("GET", "/auth/me")
            if response.status_code == 200:
                print(f"\n{Fore.CYAN}=== Auth Context ===")
                print(json.dumps(response.json(), indent=2, default=str))
                print()
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def list_modules(self, *args):
        params: Dict[str, Any] = {"full": "1"}
        if args:
            params["type"] = args[0]
        try:
            response = self._request("GET", "/modules", params=params)
            if response.status_code != 200:
                print_error(self._error_text(response))
                return
            modules = response.json()
            print(f"\n{Fore.CYAN}=== Available Modules ===")
            if isinstance(modules, dict):
                # Compact counts map when full was ignored, or path->info map
                if all(isinstance(v, int) for v in modules.values()):
                    for mtype, count in sorted(modules.items()):
                        print(f"  {Fore.GREEN}{mtype:<20}{Fore.WHITE} {count}")
                else:
                    for module_name, info in modules.items():
                        if isinstance(info, dict):
                            description = info.get("description", "No description available")
                        else:
                            description = str(info)
                        print(f"{Fore.GREEN}{module_name}{Fore.WHITE} - {description}")
            elif isinstance(modules, list):
                for item in modules:
                    if isinstance(item, dict):
                        name = item.get("path") or item.get("name") or str(item)
                        description = item.get("description", "No description available")
                        print(f"{Fore.GREEN}{name}{Fore.WHITE} - {description}")
                    else:
                        print(f"{Fore.GREEN}{item}")
            else:
                print_warning(f"Unexpected modules payload: {type(modules).__name__}")
            print()
        except Exception as exc:
            print_error(str(exc))

    def use_module(self, *args):
        if not args:
            print_error("Usage: use <module_name>")
            return
        module_name = args[0]
        encoded = quote(module_name, safe="/")
        try:
            response = self._request("GET", f"/modules/{encoded}")
            if response.status_code == 200:
                module_info = response.json()
                self.current_module = module_name
                options = module_info.get("options", {})
                # Normalize to mutable option dicts
                normalized: Dict[str, Any] = {}
                for name, info in (options or {}).items():
                    if isinstance(info, dict):
                        normalized[name] = dict(info)
                    else:
                        normalized[name] = {
                            "value": info,
                            "required": False,
                            "description": "",
                        }
                self.module_options = normalized
                print_success(f"Using module: {module_name}")
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def show_module_info(self, *args):
        if not self.current_module:
            print_error("No module selected")
            return
        encoded = quote(self.current_module, safe="/")
        try:
            response = self._request("GET", f"/modules/{encoded}")
            if response.status_code != 200:
                print_error(self._error_text(response))
                return
            payload = response.json()
            info = payload.get("info") if isinstance(payload.get("info"), dict) else payload
            print(f"\n{Fore.CYAN}=== Module Information ===")
            print(f"{Fore.WHITE}Name: {Fore.GREEN}{info.get('name', payload.get('name', 'N/A'))}")
            print(f"{Fore.WHITE}Description: {info.get('description', payload.get('description', 'N/A'))}")
            print(f"{Fore.WHITE}Author: {info.get('author', payload.get('author', 'N/A'))}")
            refs = info.get("references", []) if isinstance(info, dict) else []
            if refs:
                print(f"{Fore.WHITE}References:")
                for ref in refs:
                    print(f"  - {ref}")
            print()
        except Exception as exc:
            print_error(str(exc))

    def set_option(self, *args):
        if not self.current_module:
            print_error("No module selected")
            return
        if len(args) < 2:
            print_error("Usage: set <option_name> <value>")
            return
        option_name = args[0]
        option_value = " ".join(args[1:])
        if option_name not in self.module_options:
            print_error(f"Invalid option: {option_name}")
            return
        info = self.module_options[option_name]
        if isinstance(info, dict):
            info["value"] = option_value
            if "display_value" in info:
                info["display_value"] = option_value
        else:
            self.module_options[option_name] = option_value
        print_success(f"Set {option_name} => {option_value}")

    def show_options(self, *args):
        if not self.current_module:
            print_error("No module selected")
            return
        print(f"\n{Fore.CYAN}=== Module Options ===")
        print(f"{'Name':<20} {'Required':<10} {'Value':<24} {'Description'}")
        print("=" * 80)
        for name, info in self.module_options.items():
            if isinstance(info, dict):
                required = info.get("required", False)
                value = info.get("display_value", info.get("value", ""))
                description = info.get("description", "")
            else:
                required, value, description = False, info, ""
            print(
                f"{Fore.GREEN}{name:<20}{Fore.WHITE} {str(required):<10} "
                f"{str(value):<24} {description}"
            )
        print()

    def run_module(self, *args):
        if not self.current_module:
            print_error("No module selected")
            return
        encoded = quote(self.current_module, safe="/")
        try:
            response = self._request(
                "POST",
                f"/modules/{encoded}/run",
                json_body={"options": self._options_payload()},
            )
            if response.status_code == 200:
                result = response.json()
                client_id = result.get("client_id")
                print_success(f"Module started. Client ID: {client_id}")
                self._stream_output(client_id)
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def execute_module(self, *args):
        """Synchronous /execute endpoint (headless)."""
        if not self.current_module:
            print_error("No module selected")
            return
        encoded = quote(self.current_module, safe="/")
        try:
            response = self._request(
                "POST",
                f"/modules/{encoded}/execute",
                json_body={"options": self._options_payload()},
                timeout=300,
            )
            if response.status_code == 200:
                print(f"\n{Fore.CYAN}=== Execute Result ===")
                print(json.dumps(response.json(), indent=2, default=str))
                print()
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def _stream_output(self, client_id: str):
        """Prefer SSE streaming; fall back to polling until terminal event."""
        if self._stream_sse(client_id):
            return
        self._poll_output(client_id)

    def _stream_sse(self, client_id: str) -> bool:
        try:
            response = self._request(
                "GET",
                f"/output/{client_id}/stream",
                stream=True,
                timeout=(10, 600),
            )
            if response.status_code != 200:
                return False
            print_info("Streaming output (SSE)…")
            finished = False
            for raw_line in response.iter_lines(decode_unicode=True):
                if raw_line is None:
                    continue
                line = raw_line.strip() if isinstance(raw_line, str) else raw_line.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if not payload:
                    continue
                try:
                    events = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if isinstance(events, dict):
                    events = [events]
                for output in events:
                    self._print_output_event(output)
                    if self._is_terminal_event(output):
                        finished = True
            # Drain anything left after the stream ends
            self._poll_output(client_id, once=True)
            return True if finished or response.status_code == 200 else False
        except KeyboardInterrupt:
            print_warning("Output streaming interrupted")
            return True
        except requests.RequestException:
            return False

    def _poll_output(self, client_id: str, once: bool = False):
        idle_rounds = 0
        max_idle = 50  # ~5s of empty polls after activity stopped
        try:
            while True:
                response = self._request("GET", f"/output/{client_id}")
                if response.status_code == 404:
                    break
                if response.status_code != 200:
                    print_error(self._error_text(response))
                    break
                outputs = response.json()
                if not isinstance(outputs, list):
                    break
                if outputs:
                    idle_rounds = 0
                    terminal = False
                    for output in outputs:
                        self._print_output_event(output)
                        if self._is_terminal_event(output):
                            terminal = True
                    if terminal:
                        break
                else:
                    if once:
                        break
                    idle_rounds += 1
                    if idle_rounds >= max_idle:
                        break
                if once:
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            print_warning("Output streaming interrupted")

    def list_sessions(self, *args):
        try:
            response = self._request("GET", "/sessions")
            if response.status_code != 200:
                print_error(self._error_text(response))
                return
            sessions = response.json()
            print(f"\n{Fore.CYAN}=== Active Sessions ===")
            if not sessions:
                print_warning("No active sessions")
            elif isinstance(sessions, dict):
                for session_id, info in sessions.items():
                    print(f"{Fore.GREEN}Session {session_id}:")
                    if isinstance(info, dict):
                        for key, value in info.items():
                            print(f"  {Fore.WHITE}{key}: {value}")
                    else:
                        print(f"  {Fore.WHITE}{info}")
            else:
                print(json.dumps(sessions, indent=2, default=str))
            print()
        except Exception as exc:
            print_error(str(exc))

    def kill_session(self, *args):
        if not args:
            print_error("Usage: kill <session_id>")
            return
        try:
            session_id = int(args[0])
        except ValueError:
            print_error("Session id must be an integer")
            return
        try:
            response = self._request("DELETE", f"/sessions/{session_id}")
            if response.status_code == 200:
                data = response.json() if response.content else {}
                print_success(data.get("message", f"Session {session_id} deleted"))
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def start_interpreter(self, *args):
        print(f"{Fore.CYAN}=== KittySploit Interactive Python Session ===")
        print(f"{Fore.WHITE}Type 'exit' to return to the API client\n")

        session_id = str(uuid.uuid4())
        interpreter_session = PromptSession(
            style=self.prompt_style,
            message=lambda: "ipk >>> ",
        )

        while True:
            try:
                code = interpreter_session.prompt().strip()
                if code.lower() in ("exit", "quit"):
                    break
                if not code:
                    continue
                try:
                    response = self._request(
                        "POST",
                        "/interpreter/execute",
                        json_body={"code": code},
                        headers={"X-Session-ID": session_id},
                        timeout=60,
                    )
                    if response.status_code == 200:
                        result = response.json()
                        if result.get("output"):
                            print(result["output"].rstrip())
                        if result.get("error"):
                            print(f"{Fore.RED}{result['error'].rstrip()}{Style.RESET_ALL}")
                        if result.get("result") not in (None, ""):
                            print(f"{Fore.GREEN}{result['result']}{Style.RESET_ALL}")
                    else:
                        print_error(self._error_text(response))
                except requests.RequestException as exc:
                    print_error(f"Connection error: {exc}")
            except KeyboardInterrupt:
                print("\n")
                continue
            except EOFError:
                break
            except Exception as exc:
                print_error(str(exc))

        print_info("Returning to API client…")

    def list_workspaces(self, *args):
        try:
            response = self._request("GET", "/workspaces")
            if response.status_code == 200:
                print(f"\n{Fore.CYAN}=== Workspaces ===")
                print(json.dumps(response.json(), indent=2, default=str))
                print()
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def switch_workspace(self, *args):
        if not args:
            print_error("Usage: workspace <name>")
            return
        name = args[0]
        try:
            response = self._request("POST", f"/workspaces/{quote(name, safe='')}")
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    print_success(f"Switched to workspace: {name}")
                else:
                    print_warning(f"Workspace switch returned: {data}")
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def list_workflows(self, *args):
        try:
            response = self._request("GET", "/workflows")
            if response.status_code == 200:
                data = response.json()
                workflows = data.get("workflows", data)
                print(f"\n{Fore.CYAN}=== Workflows ===")
                if isinstance(workflows, list):
                    for wf in workflows:
                        if isinstance(wf, dict):
                            print(
                                f"{Fore.GREEN}{wf.get('id', '?'):<30}{Fore.WHITE} "
                                f"{wf.get('name', '')} — {wf.get('description', '')}"
                            )
                        else:
                            print(f"{Fore.GREEN}{wf}")
                else:
                    print(json.dumps(workflows, indent=2, default=str))
                print()
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def run_workflow(self, *args):
        if not args:
            print_error("Usage: workflow <id> [target=<host>] [key=value ...]")
            return
        workflow_id = args[0]
        variables: Dict[str, Any] = {}
        target = None
        dry_run = False
        for token in args[1:]:
            if token in ("--dry-run", "dry_run"):
                dry_run = True
                continue
            if "=" in token:
                key, value = token.split("=", 1)
                if key == "target":
                    target = value
                else:
                    variables[key] = value
        body: Dict[str, Any] = {"variables": variables, "dry_run": dry_run}
        if target:
            body["target"] = target
        try:
            response = self._request(
                "POST",
                f"/workflows/{quote(workflow_id, safe='')}/run",
                json_body=body,
                timeout=600,
            )
            if response.status_code == 200:
                print(f"\n{Fore.CYAN}=== Workflow Result ===")
                print(json.dumps(response.json(), indent=2, default=str))
                print()
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    # ------------------------------------------------------------------ market

    def market_command(self, *args):
        """Marketplace against the remote KittySploit registry (not the local API)."""
        config = self._load_registry_config()
        has_account = bool(config and (config.get("token") or config.get("api_key")))

        if not args:
            if not has_account:
                print_warning("No marketplace account. You can browse, but install needs login.")
                choice = input("register / login / skip: ").strip().lower()
                if choice == "register":
                    self._register_account()
                elif choice == "login":
                    self._login_account()
                elif choice != "skip":
                    print_error("Invalid choice")
                    return
            self._show_marketplace_help()
            return

        action = args[0]
        if action == "list":
            self._list_marketplace_extensions()
        elif action == "info" and len(args) > 1:
            self._show_extension_info(args[1])
        elif action == "install" and len(args) > 1:
            self._install_extension(args[1])
        elif action == "login":
            self._login_account()
        elif action == "register":
            self._register_account()
        elif action == "logout":
            self._logout_account()
        else:
            self._show_marketplace_help()

    def _show_marketplace_help(self):
        print(f"\n{Fore.CYAN}=== Extension Marketplace ({self.registry_url}) ===")
        print(f"{Fore.WHITE}Available commands:")
        print(f"  {Fore.GREEN}market list{Fore.WHITE}                     - List extensions")
        print(f"  {Fore.GREEN}market info <id>{Fore.WHITE}                - Extension details")
        print(f"  {Fore.GREEN}market install <id>{Fore.WHITE}             - Install (requires account)")
        print(f"  {Fore.GREEN}market register|login|logout{Fore.WHITE}     - Account management")
        print()

    def _registry_headers(self) -> Dict[str, str]:
        config = self._load_registry_config() or {}
        headers: Dict[str, str] = {}
        token = config.get("token")
        api_key = config.get("api_key")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif api_key:
            headers["X-API-Key"] = api_key
        return headers

    def _list_marketplace_extensions(self):
        try:
            response = self.session.get(
                f"{self.registry_url}/api/cli/market/modules",
                headers=self._registry_headers(),
                timeout=20,
            )
            if response.status_code == 404:
                # Legacy registry path
                response = self.session.get(
                    f"{self.registry_url}/api/registry/extensions",
                    timeout=20,
                )
            if response.status_code != 200:
                print_error(self._error_text(response))
                return
            result = response.json()
            extensions = (
                result.get("extensions")
                or result.get("modules")
                or result.get("items")
                or (result if isinstance(result, list) else [])
            )
            total = result.get("total", len(extensions)) if isinstance(result, dict) else len(extensions)
            print(f"\n{Fore.CYAN}=== Available Extensions ({total}) ===")
            if not extensions:
                print_warning("No extensions found")
                return
            print(f"\n{Fore.WHITE}{'ID':<30} {'Name':<30} {'Type':<15} {'Price':<10} {'Publisher'}")
            print("=" * 100)
            for ext in extensions:
                if not isinstance(ext, dict):
                    continue
                ext_id = ext.get("id") or ext.get("module_id") or "N/A"
                name = ext.get("name", "N/A")
                ext_type = ext.get("type") or ext.get("category") or "N/A"
                price = ext.get("price", 0.0)
                currency = ext.get("currency", "USD")
                publisher = ext.get("publisher", {})
                if isinstance(publisher, dict):
                    publisher = publisher.get("name", "N/A")
                is_free = ext.get("is_free", price in (0, 0.0, None, "0"))
                price_str = f"{Fore.GREEN}FREE{Fore.WHITE}" if is_free else f"{price} {currency}"
                print(f"{Fore.GREEN}{str(ext_id):<30}{Fore.WHITE} {str(name):<30} {str(ext_type):<15} {price_str:<10} {publisher}")
            print()
        except Exception as exc:
            print_error(str(exc))

    def _show_extension_info(self, extension_id: str):
        try:
            response = self.session.get(
                f"{self.registry_url}/api/cli/market/modules/{quote(extension_id, safe='')}",
                headers=self._registry_headers(),
                timeout=20,
            )
            if response.status_code == 404:
                response = self.session.get(
                    f"{self.registry_url}/api/registry/extensions/{quote(extension_id, safe='')}",
                    timeout=20,
                )
            if response.status_code != 200:
                print_error(self._error_text(response))
                return
            ext = response.json()
            print(f"\n{Fore.CYAN}=== Extension Details ===")
            print(f"{Fore.WHITE}ID: {Fore.GREEN}{ext.get('id') or ext.get('module_id')}")
            print(f"{Fore.WHITE}Name: {Fore.GREEN}{ext.get('name')}")
            print(f"{Fore.WHITE}Description: {Fore.WHITE}{ext.get('description', 'N/A')}")
            print(f"{Fore.WHITE}Type: {Fore.GREEN}{ext.get('type') or ext.get('category')}")
            publisher = ext.get("publisher", {})
            pub_name = publisher.get("name", publisher) if isinstance(publisher, dict) else publisher
            print(f"{Fore.WHITE}Publisher: {Fore.GREEN}{pub_name or 'N/A'}")
            if ext.get("is_free"):
                price_label = "FREE"
            else:
                price_label = f"{ext.get('price')} {ext.get('currency', 'USD')}"
            print(f"{Fore.WHITE}Price: {Fore.GREEN}{price_label}")
            versions = ext.get("versions", [])
            if versions:
                print(f"\n{Fore.WHITE}Versions:")
                for ver in versions:
                    latest = " (latest)" if ver.get("is_latest") else ""
                    print(
                        f"  {Fore.GREEN}{ver.get('version')}{latest}{Fore.WHITE} "
                        f"- Downloads: {ver.get('download_count', 0)}"
                    )
            print()
        except Exception as exc:
            print_error(str(exc))

    def _install_extension(self, extension_id: str):
        config = self._load_registry_config()
        if not config or not (config.get("token") or config.get("api_key")):
            print_error("You need to be logged in to install extensions")
            print_info("Use: market login  or  market register")
            return
        try:
            from core.registry.client import ExtensionClient

            client = ExtensionClient(registry_url=self.registry_url)
            ok = client.install_extension(extension_id)
            if ok:
                print_success(f"Extension installed: {extension_id}")
            else:
                print_error(f"Installation failed for {extension_id}")
            return
        except ImportError:
            print_warning("ExtensionClient unavailable; downloading bundle only")
        except Exception as exc:
            print_warning(f"ExtensionClient install failed ({exc}); trying direct download")

        try:
            print_info(f"Downloading extension {extension_id}…")
            response = self.session.get(
                f"{self.registry_url}/api/cli/market/download/{quote(extension_id, safe='')}",
                headers=self._registry_headers(),
                stream=True,
                timeout=120,
            )
            if response.status_code != 200:
                print_error(self._error_text(response))
                return
            filename = f"{extension_id}.kext"
            with open(filename, "wb") as handle:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        handle.write(chunk)
            print_success(f"Extension downloaded: {filename}")
            print_info("Install via: market install in kittyconsole, or ExtensionClient")
        except Exception as exc:
            print_error(str(exc))

    def _register_account(self):
        try:
            print(f"\n{Fore.CYAN}=== Marketplace Account Registration ===")
            email = input(f"{Fore.WHITE}Email: ").strip()
            if not email:
                print_error("Email is required")
                return
            username = input(f"{Fore.WHITE}Username: ").strip()
            if not username:
                print_error("Username is required")
                return
            password = getpass.getpass(f"{Fore.WHITE}Password: ")
            if not password:
                print_error("Password is required")
                return
            password_confirm = getpass.getpass(f"{Fore.WHITE}Confirm password: ")
            if password != password_confirm:
                print_error("Passwords do not match")
                return

            response = self.session.post(
                f"{self.registry_url}/api/cli/register",
                json={"email": email, "password": password, "username": username},
                timeout=30,
            )
            if response.status_code == 201:
                result = response.json()
                user = result.get("user", {})
                print_success("Account created successfully")
                print_info(f"Email: {user.get('email', email)}")
                print_info("You can now: market login")
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def _login_account(self):
        try:
            print(f"\n{Fore.CYAN}=== Marketplace Account Login ===")
            email = input(f"{Fore.WHITE}Email: ").strip()
            if not email:
                print_error("Email is required")
                return
            password = getpass.getpass(f"{Fore.WHITE}Password: ")
            if not password:
                print_error("Password is required")
                return

            response = self.session.post(
                f"{self.registry_url}/api/cli/login",
                json={"email": email, "password": password},
                timeout=30,
            )
            if response.status_code == 200:
                result = response.json()
                token = result.get("token") or result.get("api_key")
                user = result.get("user", {})
                if not token and not result.get("success", True):
                    print_error(result.get("error", "Login failed"))
                    return
                if token:
                    self._save_registry_account(
                        token=result.get("token"),
                        api_key=result.get("api_key"),
                        email=user.get("email", email),
                        username=user.get("username"),
                        expires_at=result.get("expires_at"),
                    )
                    print_success("Login successful")
                    print_info(f"Welcome, {user.get('username') or email}")
                else:
                    print_error("Login failed: no token received")
            else:
                print_error(self._error_text(response))
        except Exception as exc:
            print_error(str(exc))

    def _logout_account(self):
        config = self._load_registry_config() or {}
        for key in ("token", "api_key", "email", "username", "expires_at"):
            config.pop(key, None)
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(REGISTRY_CONFIG, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2)
            print_success("Logged out of marketplace")
        except Exception as exc:
            print_error(str(exc))

    def _resolve_registry_url(self) -> str:
        config = self._load_registry_config()
        if config:
            for key in ("base_url", "registry_url"):
                url = config.get(key)
                if url:
                    return str(url).rstrip("/")
        try:
            from core.config import Config

            cfg = Config.get_instance()
            url = cfg.get_config_value_by_path("registry.url")
            if url:
                return str(url).rstrip("/")
        except Exception:
            pass
        return DEFAULT_REGISTRY_URL

    def _load_registry_config(self) -> Optional[Dict[str, Any]]:
        try:
            if os.path.exists(REGISTRY_CONFIG):
                with open(REGISTRY_CONFIG, "r", encoding="utf-8") as handle:
                    return json.load(handle)
        except Exception:
            pass
        return None

    def _save_registry_account(
        self,
        token: Optional[str] = None,
        api_key: Optional[str] = None,
        email: Optional[str] = None,
        username: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> bool:
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            config = self._load_registry_config() or {}
            if token:
                config["token"] = token
            if api_key:
                config["api_key"] = api_key
            if email:
                config["email"] = email
            if username:
                config["username"] = username
            if expires_at:
                config["expires_at"] = expires_at
            config["base_url"] = self.registry_url
            with open(REGISTRY_CONFIG, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2)
            return True
        except Exception as exc:
            print_error(f"Error saving account info: {exc}")
            return False

    def exit_client(self, *args):
        print_info("Exiting…")
        self.running = False

    def run(self):
        print(f"{Fore.CYAN}=== KittySploit API Client ===")
        print(f"{Fore.WHITE}Type 'help' for available commands\n")

        if not self.connect():
            self.running = False
            return

        command_completer = WordCompleter(list(self.commands.keys()))
        session = PromptSession(completer=command_completer, style=self.prompt_style)

        while self.running:
            try:
                command_line = session.prompt(self.get_prompt())
                command_parts = command_line.strip().split()
                if not command_parts:
                    continue
                command = command_parts[0].lower()
                args = command_parts[1:]
                if command in self.commands:
                    self.commands[command](*args)
                else:
                    print_error(f"Unknown command: {command}")
            except KeyboardInterrupt:
                print("\n")
                continue
            except EOFError:
                break
            except Exception as exc:
                print_error(str(exc))

        print(f"{Fore.CYAN}Goodbye!")


def parse_arguments():
    parser = argparse.ArgumentParser(description="KittySploit API Client")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="API server host (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=5000, help="API server port (default: 5000)")
    parser.add_argument(
        "-k",
        "--api-key",
        help="API key for authentication (or set KITTYSPLOIT_API_KEY)",
    )
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS")
    parser.add_argument(
        "--no-token",
        action="store_true",
        help="Do not mint a rotating Bearer token; use bootstrap key only",
    )
    return parser.parse_args()


def resolve_api_key(cli_key: Optional[str]) -> Optional[str]:
    key = (cli_key or "").strip()
    if key:
        return key
    env = (os.environ.get("KITTYSPLOIT_API_KEY") or "").strip()
    if env:
        return env
    # Do not reuse marketplace registry tokens as local API keys.
    return None


def main():
    args = parse_arguments()
    api_key = resolve_api_key(args.api_key)
    if not api_key:
        print_error("API key required: use -k/--api-key or set KITTYSPLOIT_API_KEY")
        return 1

    try:
        client = KittyApiClient(
            host=args.host,
            port=args.port,
            api_key=api_key,
            use_ssl=args.ssl,
            mint_token=not args.no_token,
        )
        client.run()
    except Exception as exc:
        print_error(f"Fatal error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
