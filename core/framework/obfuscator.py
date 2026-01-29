#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base class for stream obfuscators.
Obfuscators transform the C2 traffic (encode on send, decode on receive) to evade detection.
"""

from typing import Optional, List
from core.framework.base_module import BaseModule
from core.output_handler import print_error


class Obfuscator(BaseModule):
    """Base class for stream obfuscator modules. Transforms the C2 flux (encode/decode)."""

    TYPE_MODULE = "obfuscator"

    # Languages for which this obfuscator can generate client code (e.g. "python", "powershell").
    # Payloads declare their client language; obfuscator is only used if it supports that language.
    SUPPORTED_CLIENT_LANGUAGES: List[str] = []

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "obfuscator"

    def connection_copy(self):
        """Return a new obfuscator instance with the same options, for use on a single connection. Use this when the obfuscator is stateful (e.g. decode buffer)."""
        copy_obf = self.__class__(framework=getattr(self, "framework", None))
        for name in self.get_options():
            try:
                val = getattr(self, name)
                copy_obf.set_option(name, val)
            except Exception:
                pass
        return copy_obf

    def get_supported_client_languages(self) -> List[str]:
        """Return the list of client languages this obfuscator supports (for payload generation)."""
        return list(getattr(self.__class__, "SUPPORTED_CLIENT_LANGUAGES", []))

    def encode(self, data: bytes) -> bytes:
        """Encode data before sending on the C2 channel. Override in subclasses."""
        raise NotImplementedError("Obfuscator modules must implement encode(data: bytes) -> bytes")

    def decode(self, data: bytes) -> bytes:
        """Decode data after receiving from the C2 channel. Override in subclasses."""
        raise NotImplementedError("Obfuscator modules must implement decode(data: bytes) -> bytes")

    def generate_client_code(self, language: str) -> Optional[str]:
        """
        Generate client-side code that implements the same encode/decode logic for the given language.
        Payloads inject this code so the generated payload can obfuscate the C2 stream without
        hardcoding obfuscator-specific logic in each payload.

        The returned code must define:
          - _obf_encode(data: bytes) -> bytes
          - _obf_decode(data: bytes) -> bytes
        so the payload can wrap socket send/recv with these functions.

        Args:
            language: Target language, e.g. "python", "powershell" (optional for future use).

        Returns:
            Code string to inject, or None if this obfuscator does not support client-side generation.
        """
        return None

    def run(self):
        """Obfuscators are not run directly; they wrap a listener's stream."""
        print_error("Obfuscator module cannot be run directly. Use with a listener (option obfuscator).")
        return False
