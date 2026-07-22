#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base class for C2 stream transforms.
Transforms encode/decode traffic on an established listener connection to evade detection.
"""

from typing import Optional, List
from core.framework.base_module import BaseModule
from core.output_handler import print_error

LEGACY_MODULE_PREFIX = "obfuscators/"
MODULE_PREFIX = "transforms/"
LEGACY_OPTION = "obfuscator"
TRANSFORM_OPTION = "transform"


def normalize_transform_module_path(path: str) -> str:
    """Map legacy obfuscators/ paths to transforms/."""
    path = (path or "").strip()
    if path.startswith(LEGACY_MODULE_PREFIX):
        return MODULE_PREFIX + path[len(LEGACY_MODULE_PREFIX):]
    return path


def _read_option_path(instance, opt_name: str) -> str:
    descriptor = getattr(type(instance), opt_name, None)
    if descriptor is not None and hasattr(descriptor, "__get__"):
        try:
            raw = descriptor.__get__(instance, type(instance))
        except AttributeError:
            return ""
    else:
        try:
            raw = instance.__getattribute__(opt_name)
        except AttributeError:
            return ""
    if raw is None:
        return ""
    if hasattr(raw, "value") and not isinstance(raw, (str, bytes, int, float, bool)):
        raw = raw.value
    return str(raw or "").strip()


def get_transform_path_from_instance(instance) -> str:
    for opt_name in (TRANSFORM_OPTION, LEGACY_OPTION):
        path = normalize_transform_module_path(_read_option_path(instance, opt_name))
        if path:
            return path
    return ""


class Transform(BaseModule):
    """Base class for C2 stream transform modules. Transforms the C2 flux (encode/decode)."""

    TYPE_MODULE = "transform"

    # Languages for which this transform can generate client code (e.g. "python", "powershell").
    # Payloads declare their client language; transform is only used if it supports that language.
    SUPPORTED_CLIENT_LANGUAGES: List[str] = []

    def __init__(self, framework=None):
        super().__init__(framework)
        self.type = "transform"

    def connection_copy(self):
        copy_xf = self.__class__(framework=getattr(self, "framework", None))
        for name in self.get_options():
            try:
                val = getattr(self, name)
                copy_xf.set_option(name, val)
            except Exception:
                pass
        return copy_xf

    def get_supported_client_languages(self) -> List[str]:
        return list(getattr(self.__class__, "SUPPORTED_CLIENT_LANGUAGES", []))

    def encode(self, data: bytes) -> bytes:
        """Encode data before sending on the C2 channel. Override in subclasses."""
        raise NotImplementedError("Transform modules must implement encode(data: bytes) -> bytes")

    def decode(self, data: bytes) -> bytes:
        """Decode data after receiving from the C2 channel. Override in subclasses."""
        raise NotImplementedError("Transform modules must implement decode(data: bytes) -> bytes")

    def generate_client_code(self, language: str) -> Optional[str]:
        """
        Generate client-side code that implements the same encode/decode logic for the given language.
        Payloads inject this code so the generated payload can transform the C2 stream without
        hardcoding transform-specific logic in each payload.

        The returned code must define:
          - _xf_encode(data: bytes) -> bytes
          - _xf_decode(data: bytes) -> bytes
        so the payload can wrap socket send/recv with these functions.

        Args:
            language: Target language, e.g. "python", "powershell".

        Returns:
            Code string to inject, or None if this transform does not support client-side generation.
        """
        return None

    def run(self):
        """Transforms are not run directly; they wrap a listener's stream."""
        print_error("Transform module cannot be run directly. Use with a listener (option transform).")
        return False


# Backward compatibility alias (deprecated).
Obfuscator = Transform
