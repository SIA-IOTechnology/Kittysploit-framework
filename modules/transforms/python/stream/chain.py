#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Composable transform chain — stack multiple stream transforms on one C2 channel."""

from __future__ import annotations

import importlib
import re
from typing import List, Optional

from kittysploit import *


def _split_chain(spec: str) -> List[str]:
    parts = []
    for chunk in re.split(r"[,;]+", spec or ""):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


class Module(Transform):
    """Apply multiple transforms in order (encode) or reverse order (decode)."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "Transform Chain",
        "description": "Stack multiple stream transforms (comma-separated module paths).",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    chain = OptString(
        "transforms/python/stream/xor",
        "Comma-separated transform module paths, applied left-to-right on encode",
        True,
    )

    def __init__(self, framework=None):
        super().__init__(framework)
        self._chain_instances: List[Transform] = []
        self._chain_paths: List[str] = []
        self._encode_offsets: List[int] = []
        self._decode_offsets: List[int] = []

    def _ensure_chain_loaded(self) -> None:
        spec = str(getattr(getattr(self, "chain", None), "value", self.chain) or "").strip()
        paths = _split_chain(spec)
        if paths == self._chain_paths and self._chain_instances:
            return
        self._chain_instances = []
        self._chain_paths = []
        self._encode_offsets = []
        self._decode_offsets = []
        for path in paths:
            mod_path = "modules." + path.replace("/", ".")
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, "Module", None)
            if cls is None:
                continue
            inst = cls(framework=getattr(self, "framework", None))
            self._chain_instances.append(inst)
            self._chain_paths.append(path)
            self._encode_offsets.append(0)
            self._decode_offsets.append(0)

    def get_supported_client_languages(self) -> List[str]:
        self._ensure_chain_loaded()
        if not self._chain_instances:
            return list(self.SUPPORTED_CLIENT_LANGUAGES)
        langs = None
        for inst in self._chain_instances:
            supported = set(inst.get_supported_client_languages())
            langs = supported if langs is None else langs & supported
        return sorted(langs or [])

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        self._ensure_chain_loaded()
        if not data or not self._chain_instances:
            return data
        current = data
        for idx, xf in enumerate(self._chain_instances):
            inp_len = len(current)
            try:
                current = xf.encode(current, self._encode_offsets[idx])
            except TypeError:
                current = xf.encode(current)
            self._encode_offsets[idx] += inp_len
        return current

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        self._ensure_chain_loaded()
        if not data or not self._chain_instances:
            return data
        current = data
        for idx in reversed(range(len(self._chain_instances))):
            xf = self._chain_instances[idx]
            inp_len = len(current)
            try:
                current = xf.decode(current, self._decode_offsets[idx])
            except TypeError:
                current = xf.decode(current)
            self._decode_offsets[idx] += inp_len
        return current

    def connection_copy(self):
        copy_xf = self.__class__(framework=getattr(self, "framework", None))
        copy_xf.set_option("chain", str(getattr(getattr(self, "chain", None), "value", self.chain) or ""))
        for name in self.get_options():
            if name == "chain":
                continue
            try:
                val = getattr(self, name)
                copy_xf.set_option(name, val)
            except Exception:
                pass
        return copy_xf

    def generate_client_code(self, language: str) -> Optional[str]:
        self._ensure_chain_loaded()
        if language != "python" or not self._chain_instances:
            return None

        chunks: List[str] = []
        encode_calls: List[str] = []
        decode_calls: List[str] = []

        for idx, xf in enumerate(self._chain_instances):
            if not hasattr(xf, "generate_client_code"):
                return None
            code = xf.generate_client_code(language)
            if not code:
                return None
            renamed = code.replace("_xf_", f"_xfc{idx}_")
            chunks.append(renamed)
            encode_calls.append(f"_xfc{idx}_encode")
            decode_calls.insert(0, f"_xfc{idx}_decode")

        body_encode = "d"
        for fn in encode_calls:
            body_encode = f"{fn}({body_encode})"
        body_decode = "d"
        for fn in decode_calls:
            body_decode = f"{fn}({body_decode})"

        return (
            "\n".join(chunks)
            + "\n"
            + "def _xf_encode(d):\n"
            + f" return {body_encode}\n"
            + "def _xf_decode(d):\n"
            + f" return {body_decode}\n"
        )
