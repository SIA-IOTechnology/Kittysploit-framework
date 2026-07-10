#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Build encrypted C loader for sRDI-converted shellcode."""

from __future__ import annotations

from lib.compile.encrypted_dropper import EncryptedDropperBuilder


class SrdiLoaderBuilder(EncryptedDropperBuilder):
    """Same VirtualAlloc loader as EncryptedDropperBuilder (sRDI output is shellcode)."""

    pass
