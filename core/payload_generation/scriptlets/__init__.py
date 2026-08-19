#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Offline pre-stage scriptlets for payload generation."""

from .packer import (
    build_prestage_block,
    build_powershell_prestage_block,
    build_zig_prestage_block_legacy as build_zig_prestage_block,
    wrap_powershell_script,
    wrap_python_script,
    wrap_zig_source,
)
from .registry import Scriptlet, get_scriptlet, list_scriptlets, reload_scriptlets, resolve_scriptlet_names

__all__ = [
    "Scriptlet",
    "build_prestage_block",
    "build_powershell_prestage_block",
    "build_zig_prestage_block",
    "get_scriptlet",
    "list_scriptlets",
    "reload_scriptlets",
    "resolve_scriptlet_names",
    "wrap_powershell_script",
    "wrap_python_script",
    "wrap_zig_source",
]
