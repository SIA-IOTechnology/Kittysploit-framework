#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Helpers to embed binary blobs in generated C source."""

from __future__ import annotations


def format_c_byte_array(data: bytes, name: str, *, static: bool = True) -> str:
    prefix = "static " if static else ""
    if not data:
        return f"{prefix}unsigned char {name}[] = {{ 0 }};\n{prefix}SIZE_T {name}_len = 0;\n"
    body = ", ".join(f"0x{b:02x}" for b in data)
    return (
        f"{prefix}unsigned char {name}[] = {{ {body} }};\n"
        f"{prefix}SIZE_T {name}_len = sizeof({name});\n"
    )


def format_c_string_literal(data: bytes, name: str) -> str:
    escaped = "".join(f"\\x{b:02x}" for b in data)
    return f'static const char {name}[] = "{escaped}";\nstatic SIZE_T {name}_len = sizeof({name}) - 1;\n'
