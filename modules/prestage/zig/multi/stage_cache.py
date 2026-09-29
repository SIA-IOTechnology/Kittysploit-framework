#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.stage_cache_context import resolve_stage_cache_context


class Module(Prestage):
    PRESTAGE_ID = "stage_cache"

    __info__ = {
        "name": "Stage Cache (Zig)",
        "description": "Verified local stage cache with TTL expiration and interrupted download resume",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "staging", "cache", "zig"],
    }

    cache_dir = OptString("", "Cache directory on target (default: temp/.kitty_stage_cache)", False)
    cache_ttl = OptString("86400", "Cache entry TTL in seconds", False)
    stage_url = OptString("", "Default stage URL for fetch()", False)

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        from core.payload_generation.prestage.emitters.zig import _split_helpers_body

        cfg = resolve_stage_cache_context(self, context)
        cache_dir = str(cfg.get("cache_dir") or "").replace("\\", "\\\\").replace('"', '\\"')
        cache_ttl = int(cfg.get("cache_ttl") or 86400)
        stage_url = str(cfg.get("stage_url") or "").replace("\\", "\\\\").replace('"', '\\"')

        helpers = f"""
var kitty_stage_cache_dir: []const u8 = "";
const kitty_stage_cache_ttl: i64 = {cache_ttl};
const kitty_stage_default_url = "{stage_url}";
""".strip()

        if cache_dir:
            body = f"""
{{
    const alloc = std.heap.page_allocator;
    std.fs.cwd().makePath("{cache_dir}") catch {{}};
    kitty_stage_cache_dir = "{cache_dir}";
}}
""".strip()
        else:
            body = """
{
    const alloc = std.heap.page_allocator;
    const base = std.process.getEnvVarOwned(alloc, "TMPDIR") catch
        std.process.getEnvVarOwned(alloc, "TEMP") catch
        try alloc.dupe(u8, "/tmp");
    defer alloc.free(base);
    kitty_stage_cache_dir = std.fmt.allocPrint(alloc, "{s}/.kitty_stage_cache", .{base}) catch return;
    std.fs.cwd().makePath(kitty_stage_cache_dir) catch {};
}
""".strip()

        return _split_helpers_body(helpers, body)
