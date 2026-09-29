#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.telemetry_context import resolve_telemetry_context


class Module(Prestage):
    PRESTAGE_ID = "telemetry_buffer"

    __info__ = {
        "name": "Telemetry Buffer (Zig)",
        "description": "Persist bootstrap errors locally and flush them after the first C2 poll",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "dependencies": [],
        "tags": ["prestage", "offline", "telemetry", "zig"],
    }

    buffer_path = OptString("", "Telemetry JSON path on target (default: temp/.kitty_telemetry.json)", False)

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        from core.payload_generation.prestage.emitters.zig import _split_helpers_body

        cfg = resolve_telemetry_context(self, context)
        buffer_path = str(cfg.get("buffer_path") or "").replace("\\", "\\\\").replace('"', '\\"')
        if buffer_path:
            path_setup = f'const telemetry_path = "{buffer_path}";'
        else:
            path_setup = """
    const telemetry_path = blk: {
        const base = std.process.getEnvVarOwned(alloc, "TMPDIR") catch
            std.process.getEnvVarOwned(alloc, "TEMP") catch
            std.process.getEnvVarOwned(alloc, "TMP") catch
            try alloc.dupe(u8, "/tmp");
        defer alloc.free(base);
        break :blk std.fmt.allocPrint(alloc, "{s}/.kitty_telemetry.json", .{base}) catch break :blk alloc.dupe(u8, "/tmp/.kitty_telemetry.json") catch break :blk "";
    };
    defer alloc.free(telemetry_path);
""".strip()

        helpers = """
var kitty_telemetry_flushed = false;
var kitty_telemetry_path_storage: []const u8 = "";

fn kittyTelemetryRecord(phase: []const u8, event: []const u8, detail: []const u8) void {
    const alloc = std.heap.page_allocator;
    const path = kitty_telemetry_path_storage;
    if (path.len == 0) return;
    const line = std.fmt.allocPrint(
        alloc,
        "{{\\"ts\\":{d},\\"phase\\":\\"{s}\\",\\"event\\":\\"{s}\\",\\"detail\\":\\"{s}\\"}}\\n",
        .{ @as(i64, @intCast(std.time.timestamp())), phase, event, detail },
    ) catch return;
    defer alloc.free(line);
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch blk: {
        std.fs.cwd().writeFile(.{ .sub_path = path, .data = line }) catch {};
        break :blk return;
    };
    defer file.close();
    file.seekFromEnd(0) catch return;
    file.writeAll(line) catch {};
}
""".strip()

        if buffer_path:
            body = f"""
{{
    const alloc = std.heap.page_allocator;
    {path_setup}
    kitty_telemetry_path_storage = try alloc.dupe(u8, telemetry_path);
}}
""".strip()
        else:
            body = f"""
{{
    const alloc = std.heap.page_allocator;
{path_setup}
    kitty_telemetry_path_storage = telemetry_path;
}}
""".strip()

        return _split_helpers_body(helpers, body)
