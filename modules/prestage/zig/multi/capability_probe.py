#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "capability_probe"

    __info__ = {
        "name": "Capability Probe (Zig)",
        "description": (
            "Detect OS, architecture, runtime, privileges, writable directory, "
            "and network capabilities before callback"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "dependencies": [],
        "tags": ["recon", "prestage", "offline", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        from core.payload_generation.prestage.emitters.zig import _split_helpers_body

        helpers = """
var _kitty_capability_probe_json: []const u8 = "";

fn kittyProbeWritableDir(alloc: mem.Allocator) ![]const u8 {
    var candidates = std.ArrayList([]const u8).empty;
    defer {
        for (candidates.items) |item| alloc.free(item);
        candidates.deinit(alloc);
    }
    if (std.process.getEnvVarOwned(alloc, "TMPDIR")) |tmp| {
        try candidates.append(alloc, tmp);
    } else |_| {}
    if (std.process.getEnvVarOwned(alloc, "TEMP")) |tmp| {
        try candidates.append(alloc, tmp);
    } else |_| {}
    if (std.process.getEnvVarOwned(alloc, "TMP")) |tmp| {
        try candidates.append(alloc, tmp);
    } else |_| {}
    if (builtin.os.tag != .windows) {
        for ("/tmp", "/var/tmp", "/dev/shm") |path| {
            const owned = try alloc.dupe(u8, path);
            try candidates.append(alloc, owned);
        }
    }
    for (candidates.items) |dir| {
        std.fs.cwd().makePath(dir) catch continue;
        const probe = try std.fmt.allocPrint(alloc, "{s}/.kitty_probe", .{dir});
        defer alloc.free(probe);
        std.fs.cwd().writeFile(.{ .sub_path = probe, .data = "ok" }) catch continue;
        std.fs.cwd().deleteFile(probe) catch {};
        return try alloc.dupe(u8, dir);
    }
    return try alloc.dupe(u8, "");
}

fn kittyProbeNetwork(alloc: mem.Allocator) ![]const u8 {
    var socket_ok = false;
    var tcp_ok = false;
    var dns_ok = false;
    const addr = std.net.Address.parseIp4("127.0.0.1", 65534) catch null;
    if (addr) |parsed| {
        const stream = std.net.tcpConnectToAddress(parsed) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimedOut, error.NetworkUnreachable => {
                socket_ok = true;
                tcp_ok = true;
            },
            else => {
                socket_ok = true;
            },
        };
        if (stream) |conn| {
            socket_ok = true;
            tcp_ok = true;
            conn.close();
        }
    }
    if (std.net.Address.resolveIp("127.0.0.1", 0)) |_| dns_ok = true else |_| {}
    return try std.fmt.allocPrint(
        alloc,
        "{{\\"socket\\":{s},\\"dns\\":{s},\\"tcp_outbound\\":{s},\\"hostname\\":\\"\\",\\"ips\\":[],\\"proxy\\":{{}}}}",
        .{
            if (socket_ok) "true" else "false",
            if (dns_ok) "true" else "false",
            if (tcp_ok) "true" else "false",
        },
    );
}
""".strip()

        body = """
{
    const alloc = std.heap.page_allocator;
    const writable = kittyProbeWritableDir(alloc) catch try alloc.dupe(u8, "");
    defer alloc.free(writable);
    const network = kittyProbeNetwork(alloc) catch try alloc.dupe(u8, "{}");
    defer alloc.free(network);
    var elevated = false;
    var uid: i32 = -1;
    if (builtin.os.tag != .windows and @hasDecl(std.posix, "geteuid")) {
        uid = @intCast(std.posix.geteuid());
        elevated = uid == 0;
    }
    const os_name = switch (builtin.os.tag) {
        .linux => "Linux",
        .windows => "Windows",
        .macos => "Darwin",
        else => @tagName(builtin.os.tag),
    };
    _kitty_capability_probe_json = try std.fmt.allocPrint(
        alloc,
        "{{\\"os\\":{{\\"name\\":\\"{s}\\",\\"release\\":\\"\\",\\"version\\":\\"\\"}},\\"arch\\":\\"{s}\\",\\"runtime\\":{{\\"language\\":\\"zig\\",\\"version\\":\\"{s}\\",\\"executable\\":\\"\\"}},\\"privileges\\":{{\\"elevated\\":{s},\\"user\\":\\"\\",\\"uid\\":{d},\\"gid\\":null}},\\"writable_dir\\":\\"{s}\\",\\"network\\":{s}}}",
        .{
            os_name,
            @tagName(builtin.cpu.arch),
            @import("builtin").zig_version_string,
            if (elevated) "true" else "false",
            uid,
            writable,
            network,
        },
    );
}
""".strip()

        return _split_helpers_body(helpers, body)
