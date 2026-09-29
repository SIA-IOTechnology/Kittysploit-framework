#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *
from core.payload_generation.prestage.signed_config_context import resolve_signed_config_context


class Module(Prestage):
    PRESTAGE_ID = "signed_config"

    __info__ = {
        "name": "Signed Config (Zig)",
        "description": "Embed encrypted and signed operator config separate from the payload body",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "config", "zig"],
    }

    config_json = OptString("", "Inline JSON object to encrypt/sign at generation time", False)
    config_file = OptFile("", "JSON config file on operator machine", False)
    config_secret = OptString("", "Encryption secret (default: kitty-signed-config)", False)
    config_sign_key = OptString("", "HMAC signing key (default: config_secret)", False)

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        from core.payload_generation.prestage.emitters.zig import _split_helpers_body

        cfg = resolve_signed_config_context(self, context)
        blob_b64 = str(cfg.get("blob_b64") or "").strip()
        if not blob_b64:
            return "// signed_config: set prestage_config or config_json"

        secret = str(cfg.get("config_secret") or "kitty-signed-config").replace("\\", "\\\\").replace('"', '\\"')
        sign_key = str(cfg.get("config_sign_key") or secret).replace("\\", "\\\\").replace('"', '\\"')

        helpers = f"""
var kitty_signed_config_json: []const u8 = "";
const kitty_signed_config_blob = "{blob_b64}";
const kitty_signed_config_secret = "{secret}";
const kitty_signed_config_sign_key = "{sign_key}";

fn kittyDeriveKey(secret: []const u8, salt: []const u8, out: *[32]u8) void {{
    _ = std.crypto.pwhash.pbkdf2(out[0..], secret, salt, 120000, std.crypto.auth.hmac.sha2.HmacSha256);
}}

fn kittyXorInPlace(data: []u8, key: []const u8) void {{
    for (data, 0..) |*b, i| b.* ^= key[i % key.len];
}}
""".strip()

        body = """
{
    const alloc = std.heap.page_allocator;
    const raw = b64Decode(alloc, kitty_signed_config_blob) catch {
        kittyTelemetryRecord("signed_config", "decode_failed", "b64");
        return;
    };
    defer alloc.free(raw);
    // Store encrypted envelope for later unpack by helper modules.
    kitty_signed_config_json = raw;
    _ = kitty_signed_config_secret;
    _ = kitty_signed_config_sign_key;
}
""".strip()

        return _split_helpers_body(helpers, body)
