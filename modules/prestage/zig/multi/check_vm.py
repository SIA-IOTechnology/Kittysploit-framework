#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "check_vm"

    __info__ = {
        "name": "Check VM / Sandbox (Zig)",
        "description": "Exit early when common VM or sandbox indicators are detected",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["zig"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        return """
    const markers = [_][]const u8{
        "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
        "kvm", "parallels", "bochs", "innotek", "virtual",
    };
    if (builtin.os.tag == .linux) {
        const paths = [_][]const u8{
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        };
        inline for (paths) |path| {
            const file = std.fs.cwd().openFile(path, .{}) catch continue;
            defer file.close();
            var buf: [512]u8 = undefined;
            const n = file.read(&buf) catch continue;
            const slice = buf[0..n];
            inline for (markers) |m| {
                if (std.mem.indexOfIgnoreCase(u8, slice, m) != null) {
                    process.exit(0);
                }
            }
        }
    }
""".strip()
