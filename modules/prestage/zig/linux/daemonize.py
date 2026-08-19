#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "daemonize"

    __info__ = {
        "name": "Daemonize Process (Zig)",
        "description": "Detach from the controlling terminal on Unix (double-fork)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.UNIX,
        "languages": ["zig"],
        "dependencies": [],
        "tags": ["evasion", "prestage", "offline", "linux", "zig"],
    }

    def generate_zig(self, context: Dict[str, Any] = None) -> str:
        return """
    if (builtin.os.tag != .linux) return;
    const posix = std.posix;
    if (posix.fork() > 0) process.exit(0);
    _ = posix.setsid();
    if (posix.fork() > 0) process.exit(0);
    posix.chdir("/") catch {};
    const devnull = std.fs.cwd().openFile("/dev/null", .{ .mode = .read_write }) catch return;
    defer devnull.close();
    posix.dup2(devnull.handle, posix.STDIN_FILENO) catch {};
    posix.dup2(devnull.handle, posix.STDOUT_FILENO) catch {};
    posix.dup2(devnull.handle, posix.STDERR_FILENO) catch {};
""".strip()
