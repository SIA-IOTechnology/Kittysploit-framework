#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from core.payload_templates.zig_meterpreter_bind_tcp import ZigMeterpreterBindTcpBase


class Module(ZigMeterpreterBindTcpBase, Payload):
    __info__ = {
        'name': 'Zig Meterpreter Windows, Bind TCP',
        'description': 'Windows Meterpreter bind TCP payload in Zig (requires Zig compiler)',
        'author': 'KittySploit Team',
        'version': '1.1.0',
        'category': 'singles',
        'platform': Platform.WINDOWS,
        'arch': Arch.X64,
        'listener': 'listeners/multi/meterpreter_bind_tcp',
        'handler': Handler.BIND,
        'session_type': SessionType.METERPRETER,
        'references': [
            'https://ziglang.org/',
            'https://ziglang.org/documentation/master/#Cross-compilation-is-a-first-class-use-case'
        ]
    }

    target_os = OptChoice('windows', 'Target operating system', True, ['windows'])
    target_arch = OptChoice('x86_64', 'Target architecture', True, ['x86_64', 'x86', 'aarch64'])

    def generate(self):
        return super().generate()

    def run(self):
        return self.generate()
