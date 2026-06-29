#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from modules.payloads.singles.php.meterpreter_bind_tcp import Module as PHPMeterpreterBindTcp


class Module(PHPMeterpreterBindTcp, Payload):
    __info__ = {
        'name': 'PHP Meterpreter, Bind TCP',
        'description': 'Meterpreter-like PHP payload that listens on the target via TCP',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'category': PayloadCategory.SINGLE,
        'arch': Arch.PHP,
        'platform': Platform.ALL,
        'listener': 'listeners/multi/meterpreter_bind_tcp',
        'handler': Handler.BIND,
        'session_type': SessionType.METERPRETER,
        'references': []
    }

    def generate(self):
        return super().generate()

    def run(self):
        return self.generate()
