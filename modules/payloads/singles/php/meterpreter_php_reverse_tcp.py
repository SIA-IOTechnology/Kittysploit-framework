#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from modules.payloads.singles.php.meterpreter_reverse_tcp import Module as PHPMeterpreterReverseTcp


class Module(PHPMeterpreterReverseTcp, Payload):
    __info__ = {
        'name': 'PHP Meterpreter, Reverse TCP',
        'description': 'Meterpreter-like PHP payload that connects back via TCP',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'category': PayloadCategory.SINGLE,
        'arch': Arch.PHP,
        'platform': Platform.ALL,
        'listener': 'listeners/multi/meterpreter_reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': []
    }

    def generate(self):
        return super().generate()

    def run(self):
        return self.generate()
