#!/usr/bin/env python3
from kittysploit import *

class Module(Payload):
    __info__ = {
        'name': 'Test',
        'description': 'Test payload',
        'listener': 'listeners/multi/reverse_tcp',
    }

    def generate(self):
        return b"\x90\xcc"
