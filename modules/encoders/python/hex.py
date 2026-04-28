#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "Python Hex Encoder",
        "description": "Encodes payload to hex format",
        "author": "KittySploit Team",
        "platform": Platform.PYTHON,
    }	
    
    def encode(self, payload):
        encoded_payload = bytes(payload, "utf-8").hex()
        return "exec('{}'.decode('hex'))".format(encoded_payload)