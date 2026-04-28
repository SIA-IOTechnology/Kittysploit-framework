#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "Php Base64 Encoder",
        "description": "Encodes php payload in base64",
        "author": "KittySploit Team",
        "platform": Platform.PHP,
    }	
    
    def encode(self, payload):
        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "eval(base64_decode('{}'));".format(encoded_payload)