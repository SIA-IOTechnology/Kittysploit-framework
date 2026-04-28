#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "Php Hex Encoder",
        "description": "Encodes php payload in hex format",
        "author": "KittySploit Team",
        "platform": Platform.PHP,
    }	
    
    def encode(self, payload):
        encoded_payload = bytes(payload, "utf-8").hex()
        return "eval(hex2bin('{}'));".format(encoded_payload)