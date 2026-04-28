#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "Perl Hex Encoder",
        "description": "Encodes perl payload in hex format",
        "author": "KittySploit Team",
        "platform": Platform.PERL,
    }	
    
    def encode(self, payload):
        encoded_payload = bytes(payload, "utf-8").hex()
        return "eval(pack('H*','{}'));".format(encoded_payload)