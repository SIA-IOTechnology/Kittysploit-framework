#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
        "name": "Perl Base64 Encoder",
        "description": "Encodes perl payload in base64",
        "author": "KittySploit Team",
        "platform": Platform.PERL,
    }	
    
    def encode(self, payload):
        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "use MIME::Base64;eval(decode_base64('{}'));".format(encoded_payload)