#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64
import zlib


class Module(Encoder):

    __info__ = {
        "name": "Php Gzinflate Base64 Encoder",
        "description": "Encodes php payload using deflate compression and base64",
        "author": "KittySploit Team",
        "platform": Platform.PHP,
    }

    def encode(self, payload):
        compressed_payload = zlib.compress(payload.encode("utf-8"))
        deflated_payload = compressed_payload[2:-4]
        encoded_payload = base64.b64encode(deflated_payload).decode("utf-8")
        return "eval(gzinflate(base64_decode('{}')));".format(encoded_payload)
