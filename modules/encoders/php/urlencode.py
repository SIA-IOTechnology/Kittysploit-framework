#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from urllib.parse import quote


class Module(Encoder):

    __info__ = {
        "name": "Php UrlEncode Encoder",
        "description": "Encodes php payload using URL encoding",
        "author": "KittySploit Team",
        "platform": Platform.PHP,
    }

    def encode(self, payload):
        encoded_payload = quote(payload, safe="")
        return "eval(urldecode('{}'));".format(encoded_payload)
